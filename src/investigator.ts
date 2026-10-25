import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { GoogleGenAI, Type } from "@google/genai";
import { z } from "zod";
import type { EvidenceObservation } from "./reconstruction.js";

const promptVersion = "evidence-investigator-v1";
const resourceStates = ["PRESENT", "ABSENT", "ACTIVE", "DISABLED", "BLOCKED", "REDACTED", "ANONYMIZED"] as const;
const structuredResponseSchema = {
  type: Type.OBJECT,
  required: ["inspection_status", "identifier_matches", "observations", "unresolved_reason"],
  properties: {
    inspection_status: {
      type: Type.STRING,
      format: "enum",
      enum: ["RESOLVED", "UNRESOLVED"],
    },
    identifier_matches: {
      type: Type.ARRAY,
      items: { type: Type.STRING },
    },
    observations: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        required: ["visible_resource_label", "state", "location", "confidence"],
        properties: {
          system_id: { type: Type.STRING },
          visible_resource_label: { type: Type.STRING },
          event_time: { type: Type.STRING, format: "date-time" },
          state: {
            type: Type.STRING,
            format: "enum",
            enum: [...resourceStates],
          },
          matched_identifier: { type: Type.STRING },
          location: { type: Type.STRING },
          confidence: { type: Type.NUMBER, minimum: 0, maximum: 1 },
        },
      },
    },
    unresolved_reason: {
      type: Type.STRING,
      nullable: true,
    },
  },
} as const;

const responseSchema = z.object({
  inspection_status: z.enum(["RESOLVED", "UNRESOLVED"]),
  identifier_matches: z.array(z.string()),
  observations: z.array(z.object({
    system_id: z.string().min(1).optional(),
    visible_resource_label: z.string().min(1),
    event_time: z.string().datetime({ offset: true }).optional(),
    state: z.enum(resourceStates),
    matched_identifier: z.string().min(1).optional(),
    location: z.string().min(1),
    confidence: z.number().min(0).max(1),
  }).strict()),
  unresolved_reason: z.string().nullable(),
}).strict().superRefine((response, context) => {
  if (response.inspection_status === "RESOLVED" && response.unresolved_reason !== null) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "Resolved responses cannot include unresolved_reason" });
  }
  if (response.inspection_status === "UNRESOLVED" && response.observations.length > 0) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "Unresolved responses cannot include observations" });
  }
});

export type InvestigationResponse = z.infer<typeof responseSchema>;

export interface EvidencePacket {
  fileId: string;
  sourcePath: string;
  capturedAt: string;
  auditAt: string;
  mimeType: string;
  content: Uint8Array;
  aliases: readonly string[];
  deterministicObservations: readonly EvidenceObservation[];
  linkedResources?: readonly LinkedResource[];
}

export interface LinkedResource {
  systemId: string;
  resourceId: string;
  category: string;
  linkEvidenceId: string;
  linkedAt: string;
  visibleLabels: readonly string[];
}

export interface ModelUsage {
  inputTokens: number;
  outputTokens: number;
}

export interface InvestigatorTransportResult {
  response: unknown;
  usage: ModelUsage;
}

export interface EvidenceInvestigator {
  readonly modelName: string;
  inspect(packet: EvidencePacket): Promise<InvestigatorTransportResult>;
}

export interface UsageRecord extends ModelUsage {
  provider: "gemini" | "deterministic";
  model: string;
  fileId: string;
  cacheHit: boolean;
  attempt: number;
  outcome: "accepted" | "invalid" | "failed";
}

export interface InvestigationUsage {
  records: UsageRecord[];
}

export interface CaseDiagnostic {
  caseId: string;
  fileId: string;
  reason: string;
}

export interface InvestigationResult {
  observations: EvidenceObservation[];
  diagnostic?: CaseDiagnostic;
  completeEligible: boolean;
}

export interface CaseInvestigation {
  caseId: string;
  status: "INCOMPLETE" | "UNRESOLVED" | "NO_VIOLATION";
  observations: EvidenceObservation[];
  diagnostics: CaseDiagnostic[];
}

export function newUsageTracker(): InvestigationUsage {
  return { records: [] };
}

function normalize(value: string): string {
  return value.trim().toLocaleLowerCase();
}

function cacheKey(packet: EvidencePacket, model: string): string {
  return createHash("sha256")
    .update(promptVersion)
    .update(model)
    .update(packet.auditAt)
    .update([...packet.aliases].map(normalize).sort().join("\n"))
    .update((packet.linkedResources ?? [])
      .map((resource) => [resource.systemId, resource.resourceId, resource.category, resource.linkEvidenceId, resource.linkedAt].join("|"))
      .sort()
      .join("\n"))
    .update(packet.content)
    .digest("hex");
}

function isEligible(packet: EvidencePacket): boolean {
  const extension = path.extname(packet.sourcePath).toLowerCase();
  return [".pdf", ".png", ".jpg", ".jpeg"].includes(extension)
    || (extension === ".txt" && packet.deterministicObservations.length === 0);
}

function observationsFromResponse(packet: EvidencePacket, response: InvestigationResponse): EvidenceObservation[] {
  const aliases = new Set(packet.aliases.map(normalize));
  const linkedResources = packet.linkedResources ?? [];
  if (linkedResources.length > 0) {
    const hasSubjectMatch = response.identifier_matches.some((identifier) => aliases.has(normalize(identifier)));
    const hasConflictingIdentifier = response.identifier_matches.some((identifier) => !aliases.has(normalize(identifier)));
    if (hasConflictingIdentifier
      || (!hasSubjectMatch && linkedResources.some((resource) => resource.category !== "SUPPORT_ATTACHMENT"))) return [];
  }
  return response.observations.flatMap((item) => {
    if (item.matched_identifier && !aliases.has(normalize(item.matched_identifier))) return [];
    if (item.event_time && Date.parse(item.event_time) > Date.parse(packet.auditAt)) return [];
    if (Date.parse(packet.capturedAt) > Date.parse(packet.auditAt)) return [];
    const label = normalize(item.visible_resource_label);
    const linkedMatches = linkedResources.filter((resource) =>
      [resource.resourceId, ...resource.visibleLabels].some((candidate) => normalize(candidate) === label));
    const linked = linkedMatches.length === 1 ? linkedMatches[0] : undefined;
    if (linkedResources.length > 0 && !linked) return [];
    if (linked && item.system_id && item.system_id !== linked.systemId) return [];
    if (!linked && (!item.system_id || !item.matched_identifier
      || !/^[a-z][a-z0-9]*(?:_[a-z0-9-]+)+$/i.test(item.visible_resource_label))) return [];
    const systemId = linked?.systemId ?? item.system_id;
    if (!systemId) return [];
    return [{
      evidenceId: packet.fileId,
      sourcePath: packet.sourcePath,
      ...(item.event_time ? { eventTime: item.event_time } : {}),
      observedAt: packet.capturedAt,
      capturedAt: packet.capturedAt,
      systemId,
      resourceId: linked?.resourceId ?? item.visible_resource_label,
      state: item.state,
      tokens: item.matched_identifier ? [normalize(item.matched_identifier)] : [],
      ...(linked ? { category: linked.category } : {}),
    }];
  });
}

export async function investigatePacket(
  caseId: string,
  packet: EvidencePacket,
  investigator: EvidenceInvestigator,
  cache: Map<string, InvestigationResponse>,
  usage: InvestigationUsage,
): Promise<InvestigationResult> {
  if (!isEligible(packet)) return { observations: [], completeEligible: true };

  const key = cacheKey(packet, investigator.modelName);
  const cached = cache.get(key);
  if (cached) {
    usage.records.push({
      provider: investigator.modelName === "deterministic" ? "deterministic" : "gemini",
      model: investigator.modelName,
      fileId: packet.fileId,
      cacheHit: true,
      attempt: 0,
      outcome: "accepted",
      inputTokens: 0,
      outputTokens: 0,
    });
    const observations = observationsFromResponse(packet, cached);
    return { observations, completeEligible: observations.length === 0 };
  }

  let reason = "Investigator did not return a valid response";
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    try {
      const result = await investigator.inspect(packet);
      const parsed = responseSchema.safeParse(result.response);
      usage.records.push({
        provider: investigator.modelName === "deterministic" ? "deterministic" : "gemini",
        model: investigator.modelName,
        fileId: packet.fileId,
        cacheHit: false,
        attempt,
        outcome: parsed.success ? "accepted" : "invalid",
        ...result.usage,
      });
      if (parsed.success && parsed.data.inspection_status === "RESOLVED") {
        const observations = observationsFromResponse(packet, parsed.data);
        if (packet.linkedResources && packet.linkedResources.length > 0
          && parsed.data.observations.length > 0 && observations.length === 0) {
          reason = "Investigator observations did not match any linked resource";
          continue;
        }
        cache.set(key, parsed.data);
        return { observations, completeEligible: observations.length === 0 };
      }
      reason = parsed.success ? parsed.data.unresolved_reason ?? reason : parsed.error.message;
    } catch (error) {
      reason = error instanceof Error ? error.message : String(error);
      usage.records.push({
        provider: investigator.modelName === "deterministic" ? "deterministic" : "gemini",
        model: investigator.modelName,
        fileId: packet.fileId,
        cacheHit: false,
        attempt,
        outcome: "failed",
        inputTokens: 0,
        outputTokens: 0,
      });
    }
  }
  return {
    observations: [],
    completeEligible: false,
    diagnostic: { caseId, fileId: packet.fileId, reason },
  };
}

export async function investigateCase(
  caseId: string,
  packets: EvidencePacket[],
  investigator: EvidenceInvestigator,
  cache: Map<string, InvestigationResponse>,
  usage: InvestigationUsage,
): Promise<CaseInvestigation> {
  const results = await Promise.all(packets.map((packet) => investigatePacket(caseId, packet, investigator, cache, usage)));
  const observations = results.flatMap((result) => result.observations);
  const diagnostics = results.flatMap((result) => result.diagnostic ? [result.diagnostic] : []);
  return {
    caseId,
    status: diagnostics.length > 0 ? "UNRESOLVED" : observations.length > 0 ? "INCOMPLETE" : "NO_VIOLATION",
    observations,
    diagnostics,
  };
}

export class NoopEvidenceInvestigator implements EvidenceInvestigator {
  readonly modelName = "deterministic";

  async inspect(): Promise<InvestigatorTransportResult> {
    return {
      response: { inspection_status: "UNRESOLVED", identifier_matches: [], observations: [], unresolved_reason: "No investigator configured" },
      usage: { inputTokens: 0, outputTokens: 0 },
    };
  }
}

export interface GeminiConfig {
  apiKey: string;
  model: string;
}

function environmentFromFile(filePath: string): Record<string, string> {
  if (!existsSync(filePath)) return {};
  return Object.fromEntries(readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .filter((line) => line && !line.startsWith("#"))
    .flatMap((line) => {
      const delimiter = line.indexOf("=");
      return delimiter < 1 ? [] : [[line.slice(0, delimiter).trim(), line.slice(delimiter + 1).trim().replace(/^['"]|['"]$/g, "")]];
    }));
}

export function loadGeminiConfig(envFile = path.resolve(".env")): GeminiConfig | undefined {
  const fileEnv = environmentFromFile(envFile);
  const apiKey = process.env.GEMINI_API_KEY ?? fileEnv.GEMINI_API_KEY;
  return apiKey ? { apiKey, model: process.env.GEMINI_MODEL ?? fileEnv.GEMINI_MODEL ?? "gemini-2.5-flash" } : undefined;
}

export function createConfiguredInvestigator(
  enabled: boolean,
  config: GeminiConfig | undefined,
  client?: GeminiSdkClient,
): EvidenceInvestigator {
  if (!enabled) return new NoopEvidenceInvestigator();
  if (!config) throw new Error("LLM_ENABLED=true requires GEMINI_API_KEY in the environment or .env");
  return new GeminiEvidenceInvestigator(config, client);
}

export function loadConfiguredInvestigator(
  envFile = path.resolve(".env"),
  client?: GeminiSdkClient,
): EvidenceInvestigator {
  const fileEnv = environmentFromFile(envFile);
  const enabledValue = process.env.LLM_ENABLED ?? fileEnv.LLM_ENABLED;
  const enabled = enabledValue?.trim().toLocaleLowerCase() === "true";
  return createConfiguredInvestigator(enabled, loadGeminiConfig(envFile), client);
}

export interface GeminiSdkClient {
  generateContent(request: unknown): Promise<{
    text?: string;
    usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number };
  }>;
}

class GoogleGenAiClient implements GeminiSdkClient {
  private readonly client: GoogleGenAI;

  constructor(apiKey: string) {
    this.client = new GoogleGenAI({ apiKey });
  }

  generateContent(request: unknown): Promise<{
    text?: string;
    usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number };
  }> {
    return this.client.models.generateContent(request as never);
  }
}

export class GeminiEvidenceInvestigator implements EvidenceInvestigator {
  readonly modelName: string;
  private readonly client: GeminiSdkClient;

  constructor(config: GeminiConfig, client: GeminiSdkClient = new GoogleGenAiClient(config.apiKey)) {
    this.modelName = config.model;
    this.client = client;
  }

  async inspect(packet: EvidencePacket): Promise<InvestigatorTransportResult> {
    const prompt = [
      "Extract only evidence observations from this single artifact. Do not decide deletion status or propose a plan.",
      `file_id=${packet.fileId}; captured_at=${packet.capturedAt}; audit_at=${packet.auditAt}`,
      `Known aliases: ${packet.aliases.join(", ")}`,
      `Linked resources: ${(packet.linkedResources ?? []).map((resource) =>
        `${resource.systemId}/${resource.resourceId} visible_labels=${resource.visibleLabels.join("|")} category=${resource.category} link_evidence_id=${resource.linkEvidenceId} linked_at=${resource.linkedAt}`).join("; ") || "none"}`,
      "Use the response schema exactly. If the artifact cannot support a valid observation, return UNRESOLVED with an empty observations array.",
      "For each observation, copy visible_resource_label exactly as it appears in the artifact. Do not return a canonical ID merely because it appears in linked metadata; the application resolves visible labels through those grounded links.",
      "For linked resources, include only identifiers visibly matching a known alias. If a visible owner/customer identifier conflicts with the known aliases or the linked resource identity, return UNRESOLVED instead of asserting an observation.",
      "Only include system_id, matched_identifier, or event_time when explicitly visible in the artifact. If no event time is printed, omit event_time; the application records captured_at separately as observedAt.",
      "Do not infer missing date parts, timestamps, systems, resource IDs, or identifiers from context. Do not establish ownership from timestamp proximity alone.",
      `state must be one of ${resourceStates.join(", ")} and must describe deletion/resource state only.`,
      "For BACKUP_ARCHIVE, report ACTIVE only when restore access is explicitly allowed or unblocked, and BLOCKED only when restore is explicitly denied or blocked. Archive presence alone is PRESENT and does not establish restore access.",
      "For ACCOUNT_TOMBSTONE, report REDACTED only when the stable internal reference remains and prohibited direct identifiers are visibly absent; a retained reference is not an active customer profile.",
      "Document or business statuses such as delivered, paid, dispatched, or shipped are not valid state values. Do not translate them into a deletion state unless the artifact explicitly states that the resource is present, absent, active, disabled, or blocked.",
      "Return JSON with inspection_status, identifier_matches, observations, and unresolved_reason.",
      "Each observation must include visible_resource_label, state, location, and confidence.",
    ].join("\n");
    const response = await this.client.generateContent({
      model: this.modelName,
      contents: [{ role: "user", parts: [{ text: prompt }, { inlineData: { mimeType: packet.mimeType, data: Buffer.from(packet.content).toString("base64") } }] }],
      config: {
        responseMimeType: "application/json",
        responseSchema: structuredResponseSchema,
        temperature: 0,
      },
    });
    if (!response.text) throw new Error("Gemini response contained no text");
    return {
      response: JSON.parse(response.text),
      usage: {
        inputTokens: response.usageMetadata?.promptTokenCount ?? 0,
        outputTokens: response.usageMetadata?.candidatesTokenCount ?? 0,
      },
    };
  }
}
