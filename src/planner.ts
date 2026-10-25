import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { outputPath, datasetDirectory } from "./config.js";
import { readValidatedInputs, validateOutputRows } from "./contracts.js";
import {
  buildSubjects,
  classifyAuthorization,
  readEvidence,
  reconstructAt,
  requestResourceLink,
  resolveSubject,
  activityObservations,
  type EvidenceObservation,
  type ResourceState,
} from "./reconstruction.js";
import {
  investigateCase,
  newUsageTracker,
  NoopEvidenceInvestigator,
  type EvidenceInvestigator,
  type EvidencePacket,
  type LinkedResource,
} from "./investigator.js";

type CsvRow = Record<string, string>;
type Action = "DELETE" | "REDACT" | "ANONYMIZE" | "RETAIN";
type Operation =
  | "REPORT_REMAINING_RECORD" | "REPORT_EXPOSED_PII" | "REPORT_ACTIVE_DATA_FLOW" | "REPORT_RESTORE_RISK"
  | "DISABLE_DATA_FLOW" | "BLOCK_RESTORE" | "DELETE_RECORD" | "REDACT_RECORD" | "ANONYMIZE_RECORD"
  | "VERIFY_RECORD_ABSENT" | "VERIFY_RECORD_PRESENT" | "VERIFY_RECORD_REDACTED" | "VERIFY_RECORD_ANONYMIZED"
  | "VERIFY_DATA_FLOW_DISABLED" | "VERIFY_RESTORE_BLOCKED";
type Phase = "FINDING" | "REMEDIATION" | "VERIFICATION";
const evidenceLinkWindowMs = 10 * 60 * 1000;

export interface PlannedStep {
  step_no: number;
  phase: Phase;
  system_id: string;
  resource_id: string;
  operation: Operation;
  state: string;
  evidence_id: string;
}

export interface PlannedRow {
  case_id: string;
  deletion_status: "COMPLETE" | "INCOMPLETE" | "NOT_APPLICABLE";
  steps_json: PlannedStep[];
}

export interface GenerationResult {
  rows: PlannedRow[];
  unresolvedCases: string[];
}

const phaseOrder: Record<Phase, number> = { FINDING: 0, REMEDIATION: 1, VERIFICATION: 2 };
export function compareCaseIds(left: string, right: string): number {
  const leftMatch = /^(.*?)(\d+)$/.exec(left);
  const rightMatch = /^(.*?)(\d+)$/.exec(right);
  if (leftMatch && rightMatch && leftMatch[1] === rightMatch[1]) {
    const leftNumber = BigInt(leftMatch[2]);
    const rightNumber = BigInt(rightMatch[2]);
    if (leftNumber !== rightNumber) return leftNumber < rightNumber ? -1 : 1;
  }
  return left.localeCompare(right);
}

const knownCategories = new Set([
  "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY",
  "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
  "USER_EXPORT", "MARKETING_PROFILE", "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG",
  "LEGAL_HOLD_RECORD", "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE", "DATA_FLOW",
]);
const operationOrder: Record<Operation, number> = {
  REPORT_REMAINING_RECORD: 0,
  REPORT_EXPOSED_PII: 1,
  REPORT_ACTIVE_DATA_FLOW: 2,
  REPORT_RESTORE_RISK: 3,
  DISABLE_DATA_FLOW: 0,
  BLOCK_RESTORE: 1,
  DELETE_RECORD: 2,
  REDACT_RECORD: 3,
  ANONYMIZE_RECORD: 4,
  VERIFY_RECORD_ABSENT: 0,
  VERIFY_RECORD_PRESENT: 1,
  VERIFY_RECORD_REDACTED: 2,
  VERIFY_RECORD_ANONYMIZED: 3,
  VERIFY_DATA_FLOW_DISABLED: 4,
  VERIFY_RESTORE_BLOCKED: 5,
};

export function categoryFor(observation: EvidenceObservation): string | undefined {
  const categories: Record<string, string> = {
    customer_profiles: "USER_PROFILE",
    customer_search_documents: "SEARCH_INDEX_ENTRY",
    customer_analytics_reports: "ANALYTICS_PROFILE",
    support_records: "SUPPORT_MESSAGE",
    support_conversations: "SUPPORT_MESSAGE",
    customer_exports: "USER_EXPORT",
    marketing_profiles: "MARKETING_PROFILE",
    connector_configurations: "DATA_FLOW",
    connector_subscriptions: "DATA_FLOW",
    backup_restore_entries: "BACKUP_ARCHIVE",
    security_audit_events: "SECURITY_AUDIT_LOG",
    retained_order_records: "LEGAL_HOLD_RECORD",
  };
  if (observation.category) {
    const category = categories[observation.category] ?? observation.category;
    if (knownCategories.has(category)) return category;
  }
  if (observation.resourceId.startsWith("data_flow_")) return "DATA_FLOW";
  if (observation.resourceId.startsWith("backup_")) return "BACKUP_ARCHIVE";
  if (observation.resourceId.startsWith("account_")) return "USER_PROFILE";
  if (observation.resourceId.startsWith("tombstone_")) return "ACCOUNT_TOMBSTONE";
  if (observation.resourceId.startsWith("search_")) return "SEARCH_INDEX_ENTRY";
  if (observation.resourceId.startsWith("analytics_")) return "ANALYTICS_PROFILE";
  if (observation.resourceId.startsWith("audit_record_")) return "SECURITY_AUDIT_LOG";
  if (observation.resourceId.startsWith("marketing_")) return "MARKETING_PROFILE";
  if (observation.resourceId.startsWith("support_")) return "SUPPORT_MESSAGE";
  if (observation.resourceId.startsWith("export_")) return "USER_EXPORT";
  return undefined;
}

export function policyActions(rules: CsvRow[]): Map<string, Action> {
  return new Map(rules.map((rule) => [rule.data_category, rule.required_action as Action]));
}

function target(action: Action): { remediation: Operation | undefined; verification: Operation; state: string } {
  switch (action) {
    case "DELETE": return { remediation: "DELETE_RECORD", verification: "VERIFY_RECORD_ABSENT", state: "ABSENT" };
    case "REDACT": return { remediation: "REDACT_RECORD", verification: "VERIFY_RECORD_REDACTED", state: "REDACTED" };
    case "ANONYMIZE": return { remediation: "ANONYMIZE_RECORD", verification: "VERIFY_RECORD_ANONYMIZED", state: "ANONYMIZED" };
    case "RETAIN": return { remediation: undefined, verification: "VERIFY_RECORD_PRESENT", state: "PRESENT" };
  }
}

function compliant(action: Action, state: ResourceState): boolean {
  return (action === "DELETE" && state === "ABSENT")
    || (action === "REDACT" && state === "REDACTED")
    || (action === "ANONYMIZE" && state === "ANONYMIZED")
    || (action === "RETAIN" && state === "PRESENT");
}

function finding(observation: EvidenceObservation, category: string, action: Action): PlannedStep {
  if (category === "DATA_FLOW" && observation.state === "ACTIVE") {
    return step("FINDING", observation, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", observation.evidenceId);
  }
  if (category === "BACKUP_ARCHIVE" && observation.state === "ACTIVE") {
    return step("FINDING", observation, "REPORT_RESTORE_RISK", "ACTIVE", observation.evidenceId);
  }
  const operation = action === "DELETE" ? "REPORT_REMAINING_RECORD" : "REPORT_EXPOSED_PII";
  return step("FINDING", observation, operation, "PRESENT", observation.evidenceId);
}

function step(phase: Phase, observation: EvidenceObservation, operation: Operation, state: string, evidenceId: string): PlannedStep {
  return { step_no: 0, phase, system_id: observation.systemId, resource_id: observation.resourceId, operation, state, evidence_id: evidenceId };
}

export function sortAndNumber(steps: PlannedStep[]): PlannedStep[] {
  return steps
    .sort((left, right) => phaseOrder[left.phase] - phaseOrder[right.phase]
      || operationOrder[left.operation] - operationOrder[right.operation]
      || left.system_id.localeCompare(right.system_id)
      || left.resource_id.localeCompare(right.resource_id))
    .map((item, index) => ({ ...item, step_no: index + 1 }));
}

export interface SemanticOutputIssue {
  caseId: string;
  reason: string;
}

export function addProvisionalRows(rows: PlannedRow[], unresolvedCaseIds: string[]): PlannedRow[] {
  const existingCaseIds = new Set(rows.map((row) => row.case_id));
  const provisionalRows = unresolvedCaseIds.map((caseId): PlannedRow => {
    if (existingCaseIds.has(caseId)) throw new Error(`Cannot add a provisional row for existing case ${caseId}`);
    return { case_id: caseId, deletion_status: "INCOMPLETE", steps_json: [] };
  });
  return [...rows, ...provisionalRows];
}

export function semanticOutputIssues(rows: Array<{
  case_id: string;
  deletion_status: string;
  steps_json: Array<{ phase: string }>;
}>): SemanticOutputIssue[] {
  return rows.flatMap((row) => {
    if (row.deletion_status === "COMPLETE" && row.steps_json.length === 0) {
      return [{ caseId: row.case_id, reason: "COMPLETE has no verification steps" }];
    }
    const phaseRanks: Record<string, number> = { FINDING: 0, REMEDIATION: 1, VERIFICATION: 2 };
    if (row.steps_json.some((step, index) =>
      index > 0 && phaseRanks[step.phase] < phaseRanks[row.steps_json[index - 1].phase])) {
      return [{ caseId: row.case_id, reason: "Step phases are out of order" }];
    }
    if (row.deletion_status !== "INCOMPLETE") return [];
    const phases = new Set(row.steps_json.map((step) => step.phase));
    const missing = (["FINDING", "REMEDIATION", "VERIFICATION"] as const)
      .filter((phase) => !phases.has(phase));
    return missing.length > 0
      ? [{ caseId: row.case_id, reason: `INCOMPLETE is missing ${missing.join(", ")} steps` }]
      : [];
  });
}

export function planAuthorizedCase(
  caseId: string,
  observations: EvidenceObservation[],
  actions: Map<string, Action>,
): PlannedRow {
  const violations: Array<{ observation: EvidenceObservation; category: string; action: Action }> = [];
  const checks: PlannedStep[] = [];
  const futureChecks: PlannedStep[] = [];
  for (const observation of observations) {
    const category = categoryFor(observation);
    if (!category) throw new Error(`Unsupported resource category for ${observation.systemId}/${observation.resourceId}`);
    const action = category === "DATA_FLOW" || category === "BACKUP_ARCHIVE" ? undefined : actions.get(category);
    if (category === "DATA_FLOW" && observation.state === "ACTIVE") {
      violations.push({ observation, category, action: "DELETE" });
      futureChecks.push(step("VERIFICATION", observation, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""));
      continue;
    }
    if (category === "DATA_FLOW" && observation.state === "DISABLED") {
      checks.push(step("VERIFICATION", observation, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", observation.evidenceId));
      futureChecks.push(step("VERIFICATION", observation, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""));
      continue;
    }
    if (category === "BACKUP_ARCHIVE" && observation.state === "ACTIVE") {
      violations.push({ observation, category, action: "RETAIN" });
      futureChecks.push(step("VERIFICATION", observation, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""));
      continue;
    }
    if (category === "BACKUP_ARCHIVE" && observation.state === "PRESENT") {
      checks.push(step("VERIFICATION", observation, "VERIFY_RECORD_PRESENT", "PRESENT", observation.evidenceId));
      futureChecks.push(step("VERIFICATION", observation, "VERIFY_RECORD_PRESENT", "PRESENT", ""));
      continue;
    }
    if (category === "BACKUP_ARCHIVE" && observation.state === "BLOCKED") {
      checks.push(step("VERIFICATION", observation, "VERIFY_RESTORE_BLOCKED", "BLOCKED", observation.evidenceId));
      futureChecks.push(step("VERIFICATION", observation, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""));
      continue;
    }
    if (!action) continue;
    const final = target(action);
    checks.push(step("VERIFICATION", observation, final.verification, final.state, observation.evidenceId));
    futureChecks.push(step("VERIFICATION", observation, final.verification, final.state, ""));
    if (!compliant(action, observation.state)) violations.push({ observation, category, action });
  }

  const incomplete = violations.length > 0 || checks.length !== observations.length;
  if (!incomplete) {
    return {
      case_id: caseId,
      deletion_status: "COMPLETE",
      steps_json: sortAndNumber(checks),
    };
  }

  const steps: PlannedStep[] = [];
  for (const violation of violations) {
    steps.push(finding(violation.observation, violation.category, violation.action));
    if (violation.category === "DATA_FLOW") {
      steps.push(step("REMEDIATION", violation.observation, "DISABLE_DATA_FLOW", "DISABLED", ""));
    } else if (violation.category === "BACKUP_ARCHIVE") {
      steps.push(step("REMEDIATION", violation.observation, "BLOCK_RESTORE", "BLOCKED", ""));
    } else {
      const final = target(violation.action);
      if (final.remediation) steps.push(step("REMEDIATION", violation.observation, final.remediation, final.state, ""));
    }
  }
  steps.push(...futureChecks);
  return { case_id: caseId, deletion_status: "INCOMPLETE", steps_json: sortAndNumber(steps) };
}

function opaquePackets(
  inputs: ReturnType<typeof readValidatedInputs>,
  root: string,
  auditAt: string,
  aliases: readonly string[],
  extractions: ReturnType<typeof readEvidence>,
  groundingObservations: readonly EvidenceObservation[],
): EvidencePacket[] {
  return inputs.evidenceFiles.flatMap((entry) => {
    const extraction = extractions.find((item) => item.fileId === entry.file_id);
    const extension = path.extname(entry.file_path).toLowerCase();
    const eligible = [".pdf", ".png", ".jpg", ".jpeg"].includes(extension)
      || (extension === ".txt" && extraction?.observations.length === 0);
    if (Date.parse(entry.captured_at) > Date.parse(auditAt) || !eligible) return [];
    const sourcePath = entry.file_path;
    const content = readFileSync(path.join(root, sourcePath));
    const normalizedAliases = aliases.map((alias) => alias.trim().toLocaleLowerCase());
    const matchingObservation = extraction?.observations.some((observation) =>
      observation.tokens.some((token) => normalizedAliases.includes(token.trim().toLocaleLowerCase())),
    ) ?? false;
    if (matchingObservation && !extraction?.needsOpaqueReview) return [];
    const grounded = matchingObservation
      || extraction?.extractedTokens?.some((token) => normalizedAliases.includes(token))
      || normalizedAliases.some((alias) => content.toString("utf8").toLocaleLowerCase().includes(alias))
      || groundingObservations.some((observation) => observation.kind === "IDENTITY_LINK"
        && observation.tokens.some((token) => normalizedAliases.includes(token.trim().toLocaleLowerCase()))
        && Math.abs(Date.parse(entry.captured_at) - Date.parse(observation.eventTime ?? observation.observedAt ?? "")) <= evidenceLinkWindowMs);
    const linkedResources: LinkedResource[] = groundingObservations
      .filter((observation) => observation.kind === "IDENTITY_LINK"
        && observation.tokens.some((token) => normalizedAliases.includes(token.trim().toLocaleLowerCase()))
        && categoryFor(observation) !== undefined
        && Math.abs(Date.parse(entry.captured_at) - Date.parse(observation.eventTime ?? observation.observedAt ?? "")) <= evidenceLinkWindowMs)
      .map((observation) => ({
        systemId: observation.systemId,
        resourceId: observation.resourceId,
        category: categoryFor(observation)!,
        linkEvidenceId: observation.evidenceId,
        linkedAt: observation.eventTime ?? observation.observedAt ?? observation.capturedAt ?? "",
        visibleLabels: observation.visibleResourceLabels ?? [observation.resourceId],
      }));
    if (!grounded) return [];
    return [{
      fileId: entry.file_id,
      sourcePath,
      capturedAt: entry.captured_at,
      auditAt,
      mimeType: extension === ".pdf" ? "application/pdf" : [".jpg", ".jpeg"].includes(extension) ? "image/jpeg" : "image/png",
      content,
      aliases,
      deterministicObservations: extraction?.observations ?? [],
      linkedResources,
    }];
  });
}

function linkPdfRecordsToCatalog(
  evidence: ReturnType<typeof readEvidence>,
  identityLinks: EvidenceObservation[],
): void {
  for (const extraction of evidence) {
    const capturedAt = extraction.capturedAt;
    if (!extraction.extractedText || !capturedAt) continue;
    const text = extraction.extractedText.toLocaleLowerCase();
    const visibleIdentifiers = new Set(
      extraction.extractedText.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|user_\d+/gi)?.map((value) => value.toLocaleLowerCase()) ?? [],
    );
    const matchingLinks = identityLinks.filter((link) =>
      link.kind === "IDENTITY_LINK"
      && categoryFor(link) !== undefined
      && link.tokens.some((token) => visibleIdentifiers.has(token.toLocaleLowerCase()))
      && (link.visibleResourceLabels ?? [link.resourceId]).some((label) => text.includes(label.toLocaleLowerCase()))
      && Math.abs(Date.parse(capturedAt) - Date.parse(link.eventTime ?? link.observedAt ?? "")) <= evidenceLinkWindowMs);
    if (matchingLinks.length !== 1) continue;
    const link = matchingLinks[0];
    const category = categoryFor(link);
    if (!category) continue;
    if (extraction.observations.some((observation) => observation.resourceId === link.resourceId)) continue;
    extraction.observations.push({
      evidenceId: extraction.fileId,
      sourcePath: extraction.sourcePath,
      capturedAt,
      observedAt: capturedAt,
      systemId: link.systemId,
      resourceId: link.resourceId,
      state: "PRESENT",
      tokens: [...visibleIdentifiers],
      category,
    });
  }
}

export async function generateRows(
  inputs = readValidatedInputs(),
  root = datasetDirectory,
  investigator: EvidenceInvestigator = new NoopEvidenceInvestigator(),
  usage = newUsageTracker(),
): Promise<GenerationResult> {
  const subjects = buildSubjects(inputs.userIdentities, inputs.userAuditLog);
  const resourceCandidates = inputs.systemActivity
    .filter((event) => event.event_type === "DELETE_RECORD" && event.target_system === "account_service")
    .map((event) => ({ resourceId: event.resource_id, eventTime: event.event_time }));
  const evidence = readEvidence(inputs.evidenceFiles, root, resourceCandidates);
  const activity = activityObservations(inputs.systemActivity);
  linkPdfRecordsToCatalog(evidence, activity);
  const observations = [
    ...evidence.flatMap((entry) => entry.observations),
    ...activity,
  ];
  const actions = policyActions(inputs.deletionRules);
  const unresolvedCases: string[] = [];
  const rows: PlannedRow[] = [];
  const cache = new Map();
  for (const request of inputs.deletionRequests.slice().sort((left, right) => compareCaseIds(left.case_id, right.case_id))) {
      if (classifyAuthorization(request.request_text) === "NOT_AUTHORIZED") {
        rows.push({ case_id: request.case_id, deletion_status: "NOT_APPLICABLE", steps_json: [] });
        continue;
      }
      const subject = resolveSubject(request.email, subjects.values());
      if (!subject) {
        unresolvedCases.push(request.case_id);
        continue;
      }
      const requestLinks = requestResourceLink(request, inputs.systemActivity, subject);
      const investigation = await investigateCase(
        request.case_id,
        opaquePackets(inputs, root, request.audit_at, [...subject.aliases], evidence, observations),
        investigator,
        cache,
        usage,
      );
      const state = [...reconstructAt(
        subject,
        [...observations, ...requestLinks, ...investigation.observations],
        request.audit_at,
      ).values()];
      if (investigation.diagnostics.length > 0
        && (state.length === 0 || planAuthorizedCase(request.case_id, state, actions).deletion_status === "COMPLETE")) {
        unresolvedCases.push(request.case_id);
        continue;
      }
      if (state.length === 0) {
        unresolvedCases.push(request.case_id);
        continue;
      }
      if (state.some((observation) => categoryFor(observation) === undefined)) {
        unresolvedCases.push(request.case_id);
        continue;
      }
      if (state.some((observation) => {
        const category = categoryFor(observation);
        return category === "DATA_FLOW" && !["ACTIVE", "DISABLED"].includes(observation.state);
      })) {
        unresolvedCases.push(request.case_id);
        continue;
      }
      if (state.some((observation) => {
        const category = categoryFor(observation);
        return category === "BACKUP_ARCHIVE" && !["ACTIVE", "BLOCKED"].includes(observation.state);
      })) {
        unresolvedCases.push(request.case_id);
        continue;
      }
      rows.push(planAuthorizedCase(request.case_id, state, actions));
  }
  return { rows, unresolvedCases };
}

function escapeCsv(value: string): string {
  return `"${value.replaceAll("\"", "\"\"")}"`;
}

export function writeOutput(rows: PlannedRow[], destination = outputPath, evidenceIds?: ReadonlySet<string>): void {
  const canonicalRows = rows.map((row) => ({
    ...row,
    steps_json: sortAndNumber([...row.steps_json]),
  })).sort((left, right) => compareCaseIds(left.case_id, right.case_id));
  if (new Set(canonicalRows.map((row) => row.case_id)).size !== canonicalRows.length) {
    throw new Error("Output contains duplicate case_id values");
  }
  validateOutputRows(canonicalRows, evidenceIds);
  const lines = ["case_id,deletion_status,steps_json", ...canonicalRows.map((row) => [
    row.case_id,
    row.deletion_status,
    escapeCsv(JSON.stringify(row.steps_json)),
  ].join(","))];
  writeFileSync(destination, `${lines.join("\n")}\n`, "utf8");
}
