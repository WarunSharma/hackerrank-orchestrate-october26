import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  GeminiEvidenceInvestigator,
  NoopEvidenceInvestigator,
  createConfiguredInvestigator,
  investigateCase,
  investigatePacket,
  loadGeminiConfig,
  newUsageTracker,
  type EvidenceInvestigator,
  type EvidencePacket,
} from "./investigator.js";

const packet: EvidencePacket = {
  fileId: "evidence_1",
  sourcePath: "evidence/documents/record.pdf",
  capturedAt: "2026-01-01T00:00:00Z",
  auditAt: "2026-01-02T00:00:00Z",
  mimeType: "application/pdf",
  content: Buffer.from("fixture"),
  aliases: ["old@example.com", "user_1"],
  deterministicObservations: [],
};

const validResponse = {
  inspection_status: "RESOLVED",
  identifier_matches: ["old@example.com"],
  observations: [{
    system_id: "support_platform",
    visible_resource_label: "support_1",
    event_time: "2026-01-01T12:00:00Z",
    state: "PRESENT",
    matched_identifier: "old@example.com",
    location: "page 1",
    confidence: 0.9,
  }],
  unresolved_reason: null,
};

test("validates and preserves mocked Gemini-derived evidence provenance", async () => {
  const investigator = new GeminiEvidenceInvestigator(
    { apiKey: "test", model: "mock-gemini" },
    { generateContent: async () => ({ text: JSON.stringify(validResponse), usageMetadata: { promptTokenCount: 11, candidatesTokenCount: 7 } }) },
  );
  const usage = newUsageTracker();
  const result = await investigatePacket("case_1", packet, investigator, new Map(), usage);
  assert.equal(result.completeEligible, false);
  assert.deepEqual(result.observations[0], {
    evidenceId: "evidence_1",
    sourcePath: "evidence/documents/record.pdf",
    eventTime: "2026-01-01T12:00:00Z",
    observedAt: "2026-01-01T00:00:00Z",
    capturedAt: "2026-01-01T00:00:00Z",
    systemId: "support_platform",
    resourceId: "support_1",
    state: "PRESENT",
    tokens: ["old@example.com"],
  });
  assert.equal(usage.records[0].inputTokens, 11);
  assert.equal(usage.records[0].outputTokens, 7);
});

test("uses the deterministic default without model tokens and marks opaque PII unresolved", async () => {
  const usage = newUsageTracker();
  const result = await investigatePacket("case_1", packet, new NoopEvidenceInvestigator(), new Map(), usage);
  assert.equal(result.completeEligible, false);
  assert.equal(result.diagnostic?.fileId, "evidence_1");
  assert.deepEqual(usage.records.map((record) => [record.provider, record.inputTokens, record.outputTokens]), [
    ["deterministic", 0, 0],
    ["deterministic", 0, 0],
  ]);
});

test("caches validated responses without an additional model call", async () => {
  let calls = 0;
  const mock: EvidenceInvestigator = {
    modelName: "mock-gemini",
    inspect: async () => {
      calls += 1;
      return { response: validResponse, usage: { inputTokens: 1, outputTokens: 1 } };
    },
  };
  const cache = new Map();
  const usage = newUsageTracker();
  await investigatePacket("case_1", packet, mock, cache, usage);
  await investigatePacket("case_1", packet, mock, cache, usage);
  assert.equal(calls, 1);
  assert.equal(usage.records[1].cacheHit, true);
});

test("does not reuse a cached investigation across aliases or audit cutoffs", async () => {
  let calls = 0;
  const mock: EvidenceInvestigator = {
    modelName: "mock-gemini",
    inspect: async () => {
      calls += 1;
      return { response: validResponse, usage: { inputTokens: 1, outputTokens: 1 } };
    },
  };
  const cache = new Map();
  const usage = newUsageTracker();
  await investigatePacket("case_1", packet, mock, cache, usage);
  await investigatePacket("case_2", { ...packet, aliases: ["another@example.com"] }, mock, cache, usage);
  await investigatePacket("case_3", { ...packet, auditAt: "2026-01-03T00:00:00Z" }, mock, cache, usage);
  assert.equal(calls, 3);
  assert.equal(usage.records.filter((record) => record.cacheHit).length, 0);
});

test("retries invalid responses once and cannot make an unresolved case complete", async () => {
  let calls = 0;
  const invalid: EvidenceInvestigator = {
    modelName: "mock-gemini",
    inspect: async () => {
      calls += 1;
      return { response: { inspection_status: "RESOLVED" }, usage: { inputTokens: 1, outputTokens: 1 } };
    },
  };
  const result = await investigatePacket("case_1", packet, invalid, new Map(), newUsageTracker());
  assert.equal(calls, 2);
  assert.equal(result.completeEligible, false);
  assert.equal(result.observations.length, 0);
  assert.equal(result.diagnostic?.caseId, "case_1");
});

test("isolates an unresolved artifact while independent evidence produces INCOMPLETE", async () => {
  const unresolved: EvidenceInvestigator = {
    modelName: "mock-gemini",
    inspect: async () => ({ response: { inspection_status: "UNRESOLVED", identifier_matches: [], observations: [], unresolved_reason: "Unreadable" }, usage: { inputTokens: 1, outputTokens: 1 } }),
  };
  const resolved = investigatorWith(validResponse);
  const failed = await investigateCase("case_1", [packet], unresolved, new Map(), newUsageTracker());
  const complete = await investigateCase("case_2", [packet], resolved, new Map(), newUsageTracker());
  assert.equal(failed.status, "UNRESOLVED");
  assert.equal(complete.status, "INCOMPLETE");
  assert.equal(complete.observations[0].evidenceId, "evidence_1");
});

test("loads Gemini configuration only when a key is available", () => {
  assert.equal(loadGeminiConfig("/definitely/missing/.env"), undefined);
  const directory = mkdtempSync(path.join(tmpdir(), "gemini-config-"));
  const envFile = path.join(directory, ".env");
  writeFileSync(envFile, "GEMINI_API_KEY=local-test-key\nGEMINI_MODEL=gemini-test\n");
  try {
    assert.deepEqual(loadGeminiConfig(envFile), { apiKey: "local-test-key", model: "gemini-test" });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("requires explicit LLM enablement and configuration before selecting Gemini", () => {
  const noOp = createConfiguredInvestigator(false, { apiKey: "unused", model: "mock-gemini" });
  assert.ok(noOp instanceof NoopEvidenceInvestigator);
  assert.throws(() => createConfiguredInvestigator(true, undefined), /LLM_ENABLED=true requires GEMINI_API_KEY/);
  const gemini = createConfiguredInvestigator(true, { apiKey: "mock-key", model: "mock-gemini" }, {
    generateContent: async () => ({ text: "{}" }),
  });
  assert.ok(gemini instanceof GeminiEvidenceInvestigator);
});

test("requests Gemini structured output and constrains document-only statuses", async () => {
  let request: any;
  const investigator = new GeminiEvidenceInvestigator(
    { apiKey: "test", model: "mock-gemini" },
    {
      generateContent: async (value) => {
        request = value;
        return {
          text: JSON.stringify({
            inspection_status: "UNRESOLVED",
            identifier_matches: ["old@example.com"],
            observations: [],
            unresolved_reason: "The artifact contains a delivered order status but no deletion-state observation.",
          }),
        };
      },
    },
  );
  const response = await investigator.inspect(packet);
  assert.equal((request.config as { responseMimeType: string }).responseMimeType, "application/json");
  assert.equal((request.config as { responseSchema: { properties: Record<string, unknown> } }).responseSchema.properties.observations !== undefined, true);
  assert.match(request.contents[0].parts[0].text, /delivered.*not valid state values/i);
  assert.match(request.contents[0].parts[0].text, /explicitly visible/i);
  assert.match(request.contents[0].parts[0].text, /timestamp proximity alone/i);
  assert.deepEqual(response.response, {
    inspection_status: "UNRESOLVED",
    identifier_matches: ["old@example.com"],
    observations: [],
    unresolved_reason: "The artifact contains a delivered order status but no deletion-state observation.",
  });
});

test("grounds retained tombstones by linked resource and supports redacted state", async () => {
  const tombstonePacket: EvidencePacket = {
    ...packet,
    linkedResources: [{
      systemId: "identity_service",
      resourceId: "tombstone_1",
      category: "ACCOUNT_TOMBSTONE",
      linkEvidenceId: "activity_link_1",
      linkedAt: "2026-01-01T00:05:00Z",
      visibleLabels: ["tombstone_1", "user_17"],
    }],
  };
  const investigator = new GeminiEvidenceInvestigator(
    { apiKey: "test", model: "mock-gemini" },
    { generateContent: async () => ({
      text: JSON.stringify({
        inspection_status: "RESOLVED",
        identifier_matches: ["old@example.com"],
        observations: [{
          visible_resource_label: "user_17",
          state: "REDACTED",
          location: "reference row",
          confidence: 0.95,
        }],
        unresolved_reason: null,
      }),
    }) },
  );
  const result = await investigatePacket("case_tombstone", tombstonePacket, investigator, new Map(), newUsageTracker());
  assert.equal(result.diagnostic, undefined);
  assert.deepEqual(result.observations[0], {
    evidenceId: "evidence_1",
    sourcePath: "evidence/documents/record.pdf",
    observedAt: "2026-01-01T00:00:00Z",
    capturedAt: "2026-01-01T00:00:00Z",
    systemId: "identity_service",
    resourceId: "tombstone_1",
    state: "REDACTED",
    tokens: [],
    category: "ACCOUNT_TOMBSTONE",
  });
});

test("rejects a valid-looking observation for an unrelated linked resource", async () => {
  const tombstonePacket: EvidencePacket = {
    ...packet,
    linkedResources: [{
      systemId: "identity_service",
      resourceId: "tombstone_1",
      category: "ACCOUNT_TOMBSTONE",
      linkEvidenceId: "activity_link_1",
      linkedAt: "2026-01-01T00:05:00Z",
      visibleLabels: ["tombstone_1", "user_17"],
    }],
  };
  const investigator = investigatorWith({
    inspection_status: "RESOLVED",
    identifier_matches: ["old@example.com"],
    observations: [{
      visible_resource_label: "tombstone_other",
      event_time: "2026-01-01T00:00:00Z",
      system_id: "identity_service",
      state: "REDACTED",
      matched_identifier: "old@example.com",
      location: "reference row",
      confidence: 0.95,
    }],
    unresolved_reason: null,
  });
  const result = await investigatePacket("case_tombstone", tombstonePacket, investigator, new Map(), newUsageTracker());
  assert.equal(result.observations.length, 0);
  assert.match(result.diagnostic?.reason ?? "", /linked resource/i);
});

test("keeps document lifecycle statuses out of validated deletion observations", async () => {
  const investigator = investigatorWith({
    inspection_status: "UNRESOLVED",
    identifier_matches: ["old@example.com"],
    observations: [],
    unresolved_reason: "Only delivered status is supported by the document.",
  });
  const result = await investigatePacket("case_1", packet, investigator, new Map(), newUsageTracker());
  assert.equal(result.observations.length, 0);
  assert.equal(result.completeEligible, false);
  assert.equal(result.diagnostic?.reason, "Only delivered status is supported by the document.");
});

function investigatorWith(response: unknown): EvidenceInvestigator {
  return { modelName: "mock-gemini", inspect: async () => ({ response, usage: { inputTokens: 1, outputTokens: 1 } }) };
}
