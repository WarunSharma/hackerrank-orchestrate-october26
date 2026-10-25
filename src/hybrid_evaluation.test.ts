import test from "node:test";
import assert from "node:assert/strict";
import {
  NoopEvidenceInvestigator,
  investigatePacket,
  newUsageTracker,
  type EvidenceInvestigator,
  type EvidencePacket,
} from "./investigator.js";
import { planAuthorizedCase } from "./planner.js";

const packet: EvidencePacket = {
  fileId: "evidence_ambiguous",
  sourcePath: "evidence/ambiguous.pdf",
  capturedAt: "2026-01-01T00:00:00Z",
  auditAt: "2026-01-02T00:00:00Z",
  mimeType: "application/pdf",
  content: Buffer.from("opaque fixture"),
  aliases: ["person@example.com", "user_1"],
  deterministicObservations: [],
};

const validResponse = {
  inspection_status: "RESOLVED",
  identifier_matches: ["person@example.com"],
  observations: [{
    system_id: "account_service",
    visible_resource_label: "account_1",
    event_time: "2026-01-01T12:00:00Z",
    state: "PRESENT",
    matched_identifier: "person@example.com",
    location: "page 1",
    confidence: 1,
  }],
  unresolved_reason: null,
};

test("compares deterministic-only and hybrid fixture accuracy", async () => {
  const deterministicUsage = newUsageTracker();
  const deterministic = await investigatePacket(
    "case_opaque",
    packet,
    new NoopEvidenceInvestigator(),
    new Map(),
    deterministicUsage,
  );
  const hybridUsage = newUsageTracker();
  const hybrid = await investigatePacket(
    "case_opaque",
    packet,
    investigatorWith(validResponse, { inputTokens: 17, outputTokens: 9 }),
    new Map(),
    hybridUsage,
  );
  const rules = new Map([["USER_PROFILE", "DELETE" as const]]);
  const expected = planAuthorizedCase("case_opaque", [{
    evidenceId: packet.fileId,
    sourcePath: packet.sourcePath,
    eventTime: "2026-01-01T12:00:00Z",
    systemId: "account_service",
    resourceId: "account_1",
    state: "PRESENT",
    tokens: ["person@example.com"],
  }], rules);
  const hybridRow = planAuthorizedCase("case_opaque", hybrid.observations, rules);

  assert.equal(deterministic.diagnostic?.caseId, "case_opaque");
  assert.equal(hybridRow.deletion_status, expected.deletion_status);
  assert.deepEqual(hybridRow.steps_json, expected.steps_json);
  assert.equal(deterministicUsage.records.length, 2);
  assert.equal(hybridUsage.records.length, 1);
  assert.equal(hybridUsage.records[0].inputTokens, 17);
  assert.equal(hybridUsage.records[0].outputTokens, 9);
});

test("records invalid responses, timeouts, and cache hits without continuing independent cases", async () => {
  const invalidUsage = newUsageTracker();
  const invalid = await investigatePacket(
    "case_invalid",
    packet,
    investigatorWith({ inspection_status: "RESOLVED" }, { inputTokens: 5, outputTokens: 2 }),
    new Map(),
    invalidUsage,
  );
  assert.equal(invalid.diagnostic?.caseId, "case_invalid");
  assert.deepEqual(invalidUsage.records.map((record) => [record.outcome, record.inputTokens, record.outputTokens]), [
    ["invalid", 5, 2],
    ["invalid", 5, 2],
  ]);

  const timeoutUsage = newUsageTracker();
  const timeout = await investigatePacket(
    "case_timeout",
    packet,
    { modelName: "mock-timeout", inspect: async () => { throw new Error("timeout"); } },
    new Map(),
    timeoutUsage,
  );
  assert.equal(timeout.diagnostic?.reason, "timeout");
  assert.deepEqual(timeoutUsage.records.map((record) => record.outcome), ["failed", "failed"]);

  let calls = 0;
  const cache = new Map();
  const cacheUsage = newUsageTracker();
  const cachedInvestigator: EvidenceInvestigator = {
    modelName: "mock-gemini",
    inspect: async () => {
      calls += 1;
      return { response: validResponse, usage: { inputTokens: 11, outputTokens: 7 } };
    },
  };
  await investigatePacket("case_cache", packet, cachedInvestigator, cache, cacheUsage);
  await investigatePacket("case_cache", packet, cachedInvestigator, cache, cacheUsage);
  assert.equal(calls, 1);
  assert.equal(cacheUsage.records[1].cacheHit, true);
  assert.equal(cacheUsage.records[1].inputTokens, 0);
  assert.equal(cacheUsage.records[1].outputTokens, 0);
});

function investigatorWith(response: unknown, usage: { inputTokens: number; outputTokens: number }): EvidenceInvestigator {
  return {
    modelName: "mock-gemini",
    inspect: async () => ({ response, usage }),
  };
}
