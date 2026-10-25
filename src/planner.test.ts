import test from "node:test";
import assert from "node:assert/strict";
import { parseCsv } from "./contracts.js";
import {
  addProvisionalRows,
  categoryFor,
  compareCaseIds,
  generateRows,
  policyActions,
  planAuthorizedCase,
  semanticOutputIssues,
  sortAndNumber,
  writeOutput,
} from "./planner.js";
import type { ValidatedInputs } from "./contracts.js";
import type { EvidenceInvestigator } from "./investigator.js";
import type { EvidenceObservation } from "./reconstruction.js";
import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const rules = policyActions([
  { data_category: "USER_PROFILE", required_action: "DELETE" },
  { data_category: "SEARCH_INDEX_ENTRY", required_action: "DELETE" },
  { data_category: "SUPPORT_MESSAGE", required_action: "REDACT" },
  { data_category: "ANALYTICS_PROFILE", required_action: "ANONYMIZE" },
  { data_category: "SECURITY_AUDIT_LOG", required_action: "RETAIN" },
  { data_category: "ACCOUNT_TOMBSTONE", required_action: "REDACT" },
]);

function observation(category: string, state: EvidenceObservation["state"], resourceId: string, systemId = "service"): EvidenceObservation {
  return { evidenceId: "evidence_1", sourcePath: "fixture", eventTime: "2026-01-01T00:00:00Z", systemId, resourceId, state, tokens: ["person@example.com"], category };
}

test("adds provisional rows without changing resolved rows and reports semantic failures", () => {
  const resolved = planAuthorizedCase("case_1", [observation("USER_PROFILE", "ABSENT", "account_1")], rules);
  const before = JSON.stringify(resolved);
  const rows = addProvisionalRows([resolved], ["case_2", "case_3"]);

  assert.equal(JSON.stringify(rows[0]), before);
  assert.deepEqual(rows.slice(1), [
    { case_id: "case_2", deletion_status: "INCOMPLETE", steps_json: [] },
    { case_id: "case_3", deletion_status: "INCOMPLETE", steps_json: [] },
  ]);
  assert.deepEqual(semanticOutputIssues(rows), [
    { caseId: "case_2", reason: "INCOMPLETE is missing FINDING, REMEDIATION, VERIFICATION steps" },
    { caseId: "case_3", reason: "INCOMPLETE is missing FINDING, REMEDIATION, VERIFICATION steps" },
  ]);
  assert.throws(() => addProvisionalRows([resolved], ["case_1"]), /existing case case_1/);
});

test("preserves conditional retained records and redacts tombstones", () => {
  const deleted = planAuthorizedCase("case_absent", [observation("USER_PROFILE", "ABSENT", "account_1")], rules);
  assert.deepEqual(deleted.steps_json.map((step) => step.operation), ["VERIFY_RECORD_ABSENT"]);
  const complete = planAuthorizedCase("case_1", [observation("SECURITY_AUDIT_LOG", "PRESENT", "audit_1")], rules);
  assert.equal(complete.deletion_status, "COMPLETE");
  assert.equal(complete.steps_json[0].operation, "VERIFY_RECORD_PRESENT");
  const incomplete = planAuthorizedCase("case_2", [observation("ACCOUNT_TOMBSTONE", "PRESENT", "tombstone_1")], rules);
  assert.deepEqual(incomplete.steps_json.map((step) => step.operation), ["REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"]);
  const anonymize = planAuthorizedCase("case_3", [observation("ANALYTICS_PROFILE", "PRESENT", "analytics_1")], rules);
  assert.deepEqual(anonymize.steps_json.map((step) => step.operation), ["REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"]);
});

test("incomplete plans verify every recognized resource with empty future evidence", () => {
  const row = planAuthorizedCase("case_mixed_state", [
    observation("USER_PROFILE", "ABSENT", "account_1", "account_service"),
    observation("SEARCH_INDEX_ENTRY", "PRESENT", "search_1", "search_service"),
    observation("ANALYTICS_PROFILE", "PRESENT", "analytics_1", "analytics_platform"),
    observation("SUPPORT_MESSAGE", "PRESENT", "support_1", "support_platform"),
    observation("SECURITY_AUDIT_LOG", "PRESENT", "audit_record_1", "security_service"),
  ], rules);
  assert.equal(row.deletion_status, "INCOMPLETE");
  assert.deepEqual(row.steps_json.filter((step) => step.phase === "FINDING").map((step) => [
    step.operation,
    step.system_id,
  ]), [
    ["REPORT_REMAINING_RECORD", "search_service"],
    ["REPORT_EXPOSED_PII", "analytics_platform"],
    ["REPORT_EXPOSED_PII", "support_platform"],
  ]);
  assert.deepEqual(row.steps_json.filter((step) => step.phase === "VERIFICATION").map((step) => [
    step.operation,
    step.system_id,
    step.resource_id,
    step.evidence_id,
  ]), [
    ["VERIFY_RECORD_ABSENT", "account_service", "account_1", ""],
    ["VERIFY_RECORD_ABSENT", "search_service", "search_1", ""],
    ["VERIFY_RECORD_PRESENT", "security_service", "audit_record_1", ""],
    ["VERIFY_RECORD_REDACTED", "support_platform", "support_1", ""],
    ["VERIFY_RECORD_ANONYMIZED", "analytics_platform", "analytics_1", ""],
  ]);
  assert.ok(row.steps_json
    .filter((step) => step.phase === "FINDING")
    .every((step) => step.evidence_id === "evidence_1"));
  assert.ok(row.steps_json
    .filter((step) => step.phase !== "FINDING")
    .every((step) => step.evidence_id === ""));
});

test("keeps an opaque-evidence case unresolved when the default investigator cannot inspect it", async () => {
  const directory = path.join(tmpdir(), `opaque-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "record.png"), "opaque fixture");
  const inputs = fixtureInputs();
  inputs.evidenceFiles = [{ file_id: "evidence_1", file_path: "evidence/record.png", captured_at: "2026-01-01T00:00:00Z" }];
  try {
    const result = await generateRows(inputs, directory);
    assert.deepEqual(result.rows, []);
    assert.deepEqual(result.unresolvedCases, ["case_1"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("does not emit COMPLETE when grounded opaque evidence remains unresolved beside deterministic state", async () => {
  const directory = path.join(tmpdir(), `opaque-with-state-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "state.json"), JSON.stringify({
    system: "account_service",
    resource_id: "account_1",
    result: "ABSENT",
    email: "person@example.com",
    recorded_at: "2026-01-01T00:00:00Z",
  }));
  write(path.join(evidenceDirectory, "linked.png"), "person@example.com");
  const inputs = fixtureInputs();
  inputs.evidenceFiles = [
    { file_id: "evidence_state", file_path: "evidence/state.json", captured_at: "2026-01-01T00:00:00Z" },
    { file_id: "evidence_opaque", file_path: "evidence/linked.png", captured_at: "2026-01-01T00:00:00Z" },
  ];
  try {
    const result = await generateRows(inputs, directory);
    assert.deepEqual(result.rows, []);
    assert.deepEqual(result.unresolvedCases, ["case_1"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("investigates grounded opaque evidence even when deterministic state exists", async () => {
  const directory = path.join(tmpdir(), `opaque-merge-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "state.json"), JSON.stringify({
    system: "account_service",
    resource_id: "account_1",
    result: "ABSENT",
    email: "person@example.com",
    recorded_at: "2026-01-01T00:00:00Z",
  }));
  write(path.join(evidenceDirectory, "linked.png"), "person@example.com");
  const inputs = fixtureInputs();
  inputs.evidenceFiles = [
    { file_id: "evidence_state", file_path: "evidence/state.json", captured_at: "2026-01-01T00:00:00Z" },
    { file_id: "evidence_opaque", file_path: "evidence/linked.png", captured_at: "2026-01-01T00:00:00Z" },
  ];
  let calls = 0;
  const investigator: EvidenceInvestigator = { modelName: "mock", inspect: async () => {
    calls += 1;
    return { response: {
      inspection_status: "RESOLVED",
      identifier_matches: ["person@example.com"],
      observations: [{
        system_id: "account_service",
        visible_resource_label: "account_2",
        event_time: "2026-01-01T00:00:00Z",
        state: "PRESENT",
        matched_identifier: "person@example.com",
        location: "record 2",
        confidence: 1,
      }],
      unresolved_reason: null,
    }, usage: { inputTokens: 0, outputTokens: 0 } };
  } };
  try {
    const result = await generateRows(inputs, directory, investigator);
    assert.equal(calls, 1);
    assert.equal(result.unresolvedCases.length, 0);
    assert.equal(result.rows[0].deletion_status, "INCOMPLETE");
    assert.ok(result.rows[0].steps_json.some((step) =>
      step.resource_id === "account_2" && step.evidence_id === "evidence_opaque"));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("uses deterministic PDF facts without an investigator when resource and identity are explicit", async () => {
  const directory = path.join(tmpdir(), `pdf-deterministic-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "linked.pdf"), [
    "%PDF-1.4",
    "1 0 obj",
    "<< >>",
    "stream",
    "BT (Support attachment support_009) Tj (person@example.com) Tj (Upload history) Tj ET",
    "endstream",
    "endobj",
  ].join("\n"));
  const inputs = fixtureInputs();
  inputs.deletionRules.push({ data_category: "SUPPORT_ATTACHMENT", required_action: "DELETE" });
  inputs.evidenceFiles = [{
    file_id: "evidence_pdf",
    file_path: "evidence/linked.pdf",
    captured_at: "2026-01-01T00:00:00Z",
  }];
  let calls = 0;
  const investigator: EvidenceInvestigator = { modelName: "mock", inspect: async () => {
    calls += 1;
    throw new Error("Deterministically interpreted PDFs must not invoke the investigator");
  } };
  try {
    const result = await generateRows(inputs, directory, investigator);
    assert.equal(calls, 0);
    assert.equal(result.unresolvedCases.length, 0);
    assert.equal(result.rows[0].deletion_status, "INCOMPLETE");
    assert.ok(result.rows[0].steps_json.some((step) =>
      step.resource_id === "support_009" && step.evidence_id === "evidence_pdf"));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("links a PDF's visible catalog label to its canonical export resource", async () => {
  const directory = path.join(tmpdir(), `pdf-catalog-link-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "statement.pdf"), [
    "%PDF-1.4",
    "1 0 obj",
    "<< >>",
    "stream",
    "BT (Customer statement NST-2026-0718-1842) Tj (user_1) Tj (person@example.com) Tj ET",
    "endstream",
    "endobj",
  ].join("\n"));
  const inputs = fixtureInputs();
  inputs.deletionRules.push({ data_category: "USER_EXPORT", required_action: "DELETE" });
  inputs.evidenceFiles = [{
    file_id: "evidence_statement",
    file_path: "evidence/statement.pdf",
    captured_at: "2026-01-01T00:00:00Z",
  }];
  inputs.systemActivity = [{
    activity_id: "activity_export_link",
    event_time: "2026-01-01T00:07:00Z",
    event_type: "LINK_RESOURCE_IDENTITY",
    target_system: "export_service",
    resource_id: "export_1842",
    reported_result: "SUCCESS",
    details: "Data catalog linked export_1842 (NST-2026-0718-1842) to person@example.com and user_1.",
  }];
  let calls = 0;
  const investigator: EvidenceInvestigator = {
    modelName: "mock",
    inspect: async () => {
      calls += 1;
      throw new Error("The PDF and catalog metadata provide a deterministic association");
    },
  };
  try {
    const result = await generateRows(inputs, directory, investigator);
    assert.equal(calls, 0);
    assert.deepEqual(result.unresolvedCases, []);
    assert.equal(result.rows[0].deletion_status, "INCOMPLETE");
    assert.ok(result.rows[0].steps_json.some((step) =>
      step.resource_id === "export_1842" && step.evidence_id === "evidence_statement"));
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("keeps the opaque PDF fallback for grounded ambiguity and excludes unrelated PDFs", async () => {
  const directory = path.join(tmpdir(), `pdf-fallback-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  const pdf = (email: string) => [
    "%PDF-1.4",
    "1 0 obj",
    "<< >>",
    "stream",
    `BT (${email}) Tj ET`,
    "endstream",
    "endobj",
  ].join("\n");
  write(path.join(evidenceDirectory, "ambiguous.pdf"), pdf("person@example.com"));
  write(path.join(evidenceDirectory, "unrelated.pdf"), pdf("other@example.com"));
  const inputs = fixtureInputs();
  inputs.userIdentities = [{
    user_id: "user_123456",
    name: "Casey Example",
    email: "person@example.com",
    phone: "",
    email_hash: "",
  }];
  inputs.evidenceFiles = [
    { file_id: "evidence_ambiguous", file_path: "evidence/ambiguous.pdf", captured_at: "2026-01-01T00:00:00Z" },
    { file_id: "evidence_unrelated", file_path: "evidence/unrelated.pdf", captured_at: "2026-01-01T00:00:00Z" },
  ];
  const inspected: string[] = [];
  const investigator: EvidenceInvestigator = { modelName: "mock", inspect: async (packet) => {
    inspected.push(packet.fileId);
    return {
      response: {
        inspection_status: "UNRESOLVED",
        identifier_matches: [],
        observations: [],
        unresolved_reason: "Fixture ambiguity",
      },
      usage: { inputTokens: 0, outputTokens: 0 },
    };
  } };
  try {
    const result = await generateRows(inputs, directory, investigator);
    assert.deepEqual(inspected, ["evidence_ambiguous", "evidence_ambiguous"]);
    assert.deepEqual(result.unresolvedCases, ["case_1"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("uses a correlated full profile snapshot to verify an absent resource", async () => {
  const directory = path.join(tmpdir(), `snapshot-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "profiles.sql"), [
    "CREATE TABLE customer_profiles_primary (resource_id TEXT, user_id TEXT, full_name TEXT, email TEXT, phone TEXT, account_status TEXT, updated_at TEXT);",
    `INSERT INTO "customer_profiles_primary" VALUES('other_account','other_user','Other','other@example.com','2','ACTIVE','2026-01-02T00:00:00Z');`,
  ].join("\n"));
  const inputs = fixtureInputs();
  inputs.deletionRequests = [{
    ...inputs.deletionRequests[0],
    reported_at: "2026-01-02T00:00:00Z",
    audit_at: "2026-01-04T00:00:00Z",
  }];
  inputs.systemActivity = [{
    activity_id: "activity_1",
    event_time: "2026-01-02T00:04:00Z",
    event_type: "DELETE_RECORD",
    target_system: "account_service",
    resource_id: "account_1",
    reported_result: "PARTIAL",
    details: "Generic workflow report",
  }];
  inputs.evidenceFiles = [{
    file_id: "evidence_snapshot",
    file_path: "evidence/profiles.sql",
    captured_at: "2026-01-03T00:00:00Z",
  }];
  try {
    const result = await generateRows(inputs, directory);
    assert.equal(result.unresolvedCases.length, 0);
    assert.equal(result.rows[0].deletion_status, "COMPLETE");
    assert.deepEqual(result.rows[0].steps_json.map(({ resource_id, evidence_id }) => [resource_id, evidence_id]), [
      ["account_1", "evidence_snapshot"],
    ]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("does not invoke the investigator for an ungrounded opaque decoy", async () => {
  const directory = path.join(tmpdir(), `opaque-decoy-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "record.png"), "unrelated customer");
  const inputs = fixtureInputs();
  inputs.evidenceFiles = [{ file_id: "evidence_1", file_path: "evidence/record.png", captured_at: "2026-01-01T00:00:00Z" }];
  let calls = 0;
  const investigator: EvidenceInvestigator = { modelName: "mock", inspect: async () => {
    calls += 1;
    return { response: {}, usage: { inputTokens: 0, outputTokens: 0 } };
  } };
  try {
    const result = await generateRows(inputs, directory, investigator);
    assert.deepEqual(result.unresolvedCases, ["case_1"]);
    assert.equal(calls, 0);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("uses a grounded eligible text artifact as an investigator fallback", async () => {
  const directory = path.join(tmpdir(), `opaque-text-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "record.txt"), "person@example.com unreadable payload");
  const inputs = fixtureInputs();
  inputs.evidenceFiles = [{ file_id: "evidence_1", file_path: "evidence/record.txt", captured_at: "2026-01-01T00:00:00Z" }];
  let calls = 0;
  const investigator: EvidenceInvestigator = { modelName: "mock", inspect: async () => {
    calls += 1;
    return { response: {
      inspection_status: "RESOLVED", identifier_matches: ["person@example.com"], observations: [{
        system_id: "account_service", visible_resource_label: "account_1", event_time: "2026-01-01T00:00:00Z",
        state: "ABSENT", matched_identifier: "person@example.com", location: "record", confidence: 1,
      }], unresolved_reason: null,
    }, usage: { inputTokens: 0, outputTokens: 0 } };
  } };
  try {
    const result = await generateRows(inputs, directory, investigator);
    assert.equal(calls, 1);
    assert.equal(result.unresolvedCases.length, 0);
    assert.equal(result.rows[0].deletion_status, "COMPLETE");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("requires disabled flows and blocked restores in complete verification coverage", () => {
  const row = planAuthorizedCase("case_controls", [
    observation("DATA_FLOW", "DISABLED", "data_flow_1", "integration_service"),
    observation("BACKUP_ARCHIVE", "BLOCKED", "backup_1", "backup_service"),
  ], rules);
  assert.equal(row.deletion_status, "COMPLETE");
  assert.deepEqual(row.steps_json.map((step) => step.operation), [
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
  ]);
});

test("uses validated opaque observations without allowing post-cutoff evidence", async () => {
  const directory = path.join(tmpdir(), `opaque-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "record.png"), "opaque fixture");
  const inputs = fixtureInputs();
  inputs.evidenceFiles = [{ file_id: "evidence_1", file_path: "evidence/record.png", captured_at: "2026-01-03T00:00:00Z" }];
  const investigator: EvidenceInvestigator = { modelName: "mock", inspect: async () => ({ response: {
    inspection_status: "RESOLVED", identifier_matches: ["person@example.com"], observations: [{
      system_id: "account_service", visible_resource_label: "account_1", event_time: "2026-01-01T00:00:00Z",
      state: "ABSENT", matched_identifier: "person@example.com", location: "screen", confidence: 1,
    }], unresolved_reason: null,
  }, usage: { inputTokens: 0, outputTokens: 0 } }) };
  try {
    const result = await generateRows(inputs, directory, investigator);
    assert.deepEqual(result.rows, []);
    assert.deepEqual(result.unresolvedCases, ["case_1"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("grounds opaque screenshots through a pre-cutoff identity link", async () => {
  const directory = path.join(tmpdir(), `screenshot-link-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "screen.png"), Buffer.from([137, 80, 78, 71]));
  const inputs = fixtureInputs();
  inputs.evidenceFiles = [{ file_id: "evidence_screen", file_path: "evidence/screen.png", captured_at: "2026-01-01T00:00:00Z" }];
  inputs.deletionRules = [
    { data_category: "USER_PROFILE", required_action: "DELETE" },
    { data_category: "SEARCH_INDEX_ENTRY", required_action: "DELETE" },
  ];
  inputs.systemActivity = [{
    activity_id: "activity_link",
    event_time: "2026-01-01T00:07:00Z",
    event_type: "LINK_RESOURCE_IDENTITY",
    target_system: "search_service",
    resource_id: "search_1",
    reported_result: "SUCCESS",
    details: "Data catalog linked search_1 to person@example.com and user_1.",
  }];
  const investigator: EvidenceInvestigator = {
    modelName: "mock",
    inspect: async (packet) => {
      assert.equal(packet.fileId, "evidence_screen");
      return { response: {
        inspection_status: "RESOLVED",
        identifier_matches: ["person@example.com"],
        observations: [{
          visible_resource_label: "search_1",
          state: "PRESENT",
          matched_identifier: "person@example.com",
          location: "search result row",
          confidence: 1,
        }],
        unresolved_reason: null,
      }, usage: { inputTokens: 0, outputTokens: 0 } };
    },
  };
  try {
    const result = await generateRows(inputs, directory, investigator);
    assert.equal(result.unresolvedCases.length, 0);
    assert.equal(result.rows.length, 1);
    assert.equal(result.rows[0].deletion_status, "INCOMPLETE");
    assert.equal(result.rows[0].steps_json[0].evidence_id, "evidence_screen");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("plans a linked redacted account tombstone without treating it as a profile", async () => {
  const directory = path.join(tmpdir(), `tombstone-link-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "screen.png"), Buffer.from([137, 80, 78, 71]));
  const inputs = fixtureInputs();
  inputs.evidenceFiles = [{ file_id: "evidence_tombstone", file_path: "evidence/screen.png", captured_at: "2026-01-01T00:00:00Z" }];
  inputs.deletionRules = [{ data_category: "ACCOUNT_TOMBSTONE", required_action: "REDACT" }];
  inputs.systemActivity = [{
    activity_id: "activity_tombstone_link",
    event_time: "2026-01-01T00:05:00Z",
    event_type: "LINK_RESOURCE_IDENTITY",
    target_system: "identity_service",
    resource_id: "tombstone_1",
    reported_result: "SUCCESS",
    details: "Identity service linked tombstone_1 (user_1) to person@example.com and user_1.",
  }];
  const investigator: EvidenceInvestigator = {
    modelName: "mock",
    inspect: async (packet) => {
      assert.deepEqual(packet.linkedResources, [{
        systemId: "identity_service",
        resourceId: "tombstone_1",
        category: "ACCOUNT_TOMBSTONE",
        linkEvidenceId: "activity_tombstone_link",
        linkedAt: "2026-01-01T00:05:00Z",
        visibleLabels: ["tombstone_1", "user_1"],
      }]);
      return { response: {
        inspection_status: "RESOLVED",
        identifier_matches: ["person@example.com"],
        observations: [{
          visible_resource_label: "user_1",
          state: "REDACTED",
          location: "reference row",
          confidence: 0.95,
        }],
        unresolved_reason: null,
      }, usage: { inputTokens: 0, outputTokens: 0 } };
    },
  };
  try {
    const result = await generateRows(inputs, directory, investigator);
    assert.equal(result.unresolvedCases.length, 0);
    assert.equal(result.rows[0].deletion_status, "COMPLETE");
    assert.equal(result.rows[0].steps_json[0].operation, "VERIFY_RECORD_REDACTED");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fixtureInputs(): ValidatedInputs {
  return {
    deletionRequests: [{ case_id: "case_1", email: "person@example.com", audit_at: "2026-01-02T00:00:00Z", request_text: "Please delete my account" }],
    sampleDeletionRequests: [],
    userIdentities: [{ user_id: "user_1", name: "Person", email: "person@example.com", phone: "1", email_hash: "hash" }],
    userAuditLog: [],
    systemActivity: [],
    deletionRules: [{ data_category: "USER_PROFILE", required_action: "DELETE" }],
    evidenceFiles: [],
  };
}

test("plans flow and restore controls before dependent record changes", () => {
  const row = planAuthorizedCase("case_3", [
    observation("USER_PROFILE", "PRESENT", "account_1", "account_service"),
    observation("DATA_FLOW", "ACTIVE", "data_flow_1", "integration_service"),
    observation("BACKUP_ARCHIVE", "ACTIVE", "backup_1", "backup_service"),
  ], rules);
  assert.deepEqual(row.steps_json.map((step) => step.phase), [
    "FINDING", "FINDING", "FINDING", "REMEDIATION", "REMEDIATION", "REMEDIATION", "VERIFICATION", "VERIFICATION", "VERIFICATION",
  ]);
  assert.deepEqual(row.steps_json.slice(3, 6).map((step) => step.operation), ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD"]);
});

test("uses canonical phase and operation ordering with empty future evidence", () => {
  const steps = sortAndNumber([
    { step_no: 0, phase: "VERIFICATION", system_id: "z", resource_id: "z", operation: "VERIFY_RECORD_ABSENT", state: "ABSENT", evidence_id: "" },
    { step_no: 0, phase: "FINDING", system_id: "b", resource_id: "b", operation: "REPORT_EXPOSED_PII", state: "PRESENT", evidence_id: "evidence_1" },
    { step_no: 0, phase: "FINDING", system_id: "a", resource_id: "a", operation: "REPORT_REMAINING_RECORD", state: "PRESENT", evidence_id: "evidence_1" },
  ]);
  assert.deepEqual(steps.map((step) => [step.step_no, step.operation]), [[1, "REPORT_REMAINING_RECORD"], [2, "REPORT_EXPOSED_PII"], [3, "VERIFY_RECORD_ABSENT"]]);
});

test("sorts numbered case IDs in numeric order", () => {
  assert.deepEqual(["case_10", "case_2", "case_1"].sort(compareCaseIds), ["case_1", "case_2", "case_10"]);
});

test("maps known resource families without treating unknown IDs as user profiles", () => {
  assert.equal(categoryFor(observation("UNKNOWN", "PRESENT", "audit_record_003")), "SECURITY_AUDIT_LOG");
  assert.equal(categoryFor(observation("UNKNOWN", "PRESENT", "marketing_001")), "MARKETING_PROFILE");
  assert.equal(categoryFor(observation("retained_order_records", "PRESENT", "legal_hold_1")), "LEGAL_HOLD_RECORD");
  assert.equal(categoryFor(observation("support_conversations", "PRESENT", "support_1")), "SUPPORT_MESSAGE");
  assert.equal(categoryFor(observation("UNKNOWN", "PRESENT", "object_19")), undefined);
});

test("keeps backup presence unresolved without explicit restore permission", async () => {
  const directory = path.join(tmpdir(), `backup-presence-${Date.now()}`);
  const evidenceDirectory = path.join(directory, "evidence");
  const { mkdirSync, writeFileSync: write } = await import("node:fs");
  mkdirSync(evidenceDirectory, { recursive: true });
  write(path.join(evidenceDirectory, "backup.json"), JSON.stringify({
    system: "backup_service",
    resource_id: "backup_1",
    record_type: "BACKUP_ARCHIVE",
    result: "FOUND",
    email: "person@example.com",
    recorded_at: "2026-01-01T00:00:00Z",
  }));
  const inputs = fixtureInputs();
  inputs.evidenceFiles = [{ file_id: "evidence_backup", file_path: "evidence/backup.json", captured_at: "2026-01-01T00:00:00Z" }];
  try {
    const result = await generateRows(inputs, directory);
    assert.deepEqual(result.unresolvedCases, ["case_1"]);
    assert.deepEqual(result.rows, []);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("writes sorted, canonically numbered CSV output with valid evidence references", () => {
  const destination = path.join(tmpdir(), `output-${Date.now()}.csv`);
  try {
    writeOutput([
      { case_id: "case_2", deletion_status: "NOT_APPLICABLE", steps_json: [] },
      {
        case_id: "case_1",
        deletion_status: "COMPLETE",
        steps_json: [{
          step_no: 7,
          phase: "VERIFICATION",
          system_id: "account_service",
          resource_id: "account_1",
          operation: "VERIFY_RECORD_ABSENT",
          state: "ABSENT",
          evidence_id: "evidence_1",
        }],
      },
    ], destination, new Set(["evidence_1"]));
    const rows = parseCsv(readFileSync(destination, "utf8"), ["case_id", "deletion_status", "steps_json"]);
    assert.deepEqual(rows.map((row) => row.case_id), ["case_1", "case_2"]);
    assert.equal(JSON.parse(rows[0].steps_json)[0].step_no, 1);
    assert.deepEqual(JSON.parse(rows[1].steps_json), []);
    assert.throws(() => writeOutput([{
      case_id: "case_1",
      deletion_status: "COMPLETE",
      steps_json: [{
        step_no: 1,
        phase: "VERIFICATION",
        system_id: "account_service",
        resource_id: "account_1",
        operation: "VERIFY_RECORD_ABSENT",
        state: "ABSENT",
        evidence_id: "missing",
      }],
    }], destination, new Set(["evidence_1"])), /Invalid evidence_id/);
  } finally {
    rmSync(destination, { force: true });
  }
});
