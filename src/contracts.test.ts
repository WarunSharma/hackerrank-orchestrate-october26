import test from "node:test";
import assert from "node:assert/strict";
import { outputRowSchema, parseCsv, readValidatedInputs, validateOutputRows, validateRequest } from "./contracts.js";

const validRequest = {
  case_id: "case_1",
  email: "person@example.com",
  requested_at: "2026-01-01T00:00:00Z",
  reported_status: "COMPLETE",
  reported_at: "2026-01-01T01:00:00Z",
  audit_at: "2026-01-01T02:00:00Z",
  request_text: "Delete my account",
};

test("rejects missing headers", () => {
  assert.throws(() => parseCsv("case_id,email\nx,a@b.com", ["case_id", "audit_at"]), /Missing required header/);
});

test("parses quoted fields containing commas", () => {
  assert.deepEqual(parseCsv("case_id,request_text\ncase_1,\"Delete, please\"", ["case_id", "request_text"]), [{
    case_id: "case_1",
    request_text: "Delete, please",
  }]);
});

test("rejects missing required request values", () => {
  assert.throws(() => validateRequest({ ...validRequest, request_text: "" }), /Missing required value/);
});

test("rejects malformed timestamps", () => {
  assert.throws(() => validateRequest({ ...validRequest, requested_at: "2026-02-31T00:00:00Z" }), /Invalid timestamp/);
});

test("rejects invalid statuses", () => {
  assert.throws(() => validateRequest({ ...validRequest, reported_status: "DONE" }), /Invalid reported_status/);
});

test("rejects invalid step shapes", () => {
  assert.equal(outputRowSchema.safeParse({
    case_id: "case_1",
    deletion_status: "COMPLETE",
    steps_json: [{
      step_no: 1,
      phase: "FINDING",
      system_id: "account_service",
      resource_id: "account_1",
      operation: "REPORT_REMAINING_RECORD",
      state: "ABSENT",
      evidence_id: "evidence_1",
    }],
  }).success, false);
});

test("rejects invalid output evidence placement", () => {
  assert.throws(() => validateOutputRows([{
    case_id: "case_1",
    deletion_status: "INCOMPLETE",
    steps_json: [{
      step_no: 1,
      phase: "REMEDIATION",
      system_id: "account_service",
      resource_id: "account_1",
      operation: "DELETE_RECORD",
      state: "ABSENT",
      evidence_id: "activity_1",
    }],
  }]));
});

test("validates every required participant input file", () => {
  const inputs = readValidatedInputs();
  assert.equal(inputs.deletionRequests.length, 518);
  assert.equal(inputs.sampleDeletionRequests.length, 32);
  assert.ok(inputs.userIdentities.length > 0);
  assert.ok(inputs.userAuditLog.length > 0);
  assert.ok(inputs.systemActivity.length > 0);
  assert.ok(inputs.deletionRules.length > 0);
  assert.ok(inputs.evidenceFiles.length > 0);
});
