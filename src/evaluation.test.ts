import test from "node:test";
import assert from "node:assert/strict";
import { evaluateSample } from "./evaluation.js";
import type { PlannedRow } from "./planner.js";

const step = {
  step_no: 1,
  phase: "VERIFICATION" as const,
  system_id: "account_service",
  resource_id: "account_1",
  operation: "VERIFY_RECORD_ABSENT" as const,
  state: "ABSENT",
  evidence_id: "evidence_1",
};

test("reports missing, field, and sequence metrics for altered sample predictions", () => {
  const metrics = evaluateSample([
    { case_id: "case_1", deletion_status: "COMPLETE", steps_json: [step] },
    { case_id: "case_2", deletion_status: "NOT_APPLICABLE", steps_json: [] },
  ], [{
    case_id: "case_1",
    deletion_status: "COMPLETE",
    steps_json: [{ ...step, evidence_id: "wrong_evidence" }],
  }] satisfies PlannedRow[]);

  assert.deepEqual(metrics.missingCaseIds, ["case_2"]);
  assert.equal(metrics.statusCorrect, 1);
  assert.equal(metrics.stepCorrect, 0);
  assert.equal(metrics.fieldCorrect, 6);
  assert.equal(metrics.sequenceCorrect, 0);
  assert.deepEqual(metrics.mismatches, [
    { caseId: "case_1", reason: "FIELD" },
    { caseId: "case_2", reason: "MISSING" },
  ]);
});
