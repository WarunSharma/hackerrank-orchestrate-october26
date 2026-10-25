import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSubjects,
  classifyAuthorization,
  reconstructAt,
  resolveSubject,
  type EvidenceObservation,
} from "./reconstruction.js";

test("independent case: non-deletion export requests are not applicable", () => {
  assert.equal(classifyAuthorization("Please send me an export of my data."), "NOT_AUTHORIZED");
});

test("independent case: historical email resolves to the current subject", () => {
  const subjects = buildSubjects(
    [{ user_id: "user_history", name: "Ari Stone", email: "current@example.com", phone: "1", email_hash: "hash" }],
    [{ user_id: "user_history", old_value: "old@example.com", new_value: "current@example.com" }],
  );

  const subject = resolveSubject("old@example.com", subjects.values());
  assert.equal(subject?.userId, "user_history");
  assert.ok(subject?.aliases.has("current@example.com"));
  assert.ok(subject?.aliases.has("old@example.com"));
});

test("independent case: post-cutoff observations cannot establish current state", () => {
  const subject = buildSubjects(
    [{ user_id: "user_cutoff", name: "Sam Lee", email: "sam@example.com", phone: "2", email_hash: "hash2" }],
    [],
  ).get("user_cutoff")!;
  const observations: EvidenceObservation[] = [{
    evidenceId: "evidence_after_cutoff",
    sourcePath: "evidence/state.json",
    capturedAt: "2026-01-03T00:00:00Z",
    eventTime: "2026-01-02T00:00:00Z",
    systemId: "account_service",
    resourceId: "account_cutoff",
    state: "PRESENT",
    tokens: ["sam@example.com"],
  }];

  assert.equal(reconstructAt(subject, observations, "2026-01-02T12:00:00Z").size, 0);
});
