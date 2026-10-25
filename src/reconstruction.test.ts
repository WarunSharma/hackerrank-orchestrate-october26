import test from "node:test";
import assert from "node:assert/strict";
import { deflateSync } from "node:zlib";
import { datasetDirectory } from "./config.js";
import { readValidatedInputs } from "./contracts.js";
import {
  activityObservations,
  buildSubjects,
  classifyAuthorization,
  extractEvidence,
  readEvidence,
  reconstructAt,
  requestResourceLink,
  resolveSubject,
  type EvidenceObservation,
} from "./reconstruction.js";

function encodeAscii85(bytes: Buffer): string {
  let encoded = "";
  for (let offset = 0; offset < bytes.length; offset += 4) {
    const chunk = [...bytes.subarray(offset, offset + 4)];
    const length = chunk.length;
    while (chunk.length < 4) chunk.push(0);
    let value = ((chunk[0] * 256 + chunk[1]) * 256 + chunk[2]) * 256 + chunk[3];
    const digits = Array.from({ length: 5 }, () => {
      const digit = value % 85;
      value = Math.floor(value / 85);
      return String.fromCharCode(digit + 33);
    }).reverse().join("");
    encoded += digits.slice(0, length + 1);
  }
  return `${encoded}~>`;
}

function compressedTextPdf(text: string): string {
  const compressed = encodeAscii85(deflateSync(Buffer.from(text, "latin1")));
  return `%PDF-1.4\n1 0 obj\n<< /Filter [ /ASCII85Decode /FlateDecode ] >>\nstream\n${compressed}\nendstream\nendobj\n`;
}

test("classifies multilingual deletion separately from access and export requests", () => {
  assert.equal(classifyAuthorization("Please permanently delete my account"), "AUTHORIZED");
  assert.equal(classifyAuthorization("¿Pueden completar la eliminación si hace falta?"), "AUTHORIZED");
  assert.equal(classifyAuthorization("Je demande la suppression définitive du compte."), "AUTHORIZED");
  assert.equal(classifyAuthorization("このメールアドレスに関連するアカウントの完全な削除を依頼します。"), "AUTHORIZED");
  assert.equal(classifyAuthorization("Please close the account permanently."), "AUTHORIZED");
  assert.equal(classifyAuthorization("Please close my account for good."), "AUTHORIZED");
  assert.equal(classifyAuthorization("Please delete my account and confirm when it is done."), "AUTHORIZED");
  assert.equal(classifyAuthorization("Please investigate and finish the deletion."), "AUTHORIZED");
  assert.equal(classifyAuthorization("Can you verify whether my account was deleted?"), "AUTHORIZED");
  assert.equal(classifyAuthorization("Please confirm my account was deleted."), "AUTHORIZED");
  assert.equal(classifyAuthorization("Please check the status of my completed deletion request."), "AUTHORIZED");
  assert.equal(classifyAuthorization("This is not a request for deletion; I only want promotional emails stopped."), "NOT_AUTHORIZED");
  assert.equal(classifyAuthorization("Do not close my account; I need help resetting my login."), "NOT_AUTHORIZED");
  assert.equal(classifyAuthorization("Please remove me from marketing lists only."), "NOT_AUTHORIZED");
  assert.equal(classifyAuthorization("I am not asking for deletion, only an export of my data."), "NOT_AUTHORIZED");
  assert.equal(classifyAuthorization("I still use the account, so please don't delete it."), "NOT_AUTHORIZED");
  assert.equal(classifyAuthorization("Please verify that my account email is correct."), "NOT_AUTHORIZED");
  assert.equal(classifyAuthorization("Please confirm my account is active."), "NOT_AUTHORIZED");
  assert.equal(classifyAuthorization("Please send me an export of my data"), "NOT_AUTHORIZED");
  assert.equal(classifyAuthorization("I would like access to my account data"), "NOT_AUTHORIZED");
});

test("resolves current and historical identity aliases", () => {
  const subjects = buildSubjects(
    [{ user_id: "user_1", name: "Casey", email: "current@example.com", phone: "1", email_hash: "hash" }],
    [{ user_id: "user_1", old_value: "old@example.com", new_value: "current@example.com" }],
  );
  const subject = resolveSubject("OLD@example.com", subjects.values());
  assert.equal(subject?.userId, "user_1");
  assert.ok(subject?.aliases.has("current@example.com"));
});

test("preserves provenance for JSON, log, text, and SQL evidence", () => {
  const manifest = { file_id: "evidence_1", file_path: "evidence/test.json", captured_at: "2026-01-01T00:00:00Z" };
  const json = extractEvidence(manifest, JSON.stringify({ records: [{ recorded_at: "2026-01-01T00:00:00Z", system: "account", resource_id: "r1", result: "FOUND", subject_reference: "old@example.com" }] }));
  const log = extractEvidence({ ...manifest, file_path: "evidence/test.log" }, '2026-01-01T00:00:00Z service=account resource_id="r2" result="NOT_FOUND" subject_reference="old@example.com"');
  const text = extractEvidence({ ...manifest, file_path: "evidence/test.txt" }, "- 2026-01-01T00:00:00Z | account | r3 | PROFILE | FOUND | old@example.com");
  const sql = extractEvidence({ ...manifest, file_path: "evidence/test.sql" }, `INSERT INTO "data" VALUES('r4','account','profiles','{"resource_id":"r4","subject_reference":"old@example.com","result":"FOUND"}','2026-01-01T00:00:00Z');`);
  for (const extraction of [json, log, text, sql]) {
    assert.equal(extraction.fileId, "evidence_1");
    assert.equal(extraction.inspected, true);
    assert.equal(extraction.observations.length, 1);
    assert.equal(extraction.observations[0].evidenceId, "evidence_1");
  }
});

test("maps explicitly enabled SQL connector configurations to active flows", () => {
  const enabled = extractEvidence({
    file_id: "evidence_connector",
    file_path: "evidence/connector.sql",
    captured_at: "2026-01-01T00:00:00Z",
  }, `INSERT INTO "customer_data_primary" VALUES('data_flow_1','integration_service','connector_configurations','{"resource_id":"data_flow_1","subject_selector":"person@example.com","enabled":true,"mode":"continuous_sync"}','2026-01-01T00:00:00Z');`);
  assert.deepEqual(enabled.observations.map((item) => [item.resourceId, item.state, item.category]), [
    ["data_flow_1", "ACTIVE", "DATA_FLOW"],
  ]);
  const disabled = extractEvidence({
    file_id: "evidence_connector_disabled",
    file_path: "evidence/connector.sql",
    captured_at: "2026-01-01T00:00:00Z",
  }, `INSERT INTO "customer_data_primary" VALUES('data_flow_1','integration_service','connector_configurations','{"resource_id":"data_flow_1","subject_selector":"person@example.com","enabled":false,"mode":"continuous_sync"}','2026-01-01T00:00:00Z');`);
  assert.equal(disabled.observations[0].state, "DISABLED");
});

test("maps explicit SQL backup permissions to active or blocked restore states", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_backup_permissions", file_path: "evidence/backups.sql", captured_at: "2026-01-02T00:00:00Z" },
    [
      `INSERT INTO "customer_data_primary" VALUES('backup_active','backup_service','backup_catalog','{"resource_id":"backup_active","archive_path":"archive.tar","subject_reference":"user_1","restore_allowed":true}','2026-01-01T00:00:00Z');`,
      `INSERT INTO "customer_data_primary" VALUES('backup_blocked','backup_service','backup_catalog','{"resource_id":"backup_blocked","archive_path":"archive.tar","subject_reference":"user_1","restore_allowed":false}','2026-01-01T00:00:00Z');`,
    ].join("\n"),
  );
  assert.deepEqual(extraction.observations.map(({ resourceId, category, state }) => [resourceId, category, state]), [
    ["backup_active", "BACKUP_ARCHIVE", "ACTIVE"],
    ["backup_blocked", "BACKUP_ARCHIVE", "BLOCKED"],
  ]);
});

test("extracts ASCII85/Flate PDF text into a grounded resource observation", () => {
  const manifest = {
    file_id: "evidence_pdf",
    file_path: "evidence/support.pdf",
    captured_at: "2026-01-02T00:00:00Z",
  };
  const extraction = extractEvidence(manifest, compressedTextPdf([
    "Support attachment for ticket support_009",
    "Customer email: person@example.com",
    "File properties and upload history",
  ].map((line) => `(${line}) Tj`).join("\n")));
  assert.equal(extraction.extractedText?.includes("person@example.com"), true);
  assert.deepEqual(extraction.observations.map(({ evidenceId, systemId, resourceId, state, category }) =>
    [evidenceId, systemId, resourceId, state, category]), [
    ["evidence_pdf", "support_platform", "support_009", "PRESENT", "SUPPORT_ATTACHMENT"],
  ]);

  const subject = resolveSubject("person@example.com", buildSubjects([
    { user_id: "user_1", name: "Person", email: "person@example.com", phone: "", email_hash: "" },
  ], []).values())!;
  const unrelatedSubject = resolveSubject("other@example.com", buildSubjects([
    { user_id: "user_2", name: "Other", email: "other@example.com", phone: "", email_hash: "" },
  ], []).values())!;
  assert.equal(reconstructAt(subject, extraction.observations, "2026-01-03T00:00:00Z").has("support_009"), true);
  assert.equal(reconstructAt(unrelatedSubject, extraction.observations, "2026-01-03T00:00:00Z").size, 0);
});

test("does not classify ordinary PDF business text as a stored resource snapshot", () => {
  const extraction = extractEvidence({
    file_id: "evidence_statement",
    file_path: "evidence/statement.pdf",
    captured_at: "2026-01-02T00:00:00Z",
  }, compressedTextPdf([
    "Customer statement for export_1842",
    "Customer email: person@example.com",
    "Order total paid",
  ].map((line) => `(${line}) Tj`).join("\n")));
  assert.deepEqual(extraction.observations, []);
  assert.ok(extraction.extractedText?.includes("person@example.com"));
});

test("retains extracted PDF identifiers for opaque fallback when no resource can be normalized", () => {
  const extraction = extractEvidence({
    file_id: "evidence_ambiguous_pdf",
    file_path: "evidence/ambiguous.pdf",
    captured_at: "2026-01-02T00:00:00Z",
  }, compressedTextPdf("(person@example.com) Tj"));
  assert.deepEqual(extraction.observations, []);
  assert.ok(extraction.extractedTokens?.includes("person@example.com"));
});

test("normalizes replica profile tables and derives absence only from a complete snapshot", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_snapshot", file_path: "evidence/snapshot.sql", captured_at: "2026-01-03T00:00:00Z" },
    [
      "CREATE TABLE customer_profiles_failover_replica (resource_id TEXT, user_id TEXT, full_name TEXT, email TEXT, phone TEXT, account_status TEXT, updated_at TEXT);",
      `INSERT INTO "customer_profiles_failover_replica" VALUES('account_present','user_2','Other','other@example.com','2','ACTIVE','2026-01-02T00:00:00Z');`,
      "CREATE TABLE customer_profiles_primary (resource_id TEXT, user_id TEXT, full_name TEXT, email TEXT, phone TEXT, account_status TEXT, updated_at TEXT);",
    ].join("\n"),
    [
      { resourceId: "account_present", eventTime: "2026-01-01T00:00:00Z" },
      { resourceId: "account_absent", eventTime: "2026-01-02T00:00:00Z" },
      { resourceId: "account_not_yet_created", eventTime: "2026-01-04T00:00:00Z" },
    ],
  );
  assert.deepEqual(extraction.observations.map(({ resourceId, state, evidenceId }) => [resourceId, state, evidenceId]), [
    ["account_present", "PRESENT", "evidence_snapshot"],
    ["account_absent", "ABSENT", "evidence_snapshot"],
  ]);
});

test("does not infer absence from a schema-only SQL export", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_schema", file_path: "evidence/schema.sql", captured_at: "2026-01-03T00:00:00Z" },
    "CREATE TABLE customer_profiles (resource_id TEXT PRIMARY KEY, email TEXT);",
    [{ resourceId: "account_absent", eventTime: "2026-01-02T00:00:00Z" }],
  );
  assert.deepEqual(extraction.observations, []);
});

test("links a request to one nearby account deletion event without trusting its result", () => {
  const subject = buildSubjects(
    [{ user_id: "user_1", name: "Casey", email: "current@example.com", phone: "1", email_hash: "hash" }],
    [],
  ).get("user_1")!;
  const request = { reported_at: "2026-01-02T00:00:00Z" };
  const activity = [{
    activity_id: "activity_partial",
    event_time: "2026-01-02T00:05:00Z",
    event_type: "DELETE_RECORD",
    target_system: "account_service",
    resource_id: "account_1",
    reported_result: "PARTIAL",
    details: "Generic workflow report",
  }];
  assert.equal(requestResourceLink(request, activity, subject)[0]?.resourceId, "account_1");
  assert.deepEqual(requestResourceLink(request, [...activity, { ...activity[0], activity_id: "activity_ambiguous" }], subject), []);
});

test("accounts for opaque manifest files without inventing observations", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_png", file_path: "evidence/test.png", captured_at: "2026-01-01T00:00:00Z" },
    "binary omitted",
  );
  assert.deepEqual(extraction, {
    fileId: "evidence_png",
    sourcePath: "evidence/test.png",
    capturedAt: "2026-01-01T00:00:00Z",
    inspected: true,
    observations: [],
  });
});

test("accounts for every participant manifest artifact", () => {
  const inputs = readValidatedInputs();
  const evidence = readEvidence(inputs.evidenceFiles, datasetDirectory);
  assert.equal(evidence.length, inputs.evidenceFiles.length);
  assert.deepEqual(new Set(evidence.map((entry) => entry.fileId)), new Set(inputs.evidenceFiles.map((entry) => entry.file_id)));
  assert.ok(evidence.every((entry) => entry.inspected));
});

test("reduces only linked pre-cutoff evidence and keeps a later recreation present", () => {
  const subject = buildSubjects(
    [{ user_id: "user_1", name: "Casey", email: "current@example.com", phone: "1", email_hash: "hash" }],
    [{ user_id: "user_1", old_value: "old@example.com", new_value: "current@example.com" }],
  ).get("user_1")!;
  const observations: EvidenceObservation[] = [
    { evidenceId: "evidence_1", sourcePath: "fixture", eventTime: "2026-01-01T00:00:00Z", systemId: "account", resourceId: "r1", state: "ABSENT", tokens: ["old@example.com"] },
    { evidenceId: "evidence_2", sourcePath: "fixture", eventTime: "2026-01-02T00:00:00Z", systemId: "account", resourceId: "r1", state: "PRESENT", tokens: ["current@example.com"] },
    { evidenceId: "evidence_3", sourcePath: "fixture", eventTime: "2026-01-03T00:00:00Z", systemId: "account", resourceId: "r1", state: "ABSENT", tokens: ["current@example.com"] },
    { evidenceId: "evidence_4", sourcePath: "fixture", eventTime: "2026-01-02T00:00:00Z", systemId: "account", resourceId: "r2", state: "PRESENT", tokens: ["unrelated@example.com"] },
  ];
  const state = reconstructAt(subject, observations, "2026-01-02T12:00:00Z");
  assert.equal(state.get("r1")?.state, "PRESENT");
  assert.equal(state.get("r1")?.evidenceId, "evidence_2");
  assert.equal(state.has("r2"), false);
});

test("excludes evidence captured after the audit cutoff even when its asserted event is earlier", () => {
  const subject = buildSubjects(
    [{ user_id: "user_1", name: "Casey", email: "current@example.com", phone: "1", email_hash: "hash" }],
    [],
  ).get("user_1")!;
  const state = reconstructAt(subject, [{
    evidenceId: "evidence_late",
    sourcePath: "fixture",
    capturedAt: "2026-01-03T00:00:00Z",
    eventTime: "2026-01-01T00:00:00Z",
    systemId: "account_service",
    resourceId: "account_1",
    state: "ABSENT",
    tokens: ["current@example.com"],
  }], "2026-01-02T00:00:00Z");
  assert.equal(state.size, 0);
});

test("maps successful sync and restore activity to present observations", () => {
  const observations = activityObservations([
    { activity_id: "activity_1", event_time: "2026-01-01T00:00:00Z", event_type: "DELETE_RECORD", reported_result: "SUCCESS", target_system: "account", resource_id: "r1", details: "old@example.com" },
    { activity_id: "activity_2", event_time: "2026-01-02T00:00:00Z", event_type: "SYNC_RECORD", reported_result: "SUCCESS", target_system: "account", resource_id: "r1", details: "old@example.com" },
    { activity_id: "activity_3", event_time: "2026-01-03T00:00:00Z", event_type: "RESTORE_BACKUP", reported_result: "SUCCESS", target_system: "account", resource_id: "r1", details: "old@example.com" },
  ]);
  assert.deepEqual(observations.map((item) => item.state), ["ABSENT", "PRESENT", "PRESENT"]);
  assert.deepEqual(observations.map((item) => item.category), [undefined, undefined, "BACKUP_ARCHIVE"]);
});

test("uses grounded resource links to associate otherwise identifier-free evidence", () => {
  const subject = buildSubjects(
    [{ user_id: "user_1", name: "Casey", email: "current@example.com", phone: "1", email_hash: "hash" }],
    [],
  ).get("user_1")!;
  const observations: EvidenceObservation[] = [
    { evidenceId: "activity_1", sourcePath: "system_activity.csv", eventTime: "2026-01-01T00:00:00Z", systemId: "catalog", resourceId: "account_1", state: "PRESENT", tokens: ["current@example.com"], kind: "IDENTITY_LINK" },
    { evidenceId: "evidence_1", sourcePath: "fixture", eventTime: "2026-01-01T01:00:00Z", systemId: "account_service", resourceId: "account_1", state: "PRESENT", tokens: [] },
  ];
  assert.equal(reconstructAt(subject, observations, "2026-01-02T00:00:00Z").get("account_1")?.evidenceId, "evidence_1");
});

test("retains visible resource labels and categories from identity-link evidence", () => {
  const links = activityObservations([{
    activity_id: "activity_1",
    event_time: "2026-01-01T00:05:00Z",
    event_type: "LINK_RESOURCE_IDENTITY",
    target_system: "object_storage",
    resource_id: "object_19",
    details: "Attachment catalog confirmed object_19 (delivery_confirmation_19.pdf) belongs only to person@example.com and user_1",
  }]);
  assert.deepEqual(links[0].visibleResourceLabels, ["object_19", "delivery_confirmation_19.pdf"]);
  assert.equal(links[0].category, "SUPPORT_ATTACHMENT");
});

test("normalizes nested service responses and trace-correlated lookup results", () => {
  const manifest = { file_id: "evidence_43", file_path: "evidence/records/export.json", captured_at: "2026-01-01T00:00:00Z" };
  const json = extractEvidence(manifest, JSON.stringify({
    service_exports: {
      account_service: {
        profile_lookups: [{ observed_at: "2026-01-01T00:00:00Z", resource_id: "account_43", status_code: 200, profile: { email: "case43@example.com" } }],
      },
    },
  }));
  const log = extractEvidence(
    { ...manifest, file_path: "evidence/logs/trace.log" },
    [
      '2026-01-01T00:00:00Z service=account_service trace_id=t1 event=profile_lookup_started lookup_key="case34@example.com"',
      '2026-01-01T00:00:01Z service=account_service trace_id=t1 resource_id=account_34 event=profile_lookup_completed rows=0 http_status=404',
    ].join("\n"),
  );
  assert.equal(json.observations[0].evidenceId, "evidence_43");
  assert.equal(json.observations[0].systemId, "account_service");
  assert.equal(json.observations[0].resourceId, "account_43");
  assert.equal(json.observations[0].state, "PRESENT");
  assert.ok(json.observations[0].tokens.includes("case43@example.com"));
  assert.equal(log.observations[0].state, "ABSENT");
  assert.ok(log.observations[0].tokens.includes("case34@example.com"));
});

test("excludes case_534 observations captured after its audit cutoff", () => {
  const inputs = readValidatedInputs();
  const request = inputs.deletionRequests.find((item) => item.case_id === "case_534")!;
  const subject = resolveSubject(request.email, buildSubjects(inputs.userIdentities, inputs.userAuditLog).values())!;
  const observations = readEvidence(inputs.evidenceFiles, datasetDirectory).flatMap((entry) => entry.observations);
  assert.equal(reconstructAt(subject, observations, request.audit_at).size, 0);
});

test("normalizes case_47 completed support reads and index hits only when explicit", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_94", file_path: "evidence/logs/readback.log", captured_at: "2026-09-26T10:00:00Z" },
    [
      '2026-09-26T08:49:37Z service=support_platform trace_id=t1 event=support_ticket_read_started resource_id=support_5742 lookup_key=zofia@example.com',
      '2026-09-26T08:49:37Z service=support_platform trace_id=t1 event=support_ticket_read_completed resource_id=support_5742 requester_email=zofia@example.com',
      '2026-09-26T09:41:03Z service=search_service trace_id=t2 event=index_query_completed resource_id=search_4324 result=hit email=zofia@example.com',
    ].join("\n"),
  );
  assert.deepEqual(extraction.observations.map((item) => [item.resourceId, item.state, item.category]), [
    ["support_5742", "PRESENT", "SUPPORT_MESSAGE"],
    ["search_4324", "PRESENT", "SEARCH_INDEX_ENTRY"],
  ]);
});

test("normalizes application traces and readbacks with explicit terminal evidence", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_trace", file_path: "evidence/logs/application.log", captured_at: "2026-09-26T10:00:00Z" },
    [
      '2026-09-26T08:49:37Z [INFO] [search_service] [trace-1] index_query_completed: resource_id="search_1" result="hit" correlation_key="zofia@example.com"',
      '2026-09-26T08:50:37Z service=backup_service trace_id=trace-2 event=restore_policy_read_completed resource_id=backup_1 archive_present=true restore_allowed=true customer_email=zofia@example.com',
      '2026-09-26T08:51:37Z service=export_service trace_id=trace-3 event=export_metadata_read_completed resource_id=export_1 available=true owner_email=zofia@example.com',
    ].join("\n"),
  );
  assert.deepEqual(extraction.observations.map((item) => [item.resourceId, item.state, item.category]), [
    ["search_1", "PRESENT", "SEARCH_INDEX_ENTRY"],
    ["backup_1", "ACTIVE", "BACKUP_ARCHIVE"],
    ["export_1", "PRESENT", "USER_EXPORT"],
  ]);
});

test("normalizes JSON-lines, syslog, and event-pipe log formats", () => {
  const jsonLines = extractEvidence(
    { file_id: "evidence_json_lines", file_path: "evidence/logs/events.log", captured_at: "2026-04-19T07:00:00Z" },
    [
      '2026-04-19T06:51:21Z {"severity":"INFO","service":"search_service","resource_id":"search_9365","event":"index_query_completed","result":"hit","correlation_key":"person@example.com"}',
      '2026-04-19T06:51:41Z {"severity":"WARN","service":"analytics_platform","resource_id":"analytics_547","event":"analytics_identity_scan","matched_value":"person@example.com","direct_identifiers":"1"}',
    ].join("\n"),
  );
  assert.deepEqual(jsonLines.observations.map((item) => [item.systemId, item.resourceId, item.state, item.category]), [
    ["search_service", "search_9365", "PRESENT", "SEARCH_INDEX_ENTRY"],
    ["analytics_platform", "analytics_547", "PRESENT", undefined],
  ]);
  assert.ok(jsonLines.observations.every((item) => item.tokens.includes("person@example.com")));

  const syslog = extractEvidence(
    { file_id: "evidence_syslog", file_path: "evidence/logs/events.log", captured_at: "2026-03-25T09:00:00Z" },
    '2026-03-25T08:55:11Z <12>1 node-8 analytics_platform tr-1 - - level=WARN resource_id="analytics_4523" event="analytics_identity_scan" matched_value="person@example.com" direct_identifiers="1"',
  );
  assert.deepEqual(syslog.observations.map((item) => [item.systemId, item.resourceId, item.state]), [
    ["analytics_platform", "analytics_4523", "PRESENT"],
  ]);

  const eventPipe = extractEvidence(
    { file_id: "evidence_event_pipe", file_path: "evidence/logs/events.log", captured_at: "2026-02-03T06:00:00Z" },
    '2026-02-03T05:51:30Z | DEBUG | security_service | tr-1 | audit_record_read_completed | instance="security-1" resource_id="audit_record_4027" rows="1" subject_ref="user_1"',
  );
  assert.deepEqual(eventPipe.observations.map((item) => [item.systemId, item.resourceId, item.state, item.category]), [
    ["security_service", "audit_record_4027", "PRESENT", "SECURITY_AUDIT_LOG"],
  ]);
});

test("normalizes case_94 nested search hits and support records only when populated", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_89", file_path: "evidence/records/export.json", captured_at: "2026-09-01T05:33:16Z" },
    JSON.stringify({
      service_exports: {
        search_service: {
          queries: [{ observed_at: "2026-09-01T02:59:37Z", resource_id: "search_7631", hits: { total: 1, documents: [{ email: "case94@example.com" }] } }],
        },
        support_platform: {
          tickets: [{ observed_at: "2026-09-01T03:57:56Z", resource_id: "support_7691", requester_email: "case94@example.com" }],
        },
      },
    }),
  );
  assert.deepEqual(extraction.observations.map((item) => [item.resourceId, item.state, item.category]), [
    ["search_7631", "PRESENT", "SEARCH_INDEX_ENTRY"],
    ["support_7691", "PRESENT", "SUPPORT_MESSAGE"],
  ]);
});

test("normalizes explicitly enabled nested connectors as active data flows", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_80", file_path: "evidence/records/export.json", captured_at: "2026-06-28T06:25:56Z" },
    JSON.stringify({
      service_exports: {
        integration_service: {
          connectors: [{
            observed_at: "2026-06-28T06:17:24Z",
            resource_id: "data_flow_1140",
            customer_email: "neel.singh@outlook.com",
            enabled: true,
          }],
        },
      },
    }),
  );
  assert.deepEqual(extraction.observations.map((item) => [item.resourceId, item.state, item.category]), [
    ["data_flow_1140", "ACTIVE", "DATA_FLOW"],
  ]);
});

test("normalizes security audit exports without linking sibling records to the subject", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_export", file_path: "evidence/records/export.json", captured_at: "2026-01-01T00:00:00Z" },
    JSON.stringify({
      service_exports: {
        security_service: {
          audit_records: [{
            event_code: "ACCOUNT_DELETION_RECORDED",
            observed_at: "2026-01-01T00:00:00Z",
            resource_id: "audit_1",
            subject_reference: "user_1",
          }],
        },
        analytics_platform: {
          profiles: [{
            customer_reference: null,
            email: null,
            email_hash: null,
            phone: null,
            observed_at: "2026-01-01T00:00:00Z",
            resource_id: "analytics_2",
          }],
        },
      },
    }),
  );
  const subject = buildSubjects(
    [{ user_id: "user_1", name: "Casey", email: "casey@example.com", phone: "1", email_hash: "hash" }],
    [],
  ).get("user_1")!;
  const state = reconstructAt(subject, extraction.observations, "2026-01-02T00:00:00Z");
  assert.deepEqual(extraction.observations.map(({ resourceId, systemId, category, state: observedState }) =>
    [resourceId, systemId, category, observedState]), [
    ["audit_1", "security_service", "SECURITY_AUDIT_LOG", "PRESENT"],
    ["analytics_2", "analytics_platform", "ANALYTICS_PROFILE", "ANONYMIZED"],
  ]);
  assert.deepEqual([...state.keys()], ["audit_1"]);
});

test("normalizes snapshot tombstones and structurally present retained records", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_snapshot", file_path: "evidence/records/snapshot.json", captured_at: "2026-01-01T00:00:00Z" },
    JSON.stringify({
      exported_at: "2026-01-01T00:00:00Z",
      snapshots: [
        {
          captured_at: "2026-01-01T00:00:00Z",
          data_store: "identity_service",
          collection: "deleted_customer_references",
          records: [
            { resource_id: "tombstone_redacted", subject_reference: "user_1", name: null, email: null, phone: null, email_hash: null, account_status: "DELETED" },
            { resource_id: "tombstone_exposed", subject_reference: "user_2", name: "Jordan", email: "jordan@example.com", phone: null, email_hash: null, account_status: "DELETED", status: "REDACTED" },
          ],
        },
        {
          captured_at: "2026-01-01T00:00:00Z",
          data_store: "analytics_platform",
          collection: "customer_analytics_reports",
          records: [
            { resource_id: "analytics_exposed", user_id: "user_2", email: "jordan@example.com", phone: null, email_hash: null, status: "ANONYMIZED" },
          ],
        },
        {
          captured_at: "2026-01-01T00:00:00Z",
          data_store: "security_service",
          collection: "security_audit_events",
          records: [{ resource_id: "audit_1", subject_reference: "user_1", event_name: "account_deletion_reviewed" }],
        },
        {
          captured_at: "2026-01-01T00:00:00Z",
          data_store: "account_service",
          collection: "customer_profiles",
          records: [],
        },
      ],
    }),
  );
  assert.deepEqual(extraction.observations.map(({ resourceId, systemId, category, state }) =>
    [resourceId, systemId, category, state]), [
    ["tombstone_redacted", "identity_service", "ACCOUNT_TOMBSTONE", "REDACTED"],
    ["tombstone_exposed", "identity_service", "ACCOUNT_TOMBSTONE", "PRESENT"],
    ["analytics_exposed", "analytics_platform", "ANALYTICS_PROFILE", "PRESENT"],
    ["audit_1", "security_service", "SECURITY_AUDIT_LOG", "PRESENT"],
  ]);
  assert.ok(extraction.observations[0].tokens.includes("user_1"));
  assert.equal(extraction.observations.length, 4);
});

test("derives connector and backup state only from explicit snapshot controls", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_controls", file_path: "evidence/records/controls.json", captured_at: "2026-01-01T00:00:00Z" },
    JSON.stringify({
      snapshots: [
        {
          captured_at: "2026-01-01T00:00:00Z",
          data_store: "integration_service",
          collection: "connector_configurations",
          records: [
            { resource_id: "flow_active", subject_selector: "user_1", enabled: true },
            { resource_id: "flow_disabled", subject_selector: "user_1", enabled: false },
          ],
        },
        {
          captured_at: "2026-01-01T00:00:00Z",
          data_store: "backup_service",
          collection: "backup_catalog",
          records: [
            { resource_id: "backup_blocked", subject_reference: "user_1", archive_path: "archive.tar", restore_allowed: false },
            { resource_id: "backup_active", subject_reference: "user_1", archive_path: "archive.tar", restore_allowed: true },
            { resource_id: "backup_presence_only", subject_reference: "user_1", archive_path: "archive.tar" },
          ],
        },
      ],
    }),
  );
  assert.deepEqual(extraction.observations.map(({ resourceId, category, state }) => [resourceId, category, state]), [
    ["flow_active", "DATA_FLOW", "ACTIVE"],
    ["flow_disabled", "DATA_FLOW", "DISABLED"],
    ["backup_blocked", "BACKUP_ARCHIVE", "BLOCKED"],
    ["backup_active", "BACKUP_ARCHIVE", "ACTIVE"],
    ["backup_presence_only", "BACKUP_ARCHIVE", "PRESENT"],
  ]);
});

test("links null-identifier snapshots through all nearby matching operations", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_analytics", file_path: "evidence/records/analytics.json", captured_at: "2026-01-02T00:00:00Z" },
    JSON.stringify({
      captured_at: "2026-01-02T00:00:00Z",
      source: "analytics_identity_store",
      collection: "customer_analytics_reports",
      records: [{
        resource_id: "analytics_1",
        user_id: null,
        email: null,
        phone: null,
        email_hash: null,
        metrics: { sessions: 3 },
      }],
    }),
  );
  const subject = buildSubjects(
    [{ user_id: "user_1", name: "Casey", email: "casey@example.com", phone: "1", email_hash: "hash" }],
    [],
  ).get("user_1")!;
  const request = { reported_at: "2026-01-02T00:00:00Z" };
  const activity = [{
    activity_id: "activity_1",
    event_time: "2026-01-01T23:55:00Z",
    event_type: "ANONYMIZE_RECORD",
    target_system: "analytics_platform",
    resource_id: "analytics_1",
    reported_result: "FAILED",
    details: "Operation report is not state proof",
  }];
  assert.equal(extraction.observations[0].state, "ANONYMIZED");
  assert.equal(reconstructAt(subject, extraction.observations, "2026-01-03T00:00:00Z").size, 0);
  const links = requestResourceLink(request, activity, subject);
  assert.equal(links[0]?.kind, "IDENTITY_LINK");
  assert.equal(links[0]?.resourceId, "analytics_1");
  assert.equal(reconstructAt(subject, [...extraction.observations, ...links], "2026-01-03T00:00:00Z")
    .get("analytics_1")?.state, "ANONYMIZED");
  assert.deepEqual(requestResourceLink(request, [...activity, { ...activity[0], activity_id: "activity_2", resource_id: "analytics_2" }], subject)
    .map((link) => link.resourceId), ["analytics_1", "analytics_2"]);
});

test("normalizes search document SQL inventory rows", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_search", file_path: "evidence/search.sql", captured_at: "2026-01-02T00:00:00Z" },
    [
      "CREATE TABLE search_documents_primary (resource_id TEXT, display_name TEXT, email TEXT, source_resource_id TEXT, indexed_at TEXT);",
      `INSERT INTO "search_documents_primary" VALUES('search_1','Casey','casey@example.com','account_1','2026-01-01T00:00:00Z');`,
    ].join("\n"),
  );
  assert.deepEqual(extraction.observations.map(({ systemId, category, resourceId, state, tokens }) => [
    systemId,
    category,
    resourceId,
    state,
    tokens.includes("casey@example.com"),
  ]), [["search_service", "SEARCH_INDEX_ENTRY", "search_1", "PRESENT", true]]);
});

test("normalizes export-job snapshots and explicitly safe service-export states", () => {
  const exportJobs = extractEvidence(
    { file_id: "evidence_jobs", file_path: "evidence/exports.json", captured_at: "2026-01-02T00:00:00Z" },
    JSON.stringify({
      captured_at: "2026-01-02T00:00:00Z",
      collection: "customer_export_jobs",
      records: [{
        resource_id: "export_1",
        owner_email: "casey@example.com",
        download_available: true,
      }],
    }),
  );
  assert.deepEqual(exportJobs.observations.map(({ systemId, category, resourceId, state }) =>
    [systemId, category, resourceId, state]), [
    ["export_service", "USER_EXPORT", "export_1", "PRESENT"],
  ]);

  const services = extractEvidence(
    { file_id: "evidence_services", file_path: "evidence/services.json", captured_at: "2026-01-02T00:00:00Z" },
    JSON.stringify({
      service_exports: {
        support_platform: { tickets: [{
          observed_at: "2026-01-01T00:00:00Z",
          resource_id: "support_1",
          customer_reference: "user_1",
          message_excerpt: "Order delivery question",
          requester_email: null,
          requester_name: null,
          requester_phone: null,
        }] },
        integration_service: { connectors: [{
          observed_at: "2026-01-01T00:00:00Z",
          resource_id: "flow_1",
          customer_reference: "user_1",
          enabled: false,
        }] },
        backup_service: { restore_entries: [{
          observed_at: "2026-01-01T00:00:00Z",
          resource_id: "backup_1",
          customer_reference: "user_1",
          restore_allowed: false,
        }, {
          observed_at: "2026-01-01T00:00:00Z",
          resource_id: "backup_2",
          customer_reference: "user_1",
          restore_allowed: true,
        }] },
      },
    }),
  );
  const subject = buildSubjects(
    [{ user_id: "user_1", name: "Casey", email: "casey@example.com", phone: "1", email_hash: "hash" }],
    [],
  ).get("user_1")!;
  const state = reconstructAt(subject, services.observations, "2026-01-02T00:00:00Z");
  assert.deepEqual([...state.values()].map(({ resourceId, category, state: currentState }) =>
    [resourceId, category, currentState]), [
    ["support_1", "SUPPORT_MESSAGE", "REDACTED"],
    ["flow_1", "DATA_FLOW", "DISABLED"],
    ["backup_1", "BACKUP_ARCHIVE", "BLOCKED"],
    ["backup_2", "BACKUP_ARCHIVE", "ACTIVE"],
  ]);
});

test("normalizes linked support, analytics, connector, and restore log events", () => {
  const extraction = extractEvidence(
    { file_id: "evidence_events", file_path: "evidence/logs/events.log", captured_at: "2026-01-02T00:00:00Z" },
    [
      '2026-01-01T00:00:00Z service=support_platform trace_id=s1 event=contact_query_started lookup_key=casey@example.com',
      '2026-01-01T00:00:01Z service=support_platform trace_id=s1 event=contact_query_completed resource_id=support_1 rows=1',
      '2026-01-01T00:00:02Z service=analytics_platform trace_id=a1 event=contact_lookup_completed resource_id=analytics_1 rows=1 correlation_key=hash',
      '2026-01-01T00:00:03Z service=integration_service trace_id=c1 event=connector_config_read_completed resource_id=flow_1 enabled=false subject_key=casey@example.com',
      '2026-01-01T00:00:04Z service=backup_service trace_id=b1 event=restore_candidate_evaluated resource_id=backup_1 eligible=true deletion_block=false subject_key=casey@example.com',
    ].join("\n"),
  );
  assert.deepEqual(extraction.observations.map(({ systemId, category, resourceId, state }) =>
    [systemId, category, resourceId, state]), [
    ["support_platform", "SUPPORT_MESSAGE", "support_1", "PRESENT"],
    ["analytics_platform", "ANALYTICS_PROFILE", "analytics_1", "PRESENT"],
    ["integration_service", "DATA_FLOW", "flow_1", "DISABLED"],
    ["backup_service", "BACKUP_ARCHIVE", "backup_1", "ACTIVE"],
  ]);
  assert.ok(extraction.observations[0].tokens.includes("casey@example.com"));
  assert.ok(extraction.observations[1].tokens.includes("hash"));
});
