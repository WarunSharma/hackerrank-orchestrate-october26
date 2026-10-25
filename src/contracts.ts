import { readFileSync } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { datasetDirectory } from "./config.js";

const deletionStatuses = ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"] as const;
const reportedStatuses = ["COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"] as const;
const phases = ["FINDING", "REMEDIATION", "VERIFICATION"] as const;

const allowedStepPairs = {
  FINDING: {
    REPORT_REMAINING_RECORD: "PRESENT",
    REPORT_EXPOSED_PII: "PRESENT",
    REPORT_ACTIVE_DATA_FLOW: "ACTIVE",
    REPORT_RESTORE_RISK: "ACTIVE",
  },
  REMEDIATION: {
    DISABLE_DATA_FLOW: "DISABLED",
    BLOCK_RESTORE: "BLOCKED",
    DELETE_RECORD: "ABSENT",
    REDACT_RECORD: "REDACTED",
    ANONYMIZE_RECORD: "ANONYMIZED",
  },
  VERIFICATION: {
    VERIFY_RECORD_ABSENT: "ABSENT",
    VERIFY_RECORD_PRESENT: "PRESENT",
    VERIFY_RECORD_REDACTED: "REDACTED",
    VERIFY_RECORD_ANONYMIZED: "ANONYMIZED",
    VERIFY_DATA_FLOW_DISABLED: "DISABLED",
    VERIFY_RESTORE_BLOCKED: "BLOCKED",
  },
} as const;

export const inputFileHeaders = {
  deletion_requests: ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"],
  sample_deletion_requests: ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"],
  user_identities: ["user_id", "name", "email", "phone", "email_hash", "updated_at"],
  user_audit_log: ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"],
  system_activity: ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"],
  deletion_rules: ["rule_id", "data_category", "condition", "required_action"],
  evidence_files: ["file_id", "file_path", "origin", "captured_at"],
} as const;

type InputFileName = keyof typeof inputFileHeaders;
type CsvRow = Record<string, string>;

function required(value: string | undefined, field: string, rowNumber: number): string {
  if (!value?.trim()) throw new Error(`Missing required value for ${field} in row ${rowNumber}`);
  return value;
}

function validateEmail(value: string, field: string, rowNumber: number): void {
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
    throw new Error(`Invalid email for ${field} in row ${rowNumber}: ${value}`);
  }
}

export function validateTimestamp(value: string, field: string): void {
  const isoUtc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
  if (!isoUtc.test(value) || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value.replace("Z", ".000Z")) {
    throw new Error(`Invalid timestamp for ${field}: ${value}`);
  }
}

export function parseCsv(text: string, requiredHeaders: readonly string[]): CsvRow[] {
  const rows: string[][] = [[]];
  let value = "";
  let quoted = false;

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === "\"") {
        if (text[index + 1] === "\"") {
          value += "\"";
          index += 1;
        } else {
          quoted = false;
        }
      } else {
        value += character;
      }
      continue;
    }

    if (character === "\"") {
      if (value) throw new Error("Unexpected quote in CSV field");
      quoted = true;
    } else if (character === ",") {
      rows.at(-1)?.push(value);
      value = "";
    } else if (character === "\n") {
      rows.at(-1)?.push(value);
      rows.push([]);
      value = "";
    } else if (character !== "\r") {
      value += character;
    }
  }

  if (quoted) throw new Error("Unterminated quoted CSV field");
  if (value || rows.at(-1)?.length) rows.at(-1)?.push(value);
  if (rows.length === 0 || rows[0].length === 0) throw new Error("CSV is missing a header row");

  const headers = rows.shift()!.map((header, index) => index === 0 ? header.replace(/^\uFEFF/, "") : header);
  const uniqueHeaders = new Set(headers);
  if (uniqueHeaders.size !== headers.length) throw new Error("CSV contains duplicate headers");
  for (const header of requiredHeaders) {
    if (!headers.includes(header)) throw new Error(`Missing required header: ${header}`);
  }

  return rows.filter((row) => row.length > 0 && (row.length > 1 || row[0] !== "")).map((row, index) => {
    const rowNumber = index + 2;
    if (row.length !== headers.length) {
      throw new Error(`Expected ${headers.length} fields in row ${rowNumber}, received ${row.length}`);
    }
    return Object.fromEntries(headers.map((header, column) => [header, row[column]]));
  });
}

export function validateRequest(row: CsvRow, rowNumber = 2): void {
  for (const field of inputFileHeaders.deletion_requests) required(row[field], field, rowNumber);
  validateEmail(row.email, "email", rowNumber);
  for (const field of ["requested_at", "reported_at", "audit_at"]) validateTimestamp(row[field], field);
  if (!reportedStatuses.includes(row.reported_status as (typeof reportedStatuses)[number])) {
    throw new Error(`Invalid reported_status: ${row.reported_status}`);
  }
}

function validateRows(fileName: InputFileName, rows: CsvRow[]): void {
  rows.forEach((row, index) => {
    const rowNumber = index + 2;
    for (const field of inputFileHeaders[fileName]) required(row[field], field, rowNumber);

    switch (fileName) {
      case "deletion_requests":
      case "sample_deletion_requests":
        validateRequest(row, rowNumber);
        break;
      case "user_identities":
        validateEmail(row.email, "email", rowNumber);
        validateTimestamp(row.updated_at, "updated_at");
        break;
      case "user_audit_log":
        validateTimestamp(row.event_time, "event_time");
        break;
      case "system_activity":
        validateTimestamp(row.event_time, "event_time");
        break;
      case "deletion_rules":
        if (!["DELETE", "REDACT", "ANONYMIZE", "RETAIN"].includes(row.required_action)) {
          throw new Error(`Invalid required_action in row ${rowNumber}: ${row.required_action}`);
        }
        break;
      case "evidence_files":
        validateTimestamp(row.captured_at, "captured_at");
        break;
    }
  });
}

export interface ValidatedInputs {
  deletionRequests: CsvRow[];
  sampleDeletionRequests: CsvRow[];
  userIdentities: CsvRow[];
  userAuditLog: CsvRow[];
  systemActivity: CsvRow[];
  deletionRules: CsvRow[];
  evidenceFiles: CsvRow[];
}

export function readValidatedInputs(directory = datasetDirectory): ValidatedInputs {
  const read = (fileName: InputFileName): CsvRow[] => {
    const rows = parseCsv(readFileSync(path.join(directory, `${fileName}.csv`), "utf8"), inputFileHeaders[fileName]);
    validateRows(fileName, rows);
    return rows;
  };

  return {
    deletionRequests: read("deletion_requests"),
    sampleDeletionRequests: read("sample_deletion_requests"),
    userIdentities: read("user_identities"),
    userAuditLog: read("user_audit_log"),
    systemActivity: read("system_activity"),
    deletionRules: read("deletion_rules"),
    evidenceFiles: read("evidence_files"),
  };
}

export const outputStepSchema = z.object({
  step_no: z.number().int().positive(),
  phase: z.enum(phases),
  system_id: z.string().min(1),
  resource_id: z.string().min(1),
  operation: z.string().min(1),
  state: z.string().min(1),
  evidence_id: z.string(),
}).strict().superRefine((step, ctx) => {
  const expectedState = allowedStepPairs[step.phase][step.operation as never];
  if (expectedState === undefined || step.state !== expectedState) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: `Invalid operation/state pair for ${step.phase}` });
  }
});

export const outputRowSchema = z.object({
  case_id: z.string().min(1),
  deletion_status: z.enum(deletionStatuses),
  steps_json: z.array(outputStepSchema),
}).strict().superRefine((row, ctx) => {
  if (row.deletion_status === "NOT_APPLICABLE" && row.steps_json.length !== 0) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "NOT_APPLICABLE requires []" });
  }

  row.steps_json.forEach((step, index) => {
    if (step.step_no !== index + 1) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "step numbers must be consecutive" });
    }
    if (row.deletion_status === "COMPLETE" && (step.phase !== "VERIFICATION" || !step.evidence_id)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "COMPLETE requires evidence-backed verification steps only" });
    }
    if (row.deletion_status === "INCOMPLETE" && ((step.phase === "FINDING" && !step.evidence_id) || (step.phase !== "FINDING" && step.evidence_id))) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "INCOMPLETE evidence IDs must be present only for findings" });
    }
  });
});

export function validateOutputRows(rows: unknown[], evidenceIds?: ReadonlySet<string>): void {
  rows.forEach((row, index) => {
    const parsed = outputRowSchema.parse(row, { path: [index] });
    if (evidenceIds) {
      for (const [stepIndex, step] of parsed.steps_json.entries()) {
        if (step.evidence_id && !evidenceIds.has(step.evidence_id)) {
          throw new Error(`Invalid evidence_id in row ${index + 1}, step ${stepIndex + 1}: ${step.evidence_id}`);
        }
      }
    }
  });
}
