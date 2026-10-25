import { readFileSync } from "node:fs";
import path from "node:path";
import { inflateSync } from "node:zlib";
import type { ValidatedInputs } from "./contracts.js";

export type Authorization = "AUTHORIZED" | "NOT_AUTHORIZED";
export type ResourceState = "PRESENT" | "ABSENT" | "ACTIVE" | "DISABLED" | "BLOCKED" | "REDACTED" | "ANONYMIZED";
type CsvRow = Record<string, string>;

export interface Subject {
  userId: string;
  aliases: ReadonlySet<string>;
}

export interface EvidenceObservation {
  evidenceId: string;
  sourcePath: string;
  capturedAt?: string;
  eventTime?: string;
  observedAt?: string;
  systemId: string;
  resourceId: string;
  state: ResourceState;
  tokens: string[];
  category?: string;
  visibleResourceLabels?: string[];
  kind?: "IDENTITY_LINK";
}

export interface EvidenceExtraction {
  fileId: string;
  sourcePath: string;
  capturedAt: string;
  inspected: true;
  observations: EvidenceObservation[];
  extractedText?: string;
  extractedTokens?: string[];
  needsOpaqueReview?: boolean;
}

export interface SnapshotResourceCandidate {
  resourceId: string;
  eventTime: string;
}

function normalize(value: string): string {
  return value.trim().toLocaleLowerCase();
}

const deletionRequestPatterns = [
  /\b(?:delete|deleting|deleted|deletion|erase|erased|erasure|remove|removed|removal|close(?:d)? (?:my )?account)\b/i,
  /\b(?:close|shut down)\s+(?:(?:my|the|this)\s+)?account(?:\s+(?:permanently|for good|completely))?\b/i,
  /\b(?:eliminar|eliminación|eliminacion|elimine|eliminen|borrar|borrado)\b/i,
  /\b(?:supprimer|suppression|supprimé(?:e)?|effacer|effacement)\b/i,
  /\b(?:exclus[aã]o|excluir)\b/i,
  /削除/,
];

const deletionVerificationPatterns = [
  /\b(?:verify|check|confirm)\b[\s\S]{0,100}\b(?:delete|deletion|deleted|erase|erasure|remove|removal|close|closed|closure|(?:account|profile|data)\s+(?:is\s+)?gone|remaining\s+records?\s+cannot\s+identify)\b/i,
  /\b(?:delete|deletion|deleted|erase|erasure|remove|removal|close|closed|closure)\b[\s\S]{0,100}\b(?:status|already|previously|completed|complete|finished|verify|confirm)\b/i,
];

const nonDeletionPatterns = [
  /\b(?:not|never)\s+(?:a\s+)?(?:request|asking)\s+(?:(?:for|to)\s+)?(?:the\s+)?(?:delete|deletion|erase|erasure|remove|removal|close|closure)\b/i,
  /\b(?:do\s+not|don't|does\s+not|doesn't|never)\b[\s\S]{0,60}\b(?:delete|erase|remove|close|shut\s+down)\b/i,
  /\b(?:remove|unsubscribe|opt[\s-]?out|stop)\b[\s\S]{0,40}\b(?:marketing|promotional|mailing|email|emails|lists?)\b[\s\S]{0,20}\bonly\b/i,
];

function isDeletionText(text: string): boolean {
  if (nonDeletionPatterns.some((pattern) => pattern.test(text))) return false;
  if (deletionVerificationPatterns.some((pattern) => pattern.test(text))) return true;
  const matchesDeletion = deletionRequestPatterns.some((pattern) => pattern.test(text));
  return matchesDeletion;
}

export function classifyAuthorization(requestText: string): Authorization {
  return isDeletionText(requestText) ? "AUTHORIZED" : "NOT_AUTHORIZED";
}

export function buildSubjects(identities: CsvRow[], auditLog: CsvRow[]): Map<string, Subject> {
  const subjects = new Map<string, Subject>();
  const aliasesByUser = new Map<string, Set<string>>();
  const add = (userId: string, value: string): void => {
    if (!value?.trim()) return;
    const aliases = aliasesByUser.get(userId) ?? new Set<string>();
    aliases.add(normalize(value));
    aliasesByUser.set(userId, aliases);
  };

  for (const identity of identities) {
    for (const value of [identity.user_id, identity.name, identity.email, identity.phone, identity.email_hash]) add(identity.user_id, value);
  }
  for (const change of auditLog) {
    add(change.user_id, change.old_value);
    add(change.user_id, change.new_value);
  }
  for (const [userId, aliases] of aliasesByUser) subjects.set(userId, { userId, aliases });
  return subjects;
}

export function resolveSubject(email: string, subjects: Iterable<Subject>): Subject | undefined {
  const alias = normalize(email);
  return [...subjects].find((subject) => subject.aliases.has(alias));
}

function stateFromResult(value: string | undefined): ResourceState | undefined {
  switch (value?.toUpperCase()) {
    case "FOUND":
    case "IDENTIFIABLE":
    case "PRESENT":
    case "SUCCESS":
      return "PRESENT";
    case "NOT_FOUND":
    case "ABSENT":
      return "ABSENT";
    case "ACTIVE":
      return "ACTIVE";
    case "DISABLED":
      return "DISABLED";
    case "BLOCKED":
      return "BLOCKED";
    case "REDACTED":
      return "REDACTED";
    case "ANONYMIZED":
      return "ANONYMIZED";
    default:
      return undefined;
  }
}

function activityState(eventType: string, result: string): ResourceState | undefined {
  if (result !== "SUCCESS") return undefined;
  if (eventType === "DELETE_RECORD") return "ABSENT";
  if (eventType === "SYNC_RECORD" || eventType === "RESTORE_BACKUP" || eventType === "INDEX_RECORD") return "PRESENT";
  if (eventType === "DISABLE_DATA_FLOW") return "DISABLED";
  if (eventType === "BLOCK_RESTORE") return "BLOCKED";
  return undefined;
}

function flattenStrings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(flattenStrings);
  if (value && typeof value === "object") return Object.values(value).flatMap(flattenStrings);
  return [];
}

function decodeAscii85(bytes: Buffer): Buffer | undefined {
  const encoded = bytes.toString("ascii").replace(/\s/g, "").replace(/^<~/, "").replace(/~>[\s\S]*$/, "");
  const output: number[] = [];
  let digits: number[] = [];
  const appendGroup = (group: number[], length: number): boolean => {
    const value = group.reduce((accumulator, digit) => accumulator * 85 + digit, 0);
    if (value > 0xffffffff) return false;
    const decoded = [
      Math.floor(value / 0x1000000) & 0xff,
      Math.floor(value / 0x10000) & 0xff,
      Math.floor(value / 0x100) & 0xff,
      value & 0xff,
    ];
    output.push(...decoded.slice(0, length));
    return true;
  };

  for (const character of encoded) {
    if (character === "z") {
      if (digits.length > 0) return undefined;
      output.push(0, 0, 0, 0);
      continue;
    }
    const digit = character.charCodeAt(0) - 33;
    if (digit < 0 || digit > 84) return undefined;
    digits.push(digit);
    if (digits.length === 5) {
      if (!appendGroup(digits, 4)) return undefined;
      digits = [];
    }
  }
  if (digits.length === 1) return undefined;
  if (digits.length > 1) {
    const length = digits.length - 1;
    while (digits.length < 5) digits.push(84);
    if (!appendGroup(digits, length)) return undefined;
  }
  return Buffer.from(output);
}

function decodePdfStream(bytes: Buffer, filters: string[]): Buffer | undefined {
  let decoded = bytes;
  for (const filter of filters) {
    if (filter === "ASCII85Decode" || filter === "A85") {
      const result = decodeAscii85(decoded);
      if (!result) return undefined;
      decoded = result;
    } else if (filter === "FlateDecode" || filter === "Fl") {
      try {
        decoded = inflateSync(decoded);
      } catch (error) {
        if (error instanceof Error
          && "code" in error
          && (error.code === "Z_DATA_ERROR" || error.code === "Z_BUF_ERROR")) return undefined;
        throw error;
      }
    } else {
      return undefined;
    }
  }
  return decoded;
}

function pdfLiteral(source: string, start: number): { value: string; end: number } | undefined {
  if (source[start] !== "(") return undefined;
  let depth = 1;
  let value = "";
  for (let index = start + 1; index < source.length; index += 1) {
    const character = source[index];
    if (character === "\\") {
      const escaped = source[index + 1];
      if (escaped === undefined) return undefined;
      if (escaped === "\r" || escaped === "\n") {
        index += escaped === "\r" && source[index + 2] === "\n" ? 2 : 1;
        continue;
      }
      if (/[0-7]/.test(escaped)) {
        let octal = escaped;
        let cursor = index + 2;
        while (cursor < source.length && octal.length < 3 && /[0-7]/.test(source[cursor])) {
          octal += source[cursor];
          cursor += 1;
        }
        value += String.fromCharCode(Number.parseInt(octal, 8) & 0xff);
        index = cursor - 1;
        continue;
      }
      const escapedCharacters: Record<string, string> = {
        b: "\b",
        f: "\f",
        n: "\n",
        r: "\r",
        t: "\t",
      };
      value += escapedCharacters[escaped] ?? escaped;
      index += 1;
      continue;
    }
    if (character === "(") {
      depth += 1;
      value += character;
    } else if (character === ")") {
      depth -= 1;
      if (depth === 0) return { value, end: index + 1 };
      value += character;
    } else {
      value += character;
    }
  }
  return undefined;
}

function pdfTextSegments(bytes: Buffer): string[] {
  const source = bytes.toString("latin1");
  const segments: string[] = [];
  let index = 0;
  while (index < source.length) {
    if (source[index] === "[") {
      const values: string[] = [];
      let cursor = index + 1;
      while (cursor < source.length && source[cursor] !== "]") {
        if (source[cursor] === "(") {
          const literal = pdfLiteral(source, cursor);
          if (!literal) break;
          values.push(literal.value);
          cursor = literal.end;
        } else {
          cursor += 1;
        }
      }
      if (source[cursor] === "]") {
        let operator = cursor + 1;
        while (/\s/.test(source[operator] ?? "")) operator += 1;
        if (source.startsWith("TJ", operator)) segments.push(...values);
        index = cursor + 1;
        continue;
      }
    }
    if (source[index] === "(") {
      const literal = pdfLiteral(source, index);
      if (!literal) break;
      let operator = literal.end;
      while (/\s/.test(source[operator] ?? "")) operator += 1;
      if (source.startsWith("Tj", operator) || source[operator] === "'" || source[operator] === "\"") {
        segments.push(literal.value);
      }
      index = literal.end;
      continue;
    }
    index += 1;
  }
  return segments;
}

function parsePdfEvidence(
  fileId: string,
  sourcePath: string,
  content: Buffer,
  capturedAt: string,
): { observations: EvidenceObservation[]; text: string; tokens: string[]; needsOpaqueReview: boolean } {
  const marker = Buffer.from("stream");
  const endMarker = Buffer.from("endstream");
  const endObject = Buffer.from("endobj");
  const segments: string[] = [];
  let needsOpaqueReview = false;
  let offset = 0;

  while (offset < content.length) {
    const streamStart = content.indexOf(marker, offset);
    if (streamStart < 0) break;
    let dataStart = streamStart + marker.length;
    if (content[dataStart] === 0x0d) {
      dataStart += 1;
      if (content[dataStart] === 0x0a) dataStart += 1;
    } else if (content[dataStart] === 0x0a) {
      dataStart += 1;
    } else {
      offset = dataStart;
      continue;
    }

    const streamEnd = content.indexOf(endMarker, dataStart);
    if (streamEnd < 0) break;
    let dataEnd = streamEnd;
    while (dataEnd > dataStart && (content[dataEnd - 1] === 0x0a || content[dataEnd - 1] === 0x0d)) dataEnd -= 1;
    const previousObjectEnd = content.lastIndexOf(endObject, streamStart);
    const header = content.subarray(previousObjectEnd < 0 ? 0 : previousObjectEnd + endObject.length, streamStart).toString("latin1");
    const filterMatch = header.match(/\/Filter\s*(?:\[\s*([^\]]+)\]|(\/[A-Za-z0-9]+))/);
    const filters = filterMatch?.[1]
      ? [...filterMatch[1].matchAll(/\/([A-Za-z0-9]+)/g)].map((match) => match[1])
      : filterMatch?.[2] ? [filterMatch[2].slice(1)] : [];
    const rawStream = content.subarray(dataStart, dataEnd);
    const decoded = decodePdfStream(rawStream, filters);
    if (!decoded) {
      needsOpaqueReview = true;
    } else {
      segments.push(...pdfTextSegments(decoded));
    }
    if (/\/Subtype\s*\/Image\b/.test(header)) needsOpaqueReview = true;
    offset = streamEnd + endMarker.length;
  }

  const text = segments.join("\n");
  const tokens = [...new Set(segments.map(normalize).filter(Boolean))];
  const resourceIds = [...new Set(text.match(/\b(?:data_flow|audit_record|account|support|analytics|search|backup|export)_[A-Za-z0-9-]+\b/gi) ?? [])];
  const emails = [...new Set(text.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi)?.map(normalize) ?? [])];
  const systems: Record<string, string> = {
    account: "account_service",
    analytics: "analytics_platform",
    audit_record: "security_service",
    backup: "backup_service",
    data_flow: "integration_service",
    export: "export_service",
    search: "search_service",
    support: "support_platform",
  };
  const resourceId = resourceIds[0];
  const prefix = resourceId?.match(/^[a-z]+(?=_)/i)?.[0]?.toLowerCase();
  const systemId = prefix ? systems[prefix] : undefined;
  const storedArtifact = /\b(?:upload history|file properties|stored(?: at| in)?|bucket|checksum|storage class)\b/i.test(text);
  const observations = storedArtifact && resourceIds.length === 1 && emails.length === 1 && resourceId && systemId
    ? [{
      evidenceId: fileId,
      sourcePath,
      observedAt: capturedAt,
      systemId,
      resourceId,
      state: "PRESENT" as const,
      tokens: [...new Set([...tokens, ...emails, normalize(resourceId)])],
      category: systemId === "support_platform" && /\b(?:attachment|upload(?:ed|er)?|file)\b/i.test(text)
        ? "SUPPORT_ATTACHMENT"
        : undefined,
    }]
    : [];
  return { observations, text, tokens, needsOpaqueReview };
}

function observation(
  evidenceId: string,
  sourcePath: string,
  value: Record<string, unknown>,
  fallbackTime: string,
): EvidenceObservation | undefined {
  const resourceId = stringValue(value.resource_id);
  const systemId = stringValue(value.system ?? value.system_id ?? value.data_store ?? value.origin_system);
  const eventTime = stringValue(value.recorded_at ?? value.captured_at ?? value.updated_at ?? value.event_time) ?? fallbackTime;
  const state = stateFromResult(stringValue(value.result ?? value.state ?? value.status));
  if (!resourceId || !systemId || !eventTime || !state) return undefined;
  return {
    evidenceId,
    sourcePath,
    resourceId,
    systemId,
    eventTime,
    state,
    tokens: flattenStrings(value).map(normalize),
    category: stringValue(value.record_type ?? value.collection),
  };
}

function isEmptyIdentifier(value: unknown): boolean {
  return value === null || (typeof value === "string" && value.trim() === "");
}

function identifiersState(value: Record<string, unknown>, fields: string[]): ResourceState | undefined {
  if (!fields.every((field) => Object.hasOwn(value, field))) return undefined;
  return fields.every((field) => isEmptyIdentifier(value[field])) ? "ANONYMIZED" : "PRESENT";
}

function snapshotSystem(collection: string): string | undefined {
  const systems: Record<string, string> = {
    customer_profiles: "account_service",
    deleted_customer_references: "identity_service",
    security_audit_events: "security_service",
    customer_analytics_reports: "analytics_platform",
    customer_search_documents: "search_service",
    support_records: "support_platform",
    support_conversations: "support_platform",
    customer_exports: "export_service",
    customer_export_jobs: "export_service",
    connector_subscriptions: "integration_service",
    connector_configurations: "integration_service",
    backup_restore_entries: "backup_service",
    backup_catalog: "backup_service",
  };
  return systems[collection];
}

function snapshotCategory(collection: string): string {
  const categories: Record<string, string> = {
    customer_profiles: "USER_PROFILE",
    security_audit_events: "SECURITY_AUDIT_LOG",
    deleted_customer_references: "ACCOUNT_TOMBSTONE",
    customer_analytics_reports: "ANALYTICS_PROFILE",
    customer_search_documents: "SEARCH_INDEX_ENTRY",
    support_records: "SUPPORT_MESSAGE",
    support_conversations: "SUPPORT_MESSAGE",
    customer_exports: "USER_EXPORT",
    customer_export_jobs: "USER_EXPORT",
    connector_subscriptions: "DATA_FLOW",
    connector_configurations: "DATA_FLOW",
    backup_restore_entries: "BACKUP_ARCHIVE",
    backup_catalog: "BACKUP_ARCHIVE",
  };
  return categories[collection] ?? collection;
}

function snapshotRecordState(record: Record<string, unknown>, collection: string): ResourceState {
  if (collection === "connector_configurations" || collection === "connector_subscriptions") {
    if (typeof record.enabled === "boolean") return record.enabled ? "ACTIVE" : "DISABLED";
  }
  if (collection === "backup_catalog" || collection === "backup_restore_entries") {
    if (record.restore_allowed === false) return "BLOCKED";
    if (record.restore_allowed === true
      && (record.archive_present === true || typeof record.archive_path === "string")) return "ACTIVE";
  }
  if (collection === "deleted_customer_references") {
    const identifierFields = ["name", "full_name", "email", "phone", "email_hash"];
    const hasRequiredFields = ["name", "email", "phone", "email_hash"].every((field) => Object.hasOwn(record, field));
    const hasIdentifiers = identifierFields.some((field) => Object.hasOwn(record, field) && !isEmptyIdentifier(record[field]));
    return stringValue(record.account_status)?.toUpperCase() === "DELETED" && hasRequiredFields && !hasIdentifiers
      ? "REDACTED"
      : "PRESENT";
  }
  if (collection === "customer_analytics_reports") {
    const state = identifiersState(record, ["user_id", "email", "phone", "email_hash"]);
    return state ?? "PRESENT";
  }
  if (collection === "support_records"
    && ["requester_email", "requester_name", "requester_phone"].every((field) => Object.hasOwn(record, field))) {
    return identifiersState(record, ["requester_email", "requester_name", "requester_phone"]) === "ANONYMIZED"
      ? "REDACTED"
      : "PRESENT";
  }
  return "PRESENT";
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function objects(value: unknown): Record<string, unknown>[] {
  if (Array.isArray(value)) return value.flatMap(objects);
  if (!value || typeof value !== "object") return [];
  const object = value as Record<string, unknown>;
  return [object, ...Object.values(object).flatMap(objects)];
}

function parseJsonEvidence(fileId: string, sourcePath: string, content: string, capturedAt: string): EvidenceObservation[] {
  const document = JSON.parse(content) as unknown;
  const parsed = objects(document).flatMap((value) => {
    const parsed = observation(fileId, sourcePath, value, capturedAt);
    if (parsed) return [parsed];

    const records = value.records;
    const collection = stringValue(value.collection);
    const system = stringValue(value.data_store ?? value.system ?? value.system_id)
      ?? (collection ? snapshotSystem(collection) : undefined);
    const time = stringValue(value.captured_at ?? value.recorded_at ?? value.exported_at) ?? capturedAt;
    if (!Array.isArray(records) || !collection || !system) return [];
    return records.flatMap((record) => {
      if (!record || typeof record !== "object") return [];
      const recordObject = record as Record<string, unknown>;
      const explicitState = stateFromResult(stringValue(recordObject.result ?? recordObject.state ?? recordObject.status));
      const snapshotState = snapshotRecordState(recordObject, collection);
      const recordValue = {
        ...recordObject,
        system,
        record_type: snapshotCategory(collection),
        result: collection === "deleted_customer_references" || collection === "customer_analytics_reports"
          ? snapshotState
          : explicitState ?? snapshotState,
        recorded_at: stringValue(recordObject.recorded_at ?? recordObject.observed_at) ?? time,
      };
      return [observation(fileId, sourcePath, recordValue, capturedAt)].filter((item): item is EvidenceObservation => item !== undefined);
    });
  });
  if (!document || typeof document !== "object") return parsed;
  const serviceExports = (document as Record<string, unknown>).service_exports;
  if (!serviceExports || typeof serviceExports !== "object") return parsed;
  const categories: Record<string, string> = {
    account_service: "USER_PROFILE",
    analytics_platform: "ANALYTICS_PROFILE",
    search_service: "SEARCH_INDEX_ENTRY",
    support_platform: "SUPPORT_MESSAGE",
    integration_service: "DATA_FLOW",
    security_service: "SECURITY_AUDIT_LOG",
    export_service: "USER_EXPORT",
    backup_service: "BACKUP_ARCHIVE",
  };
  const exports = Object.entries(serviceExports as Record<string, unknown>).flatMap(([system, value]) => {
    if (!value || typeof value !== "object") return [];
    return Object.values(value as Record<string, unknown>).flatMap((records) => objects(records).flatMap((record) => {
      const resourceId = stringValue(record.resource_id);
      const hits = record.hits;
      const statusCode = Number(record.status_code);
      const statusResult = statusCode === 200 ? "FOUND" : statusCode === 404 ? "NOT_FOUND" : undefined;
      const enabled = record.enabled === true || record.enabled === "true";
      const disabled = record.enabled === false || record.enabled === "false";
      const hasEnabledState = system === "integration_service" && (enabled || disabled);
      const restoreAllowed = record.restore_allowed === true || record.restore_allowed === "true";
      const restoreBlocked = record.restore_allowed === false || record.restore_allowed === "false";
      const unsafeRestore = (record.archive_present === true || record.archive_present === "true") && restoreAllowed;
      const hasRestoreState = system === "backup_service" && (restoreBlocked || unsafeRestore);
      const supportIdentifiers = ["requester_email", "requester_name", "requester_phone"];
      const supportState = system === "support_platform"
        && supportIdentifiers.every((field) => Object.hasOwn(record, field))
        ? identifiersState(record, supportIdentifiers) === "ANONYMIZED" ? "REDACTED" : "PRESENT"
        : undefined;
      const hitRecord = hits && typeof hits === "object" ? hits as Record<string, unknown> : undefined;
      const documents = hitRecord?.documents;
      const hasSearchHit = Number(hitRecord?.total) > 0 && Array.isArray(documents) && documents.length > 0;
      const analyticsState = system === "analytics_platform"
        ? identifiersState(record, ["customer_reference", "email", "email_hash", "phone"])
        : undefined;
      const hasSecurityAuditRecord = system === "security_service"
        && typeof record.subject_reference === "string"
        && typeof record.event_code === "string";
      const hasReturnedRecord = record.profile !== null && typeof record.profile === "object"
        || hasSearchHit
        || typeof record.requester_email === "string"
        || typeof record.message_excerpt === "string"
        || typeof record.email === "string"
        || typeof record.customer_email === "string"
        || typeof record.owner_email === "string"
        || typeof record.customer_reference === "string"
        || analyticsState !== undefined
        || hasSecurityAuditRecord
        || hasEnabledState
        || hasRestoreState;
      if (!resourceId || (!statusResult && !hasReturnedRecord)) return [];
      const entry = {
        ...record,
        system,
        record_type: categories[system],
        result: statusResult === "NOT_FOUND" ? statusResult : analyticsState ?? supportState
          ?? (hasEnabledState ? enabled ? "ACTIVE" : "DISABLED" : undefined)
          ?? (hasRestoreState ? restoreBlocked ? "BLOCKED" : "ACTIVE" : undefined)
          ?? statusResult ?? (hasSecurityAuditRecord ? "PRESENT" : "FOUND"),
        recorded_at: record.observed_at,
      };
      return [observation(fileId, sourcePath, entry, capturedAt)].filter((item): item is EvidenceObservation => item !== undefined);
    }).filter((item) => item !== undefined));
  });
  return [...parsed, ...exports];
}

function parseKeyValueLine(line: string): Record<string, unknown> {
  const fields: Record<string, unknown> = {};
  const normalizedLine = line.replaceAll('\\"', '"');
  for (const match of normalizedLine.matchAll(/([a-z_]+)=(?:"([^"]*)"|([^\s|]+))/gi)) fields[match[1]] = match[2] ?? match[3];
  const timestamp = line.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/)?.[0];
  const jsonStart = line.indexOf("{");
  if (jsonStart >= 0) {
    try {
      const parsed = JSON.parse(line.slice(jsonStart)) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        Object.assign(fields, parsed);
        if (timestamp && !fields.recorded_at) fields.recorded_at = timestamp;
      }
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
    }
  }
  const syslog = line.match(/^\d{4}-\d{2}-\d{2}T[^ ]+\s+<\d+>\d+\s+\S+\s+([a-z_]+)\s+([a-z0-9-]+)\s+-\s+-\s+/i);
  if (syslog) {
    fields.system ??= syslog[1];
    fields.trace_id ??= syslog[2];
  }
  const applicationTrace = line.match(/\[([a-z_]+)\]\s+\[([a-z0-9-]+)\]\s+([a-z_]+):/i);
  if (applicationTrace) {
    fields.system = applicationTrace[1];
    fields.trace_id = applicationTrace[2];
    fields.event = applicationTrace[3];
  }
  if (!fields.trace_id) fields.trace_id = stringValue(fields.requestId);
  const pipe = line.split("|").map((part) => part.trim());
  const pipeState = new Set(["FOUND", "NOT_FOUND", "PRESENT", "ABSENT", "ACTIVE", "DISABLED", "BLOCKED", "REDACTED", "ANONYMIZED"]);
  if (pipe.length >= 6 && pipeState.has(pipe[4].toUpperCase())) {
    fields.recorded_at = pipe[0].replace(/^- /, "");
    fields.system = pipe[1];
    fields.resource_id = pipe[2];
    fields.record_type = pipe[3];
    fields.result = pipe[4];
    fields.subject_reference = pipe[5];
  } else if (pipe.length >= 6 && /^[a-z_]+$/i.test(pipe[2]) && /^[a-z0-9-]+$/i.test(pipe[3])) {
    fields.recorded_at = pipe[0].replace(/^- /, "");
    fields.system ??= pipe[2];
    fields.trace_id ??= pipe[3];
    fields.event ??= pipe[4];
  }
  return fields;
}

function parseTextEvidence(fileId: string, sourcePath: string, content: string, capturedAt: string): EvidenceObservation[] {
  const traces = new Map<string, string[]>();
  const entries = content.split(/\r?\n/).map((line) => {
    const fields = parseKeyValueLine(line);
    if (!fields.recorded_at) fields.recorded_at = line.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/)?.[0];
    if (!fields.system) fields.system = fields.service ?? fields.function;
    const traceId = stringValue(fields.trace_id);
    const identifiers = ["lookup_key", "subject_key", "subject_ref", "email", "customer_email", "matched_value"]
      .flatMap((field) => stringValue(fields[field]) ? [stringValue(fields[field])!] : []);
    if (traceId && identifiers.length > 0) traces.set(traceId, [...(traces.get(traceId) ?? []), ...identifiers]);
    return { line, fields, traceId };
  });
  return entries.flatMap(({ line, fields, traceId }) => {
    const event = stringValue(fields.event);
    const rows = Number(stringValue(fields.rows));
    const status = Number(stringValue(fields.http_status));
    if (event === "profile_lookup_completed" && ((rows === 0 && status === 404) || (rows > 0 && status === 200))) {
      fields.result = rows === 0 ? "NOT_FOUND" : "FOUND";
    } else if (event === "message_pii_scan" || event === "attachment_pii_scan" || event === "analytics_identity_scan") {
      fields.result = "FOUND";
    } else if (event === "contact_query_completed" && rows > 0) {
      fields.result = "FOUND";
      fields.record_type = "SUPPORT_MESSAGE";
    } else if (event === "contact_lookup_completed" && rows > 0) {
      fields.result = "FOUND";
      fields.record_type = "ANALYTICS_PROFILE";
    } else if (event === "analytics_profile_read_completed" && (
      typeof fields.email === "string"
      || typeof fields.phone === "string"
      || typeof fields.email_hash === "string"
      || typeof fields.customer_reference === "string"
    )) {
      fields.result = "FOUND";
      fields.record_type = "ANALYTICS_PROFILE";
    } else if (event === "export_metadata_read_completed" && stringValue(fields.available) === "true") {
      fields.result = "FOUND";
      fields.record_type = "USER_EXPORT";
    } else if (event === "restore_policy_read_completed"
      && stringValue(fields.restore_allowed) === "false") {
      fields.result = "BLOCKED";
      fields.record_type = "BACKUP_ARCHIVE";
    } else if (event === "restore_policy_read_completed"
      && stringValue(fields.archive_present) === "true"
      && stringValue(fields.restore_allowed) === "true") {
      fields.result = "ACTIVE";
      fields.record_type = "BACKUP_ARCHIVE";
    } else if (event === "support_ticket_read_completed" && (
      typeof fields.requester_email === "string"
      || typeof fields.requester_name === "string"
      || typeof fields.customer_reference === "string"
    )) {
      fields.result = "FOUND";
      fields.record_type = "SUPPORT_MESSAGE";
    } else if (event === "index_query_completed" && stringValue(fields.result) === "hit") {
      fields.result = "FOUND";
      fields.record_type = "SEARCH_INDEX_ENTRY";
    } else if ((event === "connector_heartbeat" || event === "connector_config_read_completed") && stringValue(fields.enabled) === "true") {
      fields.result = "ACTIVE";
      fields.record_type = "DATA_FLOW";
    } else if ((event === "connector_heartbeat" || event === "connector_config_read_completed") && stringValue(fields.enabled) === "false") {
      fields.result = "DISABLED";
      fields.record_type = "DATA_FLOW";
    } else if (event === "restore_candidate_evaluated"
      && stringValue(fields.eligible) === "true"
      && stringValue(fields.deletion_block) === "false") {
      fields.result = "ACTIVE";
      fields.record_type = "BACKUP_ARCHIVE";
    } else if (event === "restore_candidate_evaluated"
      && stringValue(fields.eligible) === "true"
      && stringValue(fields.deletion_block) === "true") {
      fields.result = "BLOCKED";
      fields.record_type = "BACKUP_ARCHIVE";
    } else if (event === "audit_record_read_completed" && rows > 0) {
      fields.result = "FOUND";
      fields.record_type = "SECURITY_AUDIT_LOG";
    }
    const traceTokens = traceId ? traces.get(traceId) ?? [] : [];
    const parsed = observation(fileId, sourcePath, { ...fields, trace_tokens: traceTokens, raw_line: line }, capturedAt);
    return parsed ? [parsed] : [];
  });
}

function sqlStrings(statement: string): string[] {
  return [...statement.matchAll(/'((?:''|[^'])*)'/g)].map((match) => match[1].replaceAll("''", "'"));
}

function sqlValues(statement: string): Array<string | null> {
  const match = statement.match(/VALUES\s*\(([\s\S]*)\)\s*$/i);
  if (!match) return [];
  const values: Array<string | null> = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < match[1].length; index += 1) {
    const character = match[1][index];
    if (quoted && character === "'" && match[1][index + 1] === "'") {
      current += "'";
      index += 1;
    } else if (character === "'") {
      quoted = !quoted;
    } else if (character === "," && !quoted) {
      values.push(current.trim() === "NULL" ? null : current.trim());
      current = "";
    } else {
      current += character;
    }
  }
  values.push(current.trim() === "NULL" ? null : current.trim());
  return values;
}

function inventoryObservation(
  fileId: string,
  sourcePath: string,
  table: string,
  values: Array<string | null>,
  capturedAt: string,
): EvidenceObservation | undefined {
  const definitions: Record<string, { system: string; category: string; state?: ResourceState }> = {
    customer_profiles: { system: "account_service", category: "USER_PROFILE" },
    customer_search_documents: { system: "search_service", category: "SEARCH_INDEX_ENTRY" },
    search_documents: { system: "search_service", category: "SEARCH_INDEX_ENTRY" },
    customer_analytics_profiles: { system: "analytics_platform", category: "ANALYTICS_PROFILE" },
    support_records: { system: "support_platform", category: "SUPPORT_MESSAGE" },
    customer_exports: { system: "export_service", category: "USER_EXPORT" },
    connector_subscriptions: { system: "integration_service", category: "DATA_FLOW" },
    backup_restore_entries: { system: "backup_service", category: "BACKUP_ARCHIVE" },
    security_audit_records: { system: "security_service", category: "SECURITY_AUDIT_LOG" },
  };
  const definition = definitions[table];
  const resourceId = values[0];
  const eventTime = values.at(-1);
  if (!definition || !resourceId || !eventTime) return undefined;
  const state = table === "connector_subscriptions" ? values[4] === "1" ? "ACTIVE" : "DISABLED"
    : table === "backup_restore_entries" ? values[4] === "1" ? "ACTIVE" : "BLOCKED"
      : table === "customer_profiles" && values[6] === "DELETED" ? "REDACTED"
        : definition.state ?? "PRESENT";
  return {
    evidenceId: fileId,
    sourcePath,
    eventTime,
    systemId: definition.system,
    resourceId,
    state,
    tokens: values.filter((value): value is string => value !== null).map(normalize),
    category: definition.category,
  };
}

function canonicalTableName(table: string): string {
  return table.replace(/_(?:primary|(?:regional|reporting|read|failover)_replica)$/i, "");
}

function parseSqlEvidence(
  fileId: string,
  sourcePath: string,
  content: string,
  capturedAt: string,
  resourceCandidates: readonly SnapshotResourceCandidate[],
): EvidenceObservation[] {
  let hasCustomerProfileSnapshot = false;
  const observedProfileResources = new Set<string>();
  const parsedObservations = content.split(/;\s*(?:\r?\n|$)/).flatMap((statement) => {
    const insertTable = statement.match(/^INSERT\s+INTO\s+["']?([a-z_]+)/i)?.[1];
    const table = canonicalTableName(insertTable ?? "");
    if (!insertTable) return [];
    const values = sqlStrings(statement);
    const json = values.find((value) => value.startsWith("{") && value.endsWith("}"));
    if (json) {
      const record = JSON.parse(json) as Record<string, unknown>;
      const connectorState = values[2] === "connector_configurations" && typeof record.enabled === "boolean"
        ? record.enabled ? "ACTIVE" : "DISABLED"
        : undefined;
      return [observation(fileId, sourcePath, {
        ...record,
        system: values[1],
        collection: values[2],
        ...(connectorState ? { result: connectorState, record_type: "DATA_FLOW" } : { result: "FOUND" }),
        recorded_at: values.at(-1) ?? capturedAt,
      }, capturedAt)].filter((item): item is EvidenceObservation => item !== undefined);
    }
    const parsed = inventoryObservation(fileId, sourcePath, table, sqlValues(statement), capturedAt);
    if (parsed?.category === "USER_PROFILE") {
      hasCustomerProfileSnapshot = true;
      observedProfileResources.add(parsed.resourceId);
    }
    return parsed ? [parsed] : [];
  });

  if (!hasCustomerProfileSnapshot) return parsedObservations;
  const absentProfiles = resourceCandidates
    .filter((candidate) => Date.parse(candidate.eventTime) <= Date.parse(capturedAt))
    .filter((candidate) => !observedProfileResources.has(candidate.resourceId))
    .map((candidate): EvidenceObservation => ({
      evidenceId: fileId,
      sourcePath,
      capturedAt,
      eventTime: capturedAt,
      systemId: "account_service",
      resourceId: candidate.resourceId,
      state: "ABSENT",
      tokens: [],
      category: "USER_PROFILE",
    }));
  return [...parsedObservations, ...absentProfiles];
}

export function extractEvidence(
  manifest: CsvRow,
  content: string | Buffer,
  resourceCandidates: readonly SnapshotResourceCandidate[] = [],
): EvidenceExtraction {
  const extension = path.extname(manifest.file_path).toLowerCase();
  const textContent = typeof content === "string" ? content : content.toString("utf8");
  const pdf = extension === ".pdf"
    ? parsePdfEvidence(
      manifest.file_id,
      manifest.file_path,
      typeof content === "string" ? Buffer.from(content, "latin1") : content,
      manifest.captured_at,
    )
    : undefined;
  const parser = extension === ".json" ? parseJsonEvidence
    : extension === ".sql" ? (fileId: string, sourcePath: string, text: string, capturedAt: string) =>
      parseSqlEvidence(fileId, sourcePath, text, capturedAt, resourceCandidates)
      : extension === ".log" || extension === ".txt" ? parseTextEvidence
        : undefined;
  return {
    fileId: manifest.file_id,
    sourcePath: manifest.file_path,
    capturedAt: manifest.captured_at,
    inspected: true,
    observations: (pdf?.observations ?? (parser ? parser(manifest.file_id, manifest.file_path, textContent, manifest.captured_at) : []))
      .map((entry) => ({
        ...entry,
        capturedAt: manifest.captured_at,
        observedAt: entry.observedAt ?? manifest.captured_at,
      })),
    ...(pdf ? {
      extractedText: pdf.text,
      extractedTokens: pdf.tokens,
      needsOpaqueReview: pdf.needsOpaqueReview,
    } : {}),
  };
}

export function readEvidence(
  manifest: CsvRow[],
  datasetRoot: string,
  resourceCandidates: readonly SnapshotResourceCandidate[] = [],
): EvidenceExtraction[] {
  return manifest.map((entry) => extractEvidence(
    entry,
    readFileSync(path.join(datasetRoot, entry.file_path)),
    resourceCandidates,
  ));
}

const resourceLinkWindowMs = 10 * 60 * 1000;

export function requestResourceLink(
  request: CsvRow,
  activity: CsvRow[],
  subject: Subject,
): EvidenceObservation[] {
  const reportTime = Date.parse(request.reported_at);
  const candidates = activity.filter((row) =>
    (row.event_type === "DELETE_RECORD" && row.target_system === "account_service"
      || row.event_type === "ANONYMIZE_RECORD" && row.target_system === "analytics_platform")
      && Math.abs(Date.parse(row.event_time) - reportTime) <= resourceLinkWindowMs,
  );
  const candidatesByResource = new Map<string, CsvRow[]>();
  for (const candidate of candidates) {
    const matches = candidatesByResource.get(candidate.resource_id) ?? [];
    matches.push(candidate);
    candidatesByResource.set(candidate.resource_id, matches);
  }
  return [...candidatesByResource.values()]
    .filter((matches) => matches.length === 1)
    .map(([match]) => ({
    evidenceId: match.activity_id,
    sourcePath: "system_activity.csv",
    eventTime: match.event_time,
    capturedAt: match.event_time,
    systemId: match.target_system,
    resourceId: match.resource_id,
    state: "PRESENT" as const,
    tokens: [...subject.aliases].map(normalize),
    kind: "IDENTITY_LINK" as const,
  }));
}

export function activityObservations(activity: CsvRow[]): EvidenceObservation[] {
  return activity.flatMap<EvidenceObservation>((row) => {
    if (row.event_type === "LINK_RESOURCE_IDENTITY") {
      const visibleResourceLabels = [...new Set([
        row.resource_id,
        ...[...row.details.matchAll(/\(([^)]+)\)/g)].map((match) => match[1].trim()),
      ].map(normalize))];
      return [{
        evidenceId: row.activity_id,
        sourcePath: "system_activity.csv",
        eventTime: row.event_time,
        systemId: row.target_system,
        resourceId: row.resource_id,
        state: "PRESENT" as const,
        tokens: [row.resource_id, row.details].flatMap((value) => value.match(/[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|user_\d+/g) ?? []).map(normalize),
        visibleResourceLabels,
        ...( /attachment catalog/i.test(row.details) ? { category: "SUPPORT_ATTACHMENT" } : {}),
        kind: "IDENTITY_LINK" as const,
      }];
    }
    const state = activityState(row.event_type, row.reported_result);
    if (!state) return [];
    return [{
      evidenceId: row.activity_id,
      sourcePath: "system_activity.csv",
      eventTime: row.event_time,
      systemId: row.target_system,
      resourceId: row.resource_id,
      state,
      tokens: [row.resource_id, row.details].map(normalize),
      category: row.event_type === "RESTORE_BACKUP" ? "BACKUP_ARCHIVE" : undefined,
      capturedAt: row.event_time,
    }];
  });
}

export function reconstructAt(
  subject: Subject,
  observations: EvidenceObservation[],
  auditAt: string,
): Map<string, EvidenceObservation> {
  const cutoff = Date.parse(auditAt);
  const observationTime = (entry: EvidenceObservation): number =>
    Date.parse(entry.eventTime ?? entry.observedAt ?? entry.capturedAt ?? "");
  const preCutoff = observations
    .filter((entry) => observationTime(entry) <= cutoff
      && Date.parse(entry.capturedAt ?? entry.eventTime ?? entry.observedAt ?? "") <= cutoff)
  const linkedResources = new Set(preCutoff
    .filter((entry) => entry.kind === "IDENTITY_LINK")
    .filter((entry) => entry.tokens.some((token) => subject.aliases.has(normalize(token))))
    .map((entry) => entry.resourceId));
  const relevant = preCutoff
    .filter((entry) => entry.kind !== "IDENTITY_LINK")
    .filter((entry) => linkedResources.has(entry.resourceId) || entry.tokens.some((token) => subject.aliases.has(normalize(token))))
    .sort((left, right) => observationTime(left) - observationTime(right));
  return new Map(relevant.map((entry) => [entry.resourceId, entry]));
}

export function loadReconstructionInputs(inputs: ValidatedInputs, datasetRoot: string): {
  subjects: Map<string, Subject>;
  evidence: EvidenceExtraction[];
  activity: EvidenceObservation[];
} {
  return {
    subjects: buildSubjects(inputs.userIdentities, inputs.userAuditLog),
    evidence: readEvidence(inputs.evidenceFiles, datasetRoot),
    activity: activityObservations(inputs.systemActivity),
  };
}
