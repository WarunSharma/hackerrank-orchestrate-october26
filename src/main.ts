import { readFileSync } from "node:fs";
import { outputPath } from "./config.js";
import { parseCsv, readValidatedInputs, validateOutputRows } from "./contracts.js";
import { loadConfiguredInvestigator, newUsageTracker } from "./investigator.js";
import {
  addProvisionalRows,
  compareCaseIds,
  generateRows,
  semanticOutputIssues,
  writeOutput,
} from "./planner.js";

const inputs = readValidatedInputs();
const usage = newUsageTracker();
const result = await generateRows(inputs, undefined, loadConfiguredInvestigator(), usage);
const bestEffort = process.env.BEST_EFFORT?.toLocaleLowerCase() === "true";
const geminiUsage = usage.records.filter((record) => record.provider === "gemini");
const modelTotals = new Map<string, { calls: number; inputTokens: number; outputTokens: number }>();
for (const record of geminiUsage) {
  const totals = modelTotals.get(record.model) ?? { calls: 0, inputTokens: 0, outputTokens: 0 };
  if (!record.cacheHit) totals.calls += 1;
  totals.inputTokens += record.inputTokens;
  totals.outputTokens += record.outputTokens;
  modelTotals.set(record.model, totals);
}
console.log(`Gemini usage: calls=${[...modelTotals.values()].reduce((sum, totals) => sum + totals.calls, 0)}, input_tokens=${geminiUsage.reduce((sum, record) => sum + record.inputTokens, 0)}, output_tokens=${geminiUsage.reduce((sum, record) => sum + record.outputTokens, 0)}, cache_hits=${geminiUsage.filter((record) => record.cacheHit).length}, models=${[...modelTotals].map(([model, totals]) => `${model}(calls=${totals.calls},input=${totals.inputTokens},output=${totals.outputTokens})`).join("; ") || "none"}`);
if (result.unresolvedCases.length > 0 && !bestEffort) {
  throw new Error(`Refusing to write ${outputPath}: unresolved evidence for ${result.unresolvedCases.length} cases (${result.unresolvedCases.join(", ")})`);
}
const provisionalCaseIds = bestEffort ? [...result.unresolvedCases].sort(compareCaseIds) : [];
const rows = bestEffort ? addProvisionalRows(result.rows, provisionalCaseIds) : result.rows;
const expectedCaseIds = inputs.deletionRequests.map((request) => request.case_id).sort(compareCaseIds);
const actualCaseIds = rows.map((row) => row.case_id).sort(compareCaseIds);
if (expectedCaseIds.length !== 518 || actualCaseIds.length !== 518
  || expectedCaseIds.some((caseId, index) => actualCaseIds[index] !== caseId)) {
  throw new Error(`Refusing to write ${outputPath}: expected exactly 518 unique case rows`);
}
const evidenceIds = new Set([
  ...inputs.evidenceFiles.map((entry) => entry.file_id),
  ...inputs.systemActivity.map((entry) => entry.activity_id),
  ...inputs.userAuditLog.map((entry) => entry.audit_id),
]);
writeOutput(rows, outputPath, evidenceIds);

const outputHeaders = ["case_id", "deletion_status", "steps_json"] as const;
const outputText = readFileSync(outputPath, "utf8");
if (outputText.split(/\r?\n/, 1)[0] !== outputHeaders.join(",")) {
  throw new Error(`Invalid output header in ${outputPath}`);
}
const csvRows = parseCsv(outputText, outputHeaders);
if (csvRows.length !== 518) throw new Error(`Expected 518 output rows, received ${csvRows.length}`);
const orderedCaseIds = csvRows.map((row) => row.case_id);
if (orderedCaseIds.some((caseId, index) => caseId !== expectedCaseIds[index])) {
  throw new Error("Output rows are not sorted or do not match the request case IDs");
}
const parsedRows = csvRows.map((row) => ({
  case_id: row.case_id,
  deletion_status: row.deletion_status,
  steps_json: JSON.parse(row.steps_json) as Array<{ phase: string }>,
}));
validateOutputRows(parsedRows, evidenceIds);
const semanticIssues = semanticOutputIssues(parsedRows);
console.log(`Wrote ${csvRows.length} structurally validated audit rows to ${outputPath}`);
if (provisionalCaseIds.length > 0) {
  console.log(`Provisional INCOMPLETE rows (empty steps): ${provisionalCaseIds.join(", ")}`);
}
if (semanticIssues.length > 0) {
  console.warn(`Official semantic contract failures: ${semanticIssues.length}`);
  for (const issue of semanticIssues) console.warn(`  ${issue.caseId}: ${issue.reason}`);
} else {
  console.log("No semantic phase/order issues detected");
}
