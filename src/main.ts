import { outputPath } from "./config.js";
import { readValidatedInputs } from "./contracts.js";
import { loadConfiguredInvestigator } from "./investigator.js";
import { generateRows, writeOutput } from "./planner.js";

const inputs = readValidatedInputs();
const result = await generateRows(inputs, undefined, loadConfiguredInvestigator());
if (result.unresolvedCases.length > 0) {
  throw new Error(`Refusing to write ${outputPath}: unresolved evidence for ${result.unresolvedCases.length} cases (${result.unresolvedCases.join(", ")})`);
}
const expectedCaseIds = inputs.deletionRequests.map((request) => request.case_id).sort((left, right) => left.localeCompare(right));
const actualCaseIds = result.rows.map((row) => row.case_id).sort((left, right) => left.localeCompare(right));
if (expectedCaseIds.length !== 518 || actualCaseIds.length !== 518
  || expectedCaseIds.some((caseId, index) => actualCaseIds[index] !== caseId)) {
  throw new Error(`Refusing to write ${outputPath}: expected exactly 518 unique case rows`);
}
const evidenceIds = new Set([
  ...inputs.evidenceFiles.map((entry) => entry.file_id),
  ...inputs.systemActivity.map((entry) => entry.activity_id),
  ...inputs.userAuditLog.map((entry) => entry.audit_id),
]);
writeOutput(result.rows, outputPath, evidenceIds);
console.log(`Wrote ${result.rows.length} validated audit rows to ${outputPath}`);
