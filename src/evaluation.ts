import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { datasetDirectory } from "./config.js";
import { parseCsv, readValidatedInputs } from "./contracts.js";
import { generateRows, type PlannedRow, type PlannedStep } from "./planner.js";

interface ExpectedRow {
  case_id: string;
  deletion_status: PlannedRow["deletion_status"];
  steps_json: PlannedStep[];
}

export interface SampleMetrics {
  expectedCases: number;
  predictedCases: number;
  missingCaseIds: string[];
  statusCorrect: number;
  stepCorrect: number;
  expectedSteps: number;
  fieldCorrect: number;
  expectedFields: number;
  sequenceCorrect: number;
  mismatches: Array<{ caseId: string; reason: "MISSING" | "STATUS" | "STEP" | "FIELD" | "SEQUENCE" }>;
}

const stepFields: Array<keyof PlannedStep> = [
  "step_no",
  "phase",
  "system_id",
  "resource_id",
  "operation",
  "state",
  "evidence_id",
];

export function readExpectedSample(filePath = path.join(datasetDirectory, "sample_output.csv")): ExpectedRow[] {
  return parseCsv(readFileSync(filePath, "utf8"), ["case_id", "deletion_status", "steps_json"]).map((row) => ({
    case_id: row.case_id,
    deletion_status: row.deletion_status as PlannedRow["deletion_status"],
    steps_json: JSON.parse(row.steps_json) as PlannedStep[],
  }));
}

export function evaluateSample(expected: ExpectedRow[], predicted: PlannedRow[]): SampleMetrics {
  const predictions = new Map(predicted.map((row) => [row.case_id, row]));
  const metrics: SampleMetrics = {
    expectedCases: expected.length,
    predictedCases: predicted.length,
    missingCaseIds: [],
    statusCorrect: 0,
    stepCorrect: 0,
    expectedSteps: 0,
    fieldCorrect: 0,
    expectedFields: 0,
    sequenceCorrect: 0,
    mismatches: [],
  };

  for (const expectedRow of expected) {
    const predictedRow = predictions.get(expectedRow.case_id);
    metrics.expectedSteps += expectedRow.steps_json.length;
    metrics.expectedFields += expectedRow.steps_json.length * stepFields.length;
    if (!predictedRow) {
      metrics.missingCaseIds.push(expectedRow.case_id);
      metrics.mismatches.push({ caseId: expectedRow.case_id, reason: "MISSING" });
      continue;
    }
    if (predictedRow.deletion_status === expectedRow.deletion_status) metrics.statusCorrect += 1;
    else {
      metrics.mismatches.push({ caseId: expectedRow.case_id, reason: "STATUS" });
      continue;
    }

    const comparedSteps = Math.min(expectedRow.steps_json.length, predictedRow.steps_json.length);
    let fieldMismatch = false;
    for (let index = 0; index < comparedSteps; index += 1) {
      const expectedStep = expectedRow.steps_json[index];
      const predictedStep = predictedRow.steps_json[index];
      const matchingFields = stepFields.filter((field) => expectedStep[field] === predictedStep[field]);
      metrics.fieldCorrect += matchingFields.length;
      if (matchingFields.length === stepFields.length) metrics.stepCorrect += 1;
      else fieldMismatch = true;
    }
    if (fieldMismatch || expectedRow.steps_json.length !== predictedRow.steps_json.length) {
      metrics.mismatches.push({ caseId: expectedRow.case_id, reason: fieldMismatch ? "FIELD" : "STEP" });
      continue;
    }
    metrics.sequenceCorrect += 1;
  }
  return metrics;
}

function percentage(numerator: number, denominator: number): string {
  return denominator === 0 ? "0.0%" : `${((numerator / denominator) * 100).toFixed(1)}%`;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const inputs = readValidatedInputs();
  const result = await generateRows({ ...inputs, deletionRequests: inputs.sampleDeletionRequests });
  const metrics = evaluateSample(readExpectedSample(), result.rows);
  console.log([
    `Sample cases: ${metrics.expectedCases}`,
    `Predictions: ${metrics.predictedCases}`,
    `Missing predictions: ${metrics.missingCaseIds.length}`,
    `Status accuracy: ${metrics.statusCorrect}/${metrics.expectedCases} (${percentage(metrics.statusCorrect, metrics.expectedCases)})`,
    `Step accuracy: ${metrics.stepCorrect}/${metrics.expectedSteps} (${percentage(metrics.stepCorrect, metrics.expectedSteps)})`,
    `Field accuracy: ${metrics.fieldCorrect}/${metrics.expectedFields} (${percentage(metrics.fieldCorrect, metrics.expectedFields)})`,
    `Sequence accuracy: ${metrics.sequenceCorrect}/${metrics.expectedCases} (${percentage(metrics.sequenceCorrect, metrics.expectedCases)})`,
    `Mismatches: ${metrics.mismatches.length}`,
  ].join("\n"));
}
