import { fileURLToPath } from "node:url";
import path from "node:path";

const sourceDirectory = path.dirname(fileURLToPath(import.meta.url));
export const repoRoot = path.resolve(sourceDirectory, "..");
export const datasetDirectory = path.join(repoRoot, "dataset");
export const outputPath = path.join(repoRoot, "output.csv");
