# Tasks

## 1. TypeScript CLI foundation

- [x] 1.1 Create the minimal TypeScript package, CLI entry point, typed domain models, and deterministic path configuration; verify a clean install and compile succeed without framework or database dependencies.
- [x] 1.2 Implement CSV parsing and contract validation for all required inputs and output rows; verify focused tests reject missing headers, malformed timestamps, invalid status values, and invalid step shapes.
- [x] 1.3 Document setup, the run command, and generated-output location in README; verify the documented command runs from the repository root.

## 2. Subject and evidence reconstruction

- [x] 2.1 Implement deletion-authorization classification and current/historical identity alias indexing; verify tests cover deletion, access/export, and historical-email requests.
- [x] 2.2 Implement manifest-backed adapters for CSV activity, JSON, logs, text, and SQLite-compatible SQL with source provenance; verify each adapter emits normalized observations with evidence identifiers and every pre-cutoff manifest item is accounted for.
- [x] 2.3 Implement audit-cutoff filtering, grounded subject association, and ordered state reduction; verify tests exclude post-cutoff and unrelated evidence, preserve linked historical identifiers, and classify a delete followed by a pre-cutoff sync or restore as present.
- [x] 2.4 Define the no-tool `EvidenceInvestigator` interface, bounded evidence packet, Zod response schema, and zero-call deterministic default; verify a linked pre-cutoff PDF/image containing PII prevents `COMPLETE` and preserves its `file_id`.
- [x] 2.5 Add investigator caching, one-retry validation handling, and case-isolated failure diagnostics; verify known deterministic violations produce valid `INCOMPLETE`, unresolved relevant evidence emits no case row or `COMPLETE`, independent cases continue, and global input/output failures are run-fatal.

## 3. Policy evaluation and output planning

- [x] 3.1 Implement rule lookup and required treatments for delete, redact, anonymize, retain, tombstone, data-flow, and restore-risk cases; verify focused fixtures cover every rule action.
- [x] 3.2 Generate findings, dependency-safe remediation, and verification steps using only contract-defined operation/state pairs; verify incomplete steps have empty future evidence IDs, complete steps have valid evidence IDs, and recreated data produces the required finding and remediation.
- [ ] 3.3 Canonically sort and number steps, serialize valid JSON arrays, and write root `output.csv`; verify output ordering, consecutive numbering, exact columns, and `NOT_APPLICABLE` empty arrays.

## 4. Evaluation and submission readiness

- [x] 4.1 Add sample-evaluation comparison with case, step, field, and sequence metrics; verify it detects a deliberately altered fixture and reports the affected case.
- [x] 4.2 Add three independent evaluation cases and document failures and improvements in `code/evaluation/evaluation_report.md`; verify the report contains every required section.
- [x] 4.3 Generate `code/evaluation/usage_report.md` from the final run, including zero-use or measured model/token/cost totals; verify all required totals are present and no credentials are recorded.
- [x] 4.4 Compare deterministic-only and hybrid modes on opaque-evidence and invalid-model fixtures; verify status, step, field, sequence, unresolved-case, call, token, cost, cache, and continuation metrics are reported.
- [ ] 4.5 Run the full 518-case generation and contract validator; verify exactly 518 sorted output rows, valid JSON steps, valid evidence references, zero unresolved-case diagnostics, and a successful TypeScript build.
- [x] 4.6 Document and verify the code-only packaging command; verify the archive includes code, README, and evaluation reports while excluding datasets, dependencies, nested archives, and credentials.

## Workflow follow-up

- Apply the change only after review approval.
- Archive the change after implementation and validation are complete.
