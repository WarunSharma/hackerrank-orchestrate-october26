# Proposal

## Why

Northstar's reported deletion workflow is not proof that personal data is gone: copies, historical identifiers, retained records, and active restore or synchronization paths can leave a subject exposed. A hybrid audit agent is needed to use AI only for ambiguous evidence interpretation while deterministically reconstructing state, applying policy, and producing valid results for all 518 requests.

## What Changes

- Add a minimal TypeScript command-line audit agent that reads only participant-facing files under `dataset/` and writes a root-level `output.csv`.
- Add deterministic request parsing, authorization classification, current and historical identity resolution, and input/output validation.
- Add evidence indexing and time-bounded reconstruction across structured activity, manifest records, and evidence artifacts; use a single bounded LLM evidence investigator only when deterministic parsing cannot reliably normalize an eligible ambiguous artifact.
- Add policy-driven finding, remediation, and verification planning with contract-defined operations, evidence references, and stable ordering.
- Add sample-based evaluation, deterministic-only baseline comparison, LLM usage and unresolved-case reporting, full-dataset validation, and packaging documentation without hardcoded sample answers or unnecessary runtime services.

## Capabilities

### New Capabilities

- `deletion-request-auditing`: Classifies authorization, resolves the deletion subject, and generates one valid, ordered audit result per request.
- `evidence-state-reconstruction`: Retrieves linked participant-visible evidence and reconstructs resource and data-flow state as of an audit cutoff.
- `deletion-policy-planning`: Applies deletion rules to reconstructed state and creates compliant findings, remediation, and verification steps.
- `submission-evaluation`: Validates sample and full-dataset outputs and produces required evaluation and usage artifacts.

### Modified Capabilities

- None.

## Impact

- New TypeScript source and lightweight build/run configuration under `code/`.
- Root-level `output.csv` generated from `dataset/`; no framework, database service, external API, or organizer-only data.
- Updated README with reproducible TypeScript setup, run, validation, evaluation, and packaging instructions.
- New `code/evaluation/` reports for sample metrics, additional cases, failures/improvements, and token usage.
