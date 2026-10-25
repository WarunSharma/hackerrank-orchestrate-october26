# Design

## Context

See `proposal.md` for motivation. The public corpus contains CSV inputs plus 94 evidence artifacts across JSON, logs, SQL, PDFs, images, and text. The solution must emit one deterministic, contract-valid row for each of 518 requests without organizer-only data, external services, or hardcoded answers.

## Goals / Non-Goals

**Goals:**

- Provide a small TypeScript CLI with a reproducible full-dataset run.
- Resolve identity aliases, link evidence, reconstruct state at `audit_at`, apply policy, and serialize exact ordered steps.
- Make every output assertion traceable to a participant-visible evidence identifier.
- Evaluate against public samples and document final-run usage.

**Non-Goals:**

- A UI, persistent database, multi-agent workflow, or unbounded LLM access.
- Treating workflow claims, report statuses, or manifest rows alone as proof.
- Inferring facts from inaccessible binary evidence without a supported interpreter.

## Decisions

### Staged in-memory TypeScript pipeline

Use standard-library CSV/file handling and typed domain records:

```text
CSV + evidence files
        |
        v
validate --> identity alias index --> evidence index
                                      |
                                      v
request authorization --> time-bounded case reconstruction
                                      |
                                      v
policy evaluation --> ordered plan --> output.csv + reports
```

This keeps the run inspectable and deterministic for a corpus of this size. A database adds operational surface without a demonstrated need.

### Evidence adapters with provenance

Inspect every manifest artifact captured by the audit cutoff. Parse CSV, JSON, text/log, and SQLite-compatible SQL deterministically into normalized observations carrying source identifier, capture/event time, system, resource, linked tokens, and asserted state. Use one `EvidenceInvestigator` model call only when an eligible PDF, image, or ambiguous unstructured text cannot reliably yield facts through deterministic extraction.

The investigator receives a bounded packet: `file_id`, manifest metadata, artifact content, cutoff, resolved aliases/hashes, deterministic extraction, and an allowed-fact vocabulary. It has no tools or filesystem, network, policy, or output-writing access. Its Zod-validated response contains `inspection_status`, extracted identifier matches, observations with fact type/system/resource/event time/verbatim location/confidence, and `unresolved_reason`; it cannot return deletion status or a plan. Cache valid responses by content hash, prompt version, and model.

Alternative: send every case and corpus to an LLM. Rejected because it increases cost, weakens reproducibility, and risks unsupported citations.

### Failure isolation and accounting

Use deterministic evidence when available regardless of model outcome. Retry one transient or schema-invalid model response. If a relevant opaque artifact remains unresolved and no deterministic evidence establishes its facts, record a case-scoped diagnostic, omit that case result, continue processing independent cases, and fail final submission validation rather than emit `COMPLETE` or invent an `INCOMPLETE` finding. Missing global inputs, invalid schemas, or output-writer failures are run-level fatal errors.

Record provider/model, input/output tokens, estimated cost, latency, cache hit, and outcome for every call. Compare the hybrid path with a zero-call deterministic-only baseline on output accuracy, unresolved-case rate, calls, tokens, and cost.

### Event-sourced reconstruction at the audit cutoff

Build each subject's token set from current identity plus all historical values. Match observations with those tokens or grounded resource links, discard observations later than `audit_at`, then reduce each resource and flow by ordered grounded event time. A later sync, import, or restore that establishes data presence supersedes an earlier delete for that resource; active flows and restore paths remain independent completion blockers. Reported statuses remain non-authoritative inputs.

Alternative: use the request's reported status as the baseline. Rejected because the contract explicitly calls it a claim.

### Rule-driven planning and canonical sorting

Map normalized categories and state to deletion rules, then emit only allowed operations/states. Generate flows and restore controls before dependent record remediation; use contract-prescribed phase and operation ranks plus lexical system/resource ordering. Renumber after sorting and JSON-serialize deterministically.

Alternative: encode case patterns or sample answers. Rejected because it fails unseen cases and violates the submission rules.

### Separate validation and evaluation paths

Validate raw inputs before processing and validate every generated row before writing. A sample command compares structural and semantic fields against public answers; a production command generates all evaluation rows, checks the 518-row contract, and writes reports from measured results and recorded zero/nonzero LLM usage.

## Risks / Trade-offs

- [Opaque PDFs or images contain decisive facts] -> Examine every eligible artifact; use the isolated interpreter only where deterministic extraction is insufficient and preserve `file_id`, extracted identifiers, time, and confidence.
- [Model output is invalid or unavailable] -> Retry once, use deterministic facts when sufficient, otherwise isolate the case and fail submission validation without fabricating an output row.
- [SQL dialect or large artifact variance] -> Support the supplied SQLite-compatible form first and fail clearly for unsupported structures.
- [Identity collisions or reused identifiers] -> Require a grounded match using multiple tokens, resource links, or time-consistent audit history before associating evidence.
- [Incorrect dependency order] -> Model flows/restores as blockers and assert ordering in focused tests.
- [Sample overfitting] -> Use samples only as regression fixtures; add independent participant-created cases.

## Migration Plan

1. Add the TypeScript CLI and documented run command without changing participant data.
2. Run validation and public-sample evaluation.
3. Generate root `output.csv`, then generate evaluation and usage reports from that run.
4. Package code and reports only; rollback is removal of generated artifacts because no service or data migration is introduced.
