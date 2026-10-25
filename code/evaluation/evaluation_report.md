# Evaluation Report

## Scope and measured runs

The solution was evaluated with the participant-facing dataset only. Gemini was disabled for the deterministic full-dataset run. The public sample run produced 32 predictions for 32 cases.

| Metric | Measured result |
| --- | ---: |
| Sample case/status accuracy | 32/32 (100.0%) |
| Sample step accuracy | 104/193 (53.9%) |
| Sample field accuracy | 910/1351 (67.4%) |
| Sample sequence accuracy | 11/32 (34.4%) |
| Deterministic full-dataset cases resolved | 503/518 |
| Deterministic full-dataset cases unresolved | 15/518 |

The full-dataset command intentionally did not write `output.csv`: the current CLI refuses to emit a submission when unresolved cases remain.

## Participant-created evaluation cases

These cases are independent focused fixtures in `src/evaluation_cases.test.ts`. They are run by the normal `npm test` command.

1. **Non-deletion request** — An export request is classified as `NOT_AUTHORIZED`, preventing an unauthorized deletion audit from being treated as a deletion case.
2. **Historical identity** — A request using `old@example.com` resolves to `user_history` and retains both the historical and current email aliases.
3. **Audit cutoff** — An observation captured after the cutoff is excluded even when its asserted event time is earlier, preventing later evidence from changing the historical answer.

All three cases passed in the measured 65-test run.

## Deterministic-only versus mocked hybrid investigation

Task 4.4 uses the ambiguous-PDF fixture in `src/hybrid_evaluation.test.ts`. The expected result is an `INCOMPLETE` row with one grounded remaining record, one remediation step, and one future verification step.

| Mode/fixture | Status accuracy | Step accuracy | Field accuracy | Sequence accuracy | Unresolved cases | Attempts/calls | Input/output tokens | Cache hits | Cost |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | --- |
| Deterministic-only, ambiguous PDF | 0/1 | 0/3 | 0/21 | 0/1 | 1 | 2 deterministic attempts | 0/0 | 0 | $0 model usage |
| Mocked hybrid, valid response | 1/1 | 3/3 | 21/21 | 1/1 | 0 | 1 model call | 17/9 | 0 | Unavailable |

The hybrid fixture improves the result from unresolved to the expected `INCOMPLETE` plan, but this is a mocked capability comparison, not evidence that a real model can safely resolve every opaque artifact.

Additional mocked failure-handling measurements:

| Fixture | Attempts | Outcome | Input/output tokens | Cache hits | Continuation |
| --- | ---: | --- | --- | ---: | --- |
| Invalid model response | 2 | Both recorded as `invalid`; case remains unresolved | 5/2 per attempt | 0 | Independent processing remains possible |
| Timeout/exception | 2 | Both recorded as `failed`; case remains unresolved | 0/0 per attempt | 0 | Failure is isolated to the case |
| Valid response repeated from cache | 1 model call + 1 cache hit | Both investigations accepted | 11/7, then 0/0 | 1 | Second request avoids another model call |

Costs for mocked calls are unavailable because no provider billing is involved. A deterministic PDF whose resource and identity are explicit remains deterministic-only and does not invoke the investigator, so hybrid mode provides no improvement or additional cost there.

## Development failures and improvements

- The initial deterministic pipeline resolved 474/518 cases. Investigation showed 29 parser failures in timestamp-prefixed JSON-lines, syslog, and event-oriented pipe logs.
- The existing parser was extended for those three formats without adding a separate component. The full regression suite increased from 57 to 65 tests, and deterministic resolution increased to 503/518.
- Gemini was tested once against `evidence_18`; the first response identified plausible identifiers/resources but failed Zod validation because it returned `inspected`, `active`, and `delivered` values outside the contract.
- The Gemini request was then tightened with SDK structured JSON output, explicit allowed states, and grounding rules that distinguish business statuses such as `delivered` from deletion/resource states.
- One subsequent direct Gemini call returned a schema-valid `UNRESOLVED` response with no observations. The document explicitly contains customer and order identifiers, but does not establish an allowed deletion state or fully specified event timestamps. `case_33` therefore remains unresolved.
- The remaining 14 cases were reviewed against all identities, audit history, system activity, manifest entries, resource links, and cutoff timestamps. No safe participant-visible state evidence was found. Later-captured artifacts were not used to establish earlier state.

## Limitations

Fifteen cases remain unresolved because the supplied evidence does not establish enough state at `audit_at`. The implementation remains fail-closed: it does not convert missing proof into `COMPLETE`, invent an `INCOMPLETE` finding, use later-captured evidence, or fabricate resource states. Consequently, final 518-row output generation and the zero-unresolved full-run requirement remain blocked until the evidence limitation is addressed.

## Reproducibility

Run the focused and regression tests with:

```text
npm test
```

Run the public sample evaluation with:

```text
npm run evaluate
```
