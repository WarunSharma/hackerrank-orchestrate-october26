# Usage Report

## Scope

This report separates the two manually executed Gemini investigations from deterministic pipeline runs. It does not infer historical usage that was not persisted by the application.

The eventual final 518-case submission run has not occurred: the deterministic pipeline currently resolves 503 cases and refuses to write `output.csv` while 15 cases remain unresolved.

## Recorded manual Gemini experiments

Both experiments used the `GeminiEvidenceInvestigator` against `evidence_18` for `case_33`. Both used model `gemini-3.8-flash` and were direct investigation calls, so they bypassed the application cache.

| Experiment | Outcome | API calls | Model | Input tokens | Output tokens | Total tokens | Cache hits | Estimated cost |
| --- | --- | ---: | --- | ---: | ---: | ---: | ---: | --- |
| Initial controlled investigation | Invalid response; Zod rejected `inspected`, `active`, and `delivered` | 1 | `gemini-3.8-flash` | 1,284 | 399 | 1,683 | 0 | Unavailable |
| Structured-output retry | Zod-valid `UNRESOLVED`; no observations accepted | 1 | `gemini-3.8-flash` | 1,377 | 104 | 1,481 | 0 | Unavailable |
| **Recorded manual total** |  | **2** | `gemini-3.8-flash` | **2,661** | **503** | **3,164** | **0** | **Unavailable** |

The provider/model pricing configuration and currency were not recorded, so total cost and per-request cost cannot be calculated reliably. No cost estimate is invented here.

For the two recorded manual requests, the average was **1,330.5 input tokens**, **251.5 output tokens**, and **1,582 total tokens** per request. Average cost per request is **Unavailable**.

### Recorded provider/model totals

| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Average total/request | Cache hits | Total cost | Average cost/request |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| Google Gemini API | `gemini-3.8-flash` | 2 | 2,661 | 503 | 3,164 | 1,582 | 0 | Unavailable | Unavailable |
| **Overall recorded manual usage** |  | **2** | **2,661** | **503** | **3,164** | **1,582** | **0** | **Unavailable** | **Unavailable** |

## Deterministic pipeline runs

Gemini was disabled for the measured pipeline runs. The pipeline used `NoopEvidenceInvestigator`; therefore these measured runs made no Gemini API calls and consumed no Gemini input/output tokens.

| Run | Cases | Gemini calls | Input tokens | Output tokens | Cache hits | Gemini estimated cost | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- | --- |
| Public sample evaluation | 32 | 0 | 0 | 0 | 0 | $0 model usage | 32 predictions; 100.0% status accuracy |
| Full deterministic resolution measurement | 518 | 0 | 0 | 0 | 0 | $0 model usage | 503 resolved; 15 unresolved; no output written |

The repository does not persist a historical ledger for every prior test, build, or development run. Aggregate counts for unrecorded historical deterministic runs, wall-clock cost, and non-Gemini infrastructure cost are **unavailable**, not assumed to be zero.

For the measured deterministic runs, average Gemini tokens and Gemini cost per case are **0** because the configured investigator made no model calls. This does not estimate CPU, electricity, or other infrastructure costs.

## Existing tracking and final-run procedure

`src/investigator.ts` records one `UsageRecord` per investigation attempt with provider, model, file ID, attempt number, outcome, cache-hit status, input tokens, and output tokens. `newUsageTracker()` creates the in-memory ledger used by `generateRows()`. Cache hits record zero model tokens; SDK responses populate token counts from `usageMetadata`.

For the eventual final 518-case run, the pipeline should:

1. Create one usage tracker before `generateRows()`.
2. Preserve the tracker through all case investigations, including retries, failures, and cache hits.
3. Aggregate records by provider/model and overall:
   - API calls and attempts
   - accepted, invalid, and failed outcomes
   - cache hits
   - input, output, and total tokens
   - estimated cost using the configured provider price sheet
   - unresolved-case count
4. Write those measured totals to this report only after the run completes. If pricing or a usage field is missing, record `Unavailable` rather than infer it.

No final 518-case usage ledger exists yet because unresolved cases currently prevent final output generation.
