# Spec Delta

## Purpose

Provide reproducible sample and full-run validation plus required evaluation and usage reports for submission.

## ADDED Requirements

### Requirement: Sample evaluation
The system SHALL compare generated sample results with `sample_output.csv` and report case status, step, field, and sequence accuracy.

#### Scenario: Sample mismatch
- **WHEN** a generated sample row differs from its expected output
- **THEN** the evaluation report identifies the failed case and affected result dimension

### Requirement: Additional evaluation coverage
The system SHALL document at least three participant-created evaluation cases that exercise authorization, historical identity, evidence timing, or policy planning behavior.

#### Scenario: Report generation
- **WHEN** evaluation artifacts are prepared
- **THEN** the evaluation report includes three or more additional cases and recorded failures and improvements

### Requirement: Usage and packaging safeguards
The system SHALL produce a usage report for the full-dataset output run with model-call, token, cost, cache, and unresolved-case totals, and SHALL document packaging that excludes datasets, dependencies, nested archives, credentials, and sensitive configuration.

#### Scenario: Deterministic-only run
- **WHEN** the final run makes no model calls
- **THEN** the usage report records zero calls and zero token and estimated-cost totals

### Requirement: Hybrid baseline comparison
The system SHALL compare deterministic-only and hybrid investigation modes using status, step, field, sequence, unresolved-case, call, token, and estimated-cost metrics.

#### Scenario: Opaque-evidence fixture
- **WHEN** a focused fixture requires valid opaque-evidence interpretation
- **THEN** the evaluation report records the deterministic-only and hybrid outcomes and their respective resource usage

#### Scenario: Unresolved-case fixture
- **WHEN** an investigator response remains invalid or unavailable for relevant evidence
- **THEN** the evaluation report records the case failure, confirms no `COMPLETE` output was emitted, and confirms independent cases continued
