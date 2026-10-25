# Spec Delta

## Purpose

Define reproducible per-request audit outputs from deletion requests and identity data.

## ADDED Requirements

### Requirement: Request and identity validation
The system SHALL read required CSV headers, reject malformed required records, resolve a request email against current and historical identity values, and retain every linked identifier for auditing.

#### Scenario: Historical email matches a subject
- **WHEN** a request email is an old value in the identity audit log
- **THEN** the system associates the request with that user and includes both historical and current identifiers in its evidence lookup

#### Scenario: Required input is malformed
- **WHEN** a required dataset file lacks a mandated header or a required request value is invalid
- **THEN** the run fails with a descriptive validation error and does not emit a success-shaped submission

### Requirement: Deletion authorization classification
The system SHALL produce `NOT_APPLICABLE` with `steps_json` equal to `[]` when request text does not authorize deletion.

#### Scenario: Access request
- **WHEN** request text asks only for a data copy or access
- **THEN** the case is `NOT_APPLICABLE` with no steps

#### Scenario: Verify a prior deletion
- **WHEN** request text explicitly asks whether an account, profile, or data deletion was completed
- **THEN** the system authorizes an audit of the deletion state, while generic account verification remains `NOT_APPLICABLE`

### Requirement: Contract-compliant output
The system SHALL produce exactly one row per input case, sorted by `case_id`, with the required columns and valid JSON steps numbered consecutively from one.

#### Scenario: Full request set
- **WHEN** all evaluation requests are processed successfully
- **THEN** the root-level output contains 518 sorted data rows with the exact required header
