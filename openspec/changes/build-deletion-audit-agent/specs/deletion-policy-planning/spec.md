# Spec Delta

## Purpose

Apply deletion rules to reconstructed records and generate ordered, policy-compliant audit plans.

## ADDED Requirements

### Requirement: Policy-conformant treatment
The system SHALL apply the matching deletion rule to every relevant record and preserve records required to remain while removing prohibited direct identifiers.

#### Scenario: Account tombstone
- **WHEN** a tombstone is retained under a redaction rule
- **THEN** the plan preserves the stable subject reference and requires prohibited direct identifiers to be redacted

### Requirement: Incomplete-case planning
The system SHALL report every evidence-backed policy violation and recreation risk, then create remediation and future verification steps with empty `evidence_id` values.

#### Scenario: Active synchronization risk
- **WHEN** an active process can recreate the subject's prohibited data
- **THEN** the plan reports the active flow, disables it before dependent record changes, and verifies the disabled state

### Requirement: Complete-case planning
The system SHALL mark an authorized request complete only when all relevant copies have their required treatment, required retained records remain, every eligible pre-cutoff evidence artifact has been examined, and the final reconstructed state has no recreated data, active flow, or restore risk.

#### Scenario: Compliant state
- **WHEN** evidence proves each required final state at the audit cutoff
- **THEN** the result is `COMPLETE` and contains only evidence-backed verification steps

#### Scenario: Recreated record blocks completion
- **WHEN** a later pre-cutoff sync or restore recreates a previously deleted record
- **THEN** the result is `INCOMPLETE` with the applicable remaining-record or recreation-risk finding and ordered remediation and verification steps

### Requirement: Deterministic step ordering
The system SHALL order steps by phase, operation order, `system_id`, and `resource_id`, using only contract-defined operations and states.

#### Scenario: Multiple findings and remedies
- **WHEN** a case has several records and risks
- **THEN** its serialized steps follow the prescribed phase and in-phase ordering with consecutive step numbers
