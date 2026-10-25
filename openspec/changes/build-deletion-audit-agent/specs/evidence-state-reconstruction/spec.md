# Spec Delta

## Purpose

Reconstruct each subject's relevant record and data-flow state from visible evidence at the audit time.

## ADDED Requirements

### Requirement: Participant-visible evidence retrieval
The system SHALL inspect every manifest artifact captured at or before `audit_at` using deterministic extraction or a provenance-preserving opaque-artifact interpreter, and SHALL link relevant artifacts through resolved identifiers, resource identifiers, timestamps, and manifest metadata.

#### Scenario: Decoy artifact
- **WHEN** an evidence artifact cannot be linked to a subject through grounded data
- **THEN** the system excludes it from that subject's audit findings

#### Scenario: Opaque artifact exposes subject data
- **WHEN** a pre-cutoff PDF or image contains a resolved subject identifier and a record requiring deletion or redaction
- **THEN** the system associates its `file_id` with the subject and does not classify the case as `COMPLETE` until the record receives its required treatment

### Requirement: Temporal state reconstruction
The system SHALL order grounded state observations at or before `audit_at` by event time, apply the latest established observation per resource or flow, and treat reported workflow statuses and operation results as claims rather than proof.

#### Scenario: Later evidence capture
- **WHEN** an artifact was captured after a case's `audit_at`
- **THEN** the system does not use the artifact to determine that case's status

#### Scenario: Recreation after deletion
- **WHEN** evidence proves a record was deleted and a later pre-cutoff sync or restore recreated it
- **THEN** the reconstructed resource state is present and the case is not `COMPLETE`

### Requirement: Validated ambiguous-evidence investigation
The system SHALL invoke a bounded investigator only when deterministic extraction cannot normalize an eligible ambiguous artifact, SHALL accept only schema-valid evidence observations, and SHALL retain the source `file_id` and supporting location for accepted observations.

#### Scenario: Valid opaque-evidence extraction
- **WHEN** a gated investigator returns a schema-valid observation from a linked opaque artifact
- **THEN** the system normalizes the observation with its source provenance and applies deterministic identity, temporal, and policy logic

#### Scenario: Unresolved relevant evidence
- **WHEN** a relevant eligible artifact remains unresolved after deterministic extraction and one investigator retry
- **THEN** the system does not emit `COMPLETE` or fabricate an `INCOMPLETE` finding, records a case-scoped failure, and continues independent cases

### Requirement: Evidence-backed assertions
The system SHALL cite a valid participant-visible `file_id`, `activity_id`, or `audit_id` for every reported finding and for every verification step in a complete case.

#### Scenario: Unsupported claimed deletion
- **WHEN** activity claims a record was deleted but no qualifying evidence establishes the required state
- **THEN** the system does not use that claim alone as completion evidence
