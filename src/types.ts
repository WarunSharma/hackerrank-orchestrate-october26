export type DeletionStatus = "COMPLETE" | "INCOMPLETE" | "NOT_APPLICABLE";
export type Phase = "FINDING" | "REMEDIATION" | "VERIFICATION";

export interface DeletionRequest {
  case_id: string;
  email: string;
  requested_at: string;
  reported_status: string;
  reported_at: string;
  audit_at: string;
  request_text: string;
}

export interface AuditStep {
  step_no: number;
  phase: Phase;
  system_id: string;
  resource_id: string;
  operation: string;
  state: string;
  evidence_id: string;
}

export interface AuditResult {
  case_id: string;
  deletion_status: DeletionStatus;
  steps_json: AuditStep[];
}
