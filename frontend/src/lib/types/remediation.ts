// Mirrors backend app/schemas/remediation.py (Phase 11).
export type RemediationState = "open" | "accepted" | "fixed" | "verified";

export interface RemediationItemRead {
  id: string;
  project_id: string;
  target_id: string;
  port: number;
  protocol: string;
  cve_id: string;
  severity: string;
  cvss_score: number | null;
  kev: boolean | null;
  state: RemediationState;
  note: string | null;
  first_seen_at: string;
  last_seen_at: string;
  due_at: string;
  state_changed_at: string;
  fixed_at: string | null;
  verified_at: string | null;
  // "cve_not_matched" | "service_not_observed" once verified.
  verification_reason: string | null;
  reopened_count: number;
  sources: string[];
  simulated: boolean;
}

export interface RemediationUpdate {
  state: RemediationState;
  note?: string | null;
}

export interface RemediationMetrics {
  total: number;
  by_state: Record<RemediationState, number>;
  unresolved_by_severity: Record<string, number>;
  overdue_now: number;
  sla_breach_pct: number | null;
  mttr_days: number | null;
  mttr_days_by_severity: Record<string, number | null>;
  aging_unresolved: Record<string, number>;
  simulated: boolean;
}
