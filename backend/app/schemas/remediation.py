import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.remediation import RemediationState


class RemediationItemRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    target_id: uuid.UUID
    port: int
    protocol: str
    cve_id: str
    severity: str
    cvss_score: float | None
    kev: bool | None
    state: RemediationState
    note: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    due_at: datetime
    state_changed_at: datetime
    fixed_at: datetime | None
    verified_at: datetime | None
    verification_reason: str | None
    reopened_count: int
    sources: list[str]
    simulated: bool


class RemediationUpdate(BaseModel):
    """Analyst transition. `verified` is never accepted here: only a rescan
    can verify. `note` is full-replace (None clears it)."""

    state: RemediationState
    note: str | None = None


class RemediationMetrics(BaseModel):
    total: int
    by_state: dict[str, int]
    unresolved_by_severity: dict[str, int]
    overdue_now: int
    sla_breach_pct: float | None
    mttr_days: float | None
    mttr_days_by_severity: dict[str, float | None]
    aging_unresolved: dict[str, int]
    simulated: bool
