"""Remediation lifecycle (Phase 11): one persistent item per vulnerable
(target, port, protocol, CVE), surviving across scans.

`Finding` rows belong to one scan; a `RemediationItem` is the cross-scan
identity an analyst tracks to closure. States:
- open: seen and unresolved;
- accepted: risk accepted by an analyst (note holds the reason);
- fixed: an analyst claims it is fixed (not yet confirmed);
- verified: a trustworthy rescan no longer finds it (set only by
  modules/remediation/sync.py, never by the API).
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base_class import Base


class RemediationState(str, enum.Enum):
    OPEN = "open"
    ACCEPTED = "accepted"
    FIXED = "fixed"
    VERIFIED = "verified"


class RemediationItem(Base):
    __tablename__ = "remediation_items"
    __table_args__ = (
        UniqueConstraint(
            "target_id", "port", "protocol", "cve_id", name="uq_remediation_target_port_cve"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(20), nullable=False)

    # Snapshot from the latest sighting.
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    state: Mapped[RemediationState] = mapped_column(
        Enum(
            RemediationState,
            name="remediation_state",
            values_callable=lambda enum_cls: [e.value for e in enum_cls],
        ),
        default=RemediationState.OPEN,
        nullable=False,
    )
    # Analyst note (e.g. the risk-acceptance reason). Full-replace on every
    # PATCH, same as Finding.validation_note.
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    # first_seen + SLA days for the severity (14 if in KEV). Only ever
    # tightened later (e.g. the CVE joins KEV), never extended.
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Analyst's fix claim, or the verification time if nobody claimed one.
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    # Why the rescan verified it: "cve_not_matched" (service still there, the
    # completed rescan no longer matches the CVE) or "service_not_observed"
    # (the port is no longer open: weaker evidence, a service that is down
    # looks the same).
    verification_reason: Mapped[str | None] = mapped_column(String(30), nullable=True)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Phase 12: every source that has reported this item ("vulnsight",
    # "nessus", "openvas"). A VulnSight rescan may verify by "CVE not
    # matched" only if "vulnsight" is among them.
    sources: Mapped[list] = mapped_column(
        JSONB,
        default=lambda: ["vulnsight"],
        server_default=text("'[\"vulnsight\"]'::jsonb"),
        nullable=False,
    )
    # Phase 12 race fix: scan time of the newest scan that saw or verified
    # this item. No older scan may change it.
    last_evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Seeded demo data (scripts/seed_simulated_remediation.py). Never real.
    simulated: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false", nullable=False
    )
