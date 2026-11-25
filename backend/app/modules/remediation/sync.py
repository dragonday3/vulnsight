"""Rescan sync for the remediation lifecycle (Phase 11).

Runs once per nmap scan, inside the existing CORRELATING stage (no new
pipeline stage), after findings are written and enriched. It turns this
scan's findings into persistent RemediationItem rows for the target:
- a finding seen now upserts its item (new = open); a verified item that
  reappears is reopened, and a "fixed" claim the rescan contradicts goes
  back to open;
- a tracked item this scan no longer finds becomes verified, but only
  when the rescan can be trusted (see `_absence_is_trustworthy`).

Never raises and never touches scan.status: remediation tracking is
best-effort like every stage after discovery.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models.finding import Finding, FindingValidationState
from app.models.remediation import RemediationItem, RemediationState
from app.models.scan import Scan
from app.models.service import Service
from app.modules.remediation.config import KEV_SLA_DAYS, SLA_DAYS, SLA_DAYS_DEFAULT
from app.modules.vulnerability.finding_dedup import dedupe_findings_by_cve

logger = logging.getLogger(__name__)

Key = tuple[int, str, str]  # (port, protocol, cve_id)

_UNRESOLVED_OR_ACCEPTED = {
    RemediationState.OPEN,
    RemediationState.ACCEPTED,
    RemediationState.FIXED,
}


def sla_due(first_seen: datetime, severity: str, kev: bool | None) -> datetime:
    """Remediation deadline: first sighting + the severity's SLA days,
    capped at KEV_SLA_DAYS when the CVE is in CISA KEV. Pure."""
    days = SLA_DAYS.get(severity, SLA_DAYS_DEFAULT)
    if kev:
        days = min(days, KEV_SLA_DAYS)
    return first_seen + timedelta(days=days)


SERVICE_NOT_OBSERVED = "service_not_observed"
CVE_NOT_MATCHED = "cve_not_matched"


def verification_reason(key: Key, services_by_port: dict, scan: Scan) -> str | None:
    """Why a tracked CVE missing from this scan counts as gone, or None if
    the scan can't tell:
    - SERVICE_NOT_OBSERVED: its port is no longer open;
    - CVE_NOT_MATCHED: the port is open, the service still has CPE
      evidence (so CVEs were looked up), and every CVE lookup in this scan
      completed.
    Otherwise (no fingerprint, a failed or truncated lookup) absence proves
    nothing: Phase 9 showed a failed lookup looks exactly like "no CVEs".
    """
    service = services_by_port.get((key[0], key[1]))
    if service is None:
        return SERVICE_NOT_OBSERVED
    has_cpe = bool((service.evidence or {}).get("cpe"))
    if has_cpe and scan.cve_lookups_failed == 0:
        return CVE_NOT_MATCHED
    return None


def sync_remediation(db: Session, scan: Scan, services: list[Service]) -> dict[str, int]:
    """Upsert this scan's findings into the target's remediation items and
    verify the ones a trustworthy rescan no longer finds. Returns counts
    (created, updated, reopened, verified). Never raises."""
    counts = {"created": 0, "updated": 0, "reopened": 0, "verified": 0}
    try:
        if scan.config.get("scanner") != "nmap":
            # Native scans have no CPE evidence, so no findings and no way to
            # judge absence; they never create or close remediation items.
            return counts

        now = datetime.now(UTC)
        seen_at = scan.created_at or now
        services_by_port = {(s.port, s.protocol): s for s in services}

        present: dict[Key, Finding] = {}
        for service in services:
            real = [
                f
                for f in service.findings
                if f.validation_state != FindingValidationState.FALSE_POSITIVE
            ]
            for finding in dedupe_findings_by_cve(real):
                present[(service.port, service.protocol, finding.cve_id)] = finding

        items = {
            (i.port, i.protocol, i.cve_id): i
            for i in db.query(RemediationItem)
            .filter(RemediationItem.target_id == scan.target_id)
            .all()
        }

        for key, finding in present.items():
            item = items.get(key)
            if item is None:
                db.add(
                    RemediationItem(
                        project_id=scan.project_id,
                        target_id=scan.target_id,
                        port=key[0],
                        protocol=key[1],
                        cve_id=key[2],
                        severity=finding.severity,
                        cvss_score=finding.cvss_score,
                        kev=finding.kev,
                        state=RemediationState.OPEN,
                        first_seen_at=seen_at,
                        first_seen_scan_id=scan.id,
                        last_seen_at=seen_at,
                        last_seen_scan_id=scan.id,
                        due_at=sla_due(seen_at, finding.severity, finding.kev),
                        state_changed_at=now,
                    )
                )
                counts["created"] += 1
                continue

            item.severity = finding.severity
            item.cvss_score = finding.cvss_score
            if finding.kev is not None:
                item.kev = finding.kev
            item.last_seen_at = seen_at
            item.last_seen_scan_id = scan.id
            # Deadlines only ever tighten (e.g. the CVE was added to KEV).
            item.due_at = min(item.due_at, sla_due(item.first_seen_at, item.severity, item.kev))
            if item.state == RemediationState.VERIFIED:
                item.state = RemediationState.OPEN
                item.verified_at = None
                item.verified_scan_id = None
                item.verification_reason = None
                item.fixed_at = None
                item.reopened_count += 1
                item.state_changed_at = now
                counts["reopened"] += 1
            elif item.state == RemediationState.FIXED:
                # The analyst's fix claim is contradicted by this rescan.
                item.state = RemediationState.OPEN
                item.fixed_at = None
                item.state_changed_at = now
                counts["reopened"] += 1
            else:
                counts["updated"] += 1

        for key, item in items.items():
            if key in present or item.state not in _UNRESOLVED_OR_ACCEPTED:
                continue
            reason = verification_reason(key, services_by_port, scan)
            if reason is None:
                continue
            item.state = RemediationState.VERIFIED
            item.verification_reason = reason
            item.verified_at = now
            item.verified_scan_id = scan.id
            item.fixed_at = item.fixed_at or now
            item.state_changed_at = now
            counts["verified"] += 1

        db.commit()
        return counts
    except Exception:
        db.rollback()
        logger.exception("sync_remediation: remediation sync failed for scan %s", scan.id)
        return counts
