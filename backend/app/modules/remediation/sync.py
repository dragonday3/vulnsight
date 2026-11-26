"""Rescan sync for the remediation lifecycle (Phase 11).

Runs once per nmap scan or imported report (Phase 12), inside the
existing CORRELATING stage (no new pipeline stage), after findings are
written and enriched. It turns this scan's findings into persistent
RemediationItem rows for the target:
- a finding seen now upserts its item (new = open); a verified item that
  reappears is reopened, and a "fixed" claim the rescan contradicts goes
  back to open;
- a tracked item this scan no longer finds becomes verified, but only
  when the rescan can be trusted (see `verification_reason`), and only
  by a VulnSight scan: an import never verifies anything.

Ordering (Phase 12 race fix): the target row is locked for the whole
sync, so syncs of one target are serialized; a scan older than the newest
synced scan of the same source is skipped as stale; and no scan older
than an item's `last_evaluated_at` may change that item.

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
from app.models.target import Target
from app.modules.remediation.config import KEV_SLA_DAYS, SLA_DAYS, SLA_DAYS_DEFAULT
from app.modules.vulnerability import cpe_utils
from app.modules.vulnerability.correlator import _is_versionless_cpe23
from app.modules.vulnerability.finding_dedup import dedupe_findings_by_cve

logger = logging.getLogger(__name__)

Key = tuple[int, str, str]  # (port, protocol, cve_id)

VULNSIGHT = "vulnsight"
# Scan.config["scanner"] -> remediation source. Anything else (the native
# scanner: no CPE evidence, so no findings and no way to judge absence)
# never creates or closes remediation items.
_SOURCES = {"nmap": VULNSIGHT, "nessus": "nessus", "openvas": "openvas"}

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


def scan_source(scan: Scan) -> str | None:
    config = scan.config or {}
    source = _SOURCES.get(str(config.get("scanner")))
    # An import source only counts on a scan the import service created
    # (POST /scans refuses the "import" key).
    if source not in (None, VULNSIGHT) and config.get("import") is not True:
        return None
    return source


def may_change(item_last_evaluated: datetime, seen_at: datetime) -> bool:
    """A scan may change an item only if it is not older than the newest
    scan that already saw or verified it. Pure."""
    return seen_at >= item_last_evaluated


def verification_reason(
    key: Key, services_by_port: dict, scan: Scan, item_sources: list[str] | None = None
) -> str | None:
    """Why a tracked CVE missing from this scan counts as gone, or None if
    the scan can't tell:
    - SERVICE_NOT_OBSERVED: its port is no longer open, while the host
      still shows at least one open port (a host with nothing open is more
      likely down or firewalled than fixed, so it verifies nothing);
    - CVE_NOT_MATCHED: the port is open, the service has a CPE the
      correlator actually looks up (converted and versioned), and every
      CVE lookup in this scan completed.
    Otherwise (no usable fingerprint, a failed or truncated lookup) absence
    proves nothing: Phase 9 showed a failed lookup looks exactly like "no
    CVEs".

    Phase 12: port 0 (Nessus's host-level checks) is never "not observed",
    since nmap can't observe it; and CVE_NOT_MATCHED needs "vulnsight"
    among the item's sources, since VulnSight's silence about a CVE only
    an imported scanner can detect proves nothing.
    """
    service = services_by_port.get((key[0], key[1]))
    if service is None:
        return SERVICE_NOT_OBSERVED if services_by_port and key[0] > 0 else None
    if (
        VULNSIGHT in (item_sources if item_sources is not None else [VULNSIGHT])
        and _has_looked_up_cpe(service)
        and scan.cve_lookups_failed == 0
    ):
        return CVE_NOT_MATCHED
    return None


def _has_looked_up_cpe(service: Service) -> bool:
    """Same filter as the correlator: a CPE that converts to 2.3 and has a
    version. A version-less or unconvertible CPE is skipped there without
    counting as a failed lookup, so it must not count as a check here."""
    for cpe22 in (service.evidence or {}).get("cpe") or []:
        cpe23 = cpe_utils.to_cpe23(cpe22)
        if cpe23 is not None and not _is_versionless_cpe23(cpe23):
            return True
    return False


def sync_remediation(db: Session, scan: Scan, services: list[Service]) -> dict[str, int]:
    """Upsert this scan's findings into the target's remediation items and
    verify the ones a trustworthy rescan no longer finds. Returns counts
    (created, updated, reopened, verified, stale). Never raises."""
    counts = {"created": 0, "updated": 0, "reopened": 0, "verified": 0, "stale": 0}
    try:
        source = scan_source(scan)
        if source is None:
            return counts

        now = datetime.now(UTC)
        seen_at = scan.created_at or now

        # Serialize syncs of this target: the row lock is held until the
        # commit (or rollback) below.
        target = (
            db.query(Target)
            .filter(Target.id == scan.target_id)
            .with_for_update()
            .populate_existing()
            .one()
        )
        watermarks = dict(target.remediation_watermarks or {})
        mark = watermarks.get(source)
        if mark is not None and seen_at < datetime.fromisoformat(mark):
            counts["stale"] = 1
            db.rollback()  # release the lock
            logger.info(
                "sync_remediation: scan %s is older than the newest synced %s scan; skipped",
                scan.id,
                source,
            )
            return counts
        watermarks[source] = seen_at.isoformat()
        target.remediation_watermarks = watermarks  # new dict, so the JSONB change is tracked

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
            .with_for_update()
            .populate_existing()
            .all()
        }

        for key, finding in present.items():
            item = items.get(key)
            if item is not None and not may_change(item.last_evaluated_at, seen_at):
                continue  # a newer scan already saw or verified it
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
                        sources=[source],
                        last_evaluated_at=seen_at,
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
            item.last_evaluated_at = seen_at
            if source not in item.sources:
                item.sources = [*item.sources, source]  # new list, so the JSONB change is tracked
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
            if source != VULNSIGHT:
                break  # an import never verifies: absence from an export isn't a fix
            if key in present or item.state not in _UNRESOLVED_OR_ACCEPTED:
                continue
            if not may_change(item.last_evaluated_at, seen_at):
                continue  # an older scan can't verify what a newer one saw
            reason = verification_reason(key, services_by_port, scan, item.sources)
            if reason is None:
                continue
            item.last_evaluated_at = seen_at
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
