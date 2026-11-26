"""Import a Nessus / OpenVAS report into a project (Phase 12).

Each report host that matches an existing non-CIDR target of the project
becomes one Scan, with one Asset, its Services and its Findings. The scan
enters the pipeline at CORRELATING; finish_import_task runs the same tail
as a VulnSight scan (KEV/EPSS, remediation sync, risk, report). Unmatched
hosts are skipped and listed: an import never creates a target.

Importing scans nothing, so target authorization is not required.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, ValidationConflictError
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan, ScanStatus
from app.models.service import Service
from app.models.target import Target, TargetType
from app.modules.importing.parsers import (
    ImportFormatError,
    ParsedHost,
    ParsedReport,
    parse_report,
)
from app.workers.tasks import finish_import_task

# Nessus gives no per-result confidence, so its imported findings get this
# fixed value (OpenVAS findings use the result's own QoD). First-pass
# judgment call, disclosed in the README: Nessus results are mostly
# remote version/banner checks, slightly below VulnSight's own probed
# nmap matches (which cluster near 100).
IMPORT_DEFAULT_CONFIDENCE = 90.0

MAX_SERVICE_NAME_LENGTH = 50

# Report scan times are bounded (prereg amendment 1): a future-dated file
# would otherwise push the remediation watermark and items' last
# evaluation into the future and freeze the target's remediation.
EARLIEST_SCAN_TIME = datetime(2000, 1, 1, tzinfo=UTC)
MAX_FUTURE_SKEW = timedelta(days=1)


def _norm(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    try:
        return ipaddress.ip_address(value).compressed  # 2001:0db8::0:1 == 2001:db8::1
    except ValueError:
        return value


def check_scan_times(report: ParsedReport, now: datetime) -> None:
    """Reject a host dated before 2000 or more than a day ahead; clamp a
    small future skew (clock drift, Nessus's timezone-less HOST_START read
    as UTC) to `now`."""
    for host in report.hosts:
        if host.scan_start < EARLIEST_SCAN_TIME or host.scan_start > now + MAX_FUTURE_SKEW:
            raise ValidationConflictError(
                f"Host {host.names[0][:100] if host.names else '?'!r} has an implausible "
                f"scan time ({host.scan_start.isoformat()})"
            )
        host.scan_start = min(host.scan_start, now)


def match_target(host: ParsedHost, targets: list[Target]) -> Target | None:
    """The project target a report host belongs to: its IP, report name or
    FQDN equal to the target value (case-insensitive, trailing dot ignored).
    IP targets win over hostname targets; CIDR targets never match."""
    names = {_norm(n) for n in host.names if n}
    ranked = sorted(
        (t for t in targets if t.target_type != TargetType.CIDR),
        key=lambda t: t.target_type != TargetType.IP,
    )
    for target in ranked:
        if _norm(target.value) in names:
            return target
    return None


def _host_label(host: ParsedHost) -> str:
    for name in host.names:
        try:
            ipaddress.ip_address(name)
            return name
        except ValueError:
            continue
    return host.names[0] if host.names else "?"


def import_report(db: Session, project_id: uuid.UUID, raw: bytes) -> dict:
    if db.get(Project, project_id) is None:
        raise NotFoundError(f"Project {project_id} not found")
    try:
        report = parse_report(raw)
    except ImportFormatError as exc:
        raise ValidationConflictError(str(exc)) from exc
    check_scan_times(report, datetime.now(UTC))

    targets = db.query(Target).filter(Target.project_id == project_id).all()
    scans: list[dict] = []
    skipped_hosts: list[str] = []
    findings_imported = 0
    for host in report.hosts:
        target = match_target(host, targets)
        if target is None:
            skipped_hosts.append(_host_label(host)[:255])
            continue
        scan, n = _persist_host(db, report, host, target)
        findings_imported += n
        scans.append({"scan_id": scan.id, "target_id": target.id, "host": _host_label(host)})
    db.commit()

    for entry in scans:
        finish_import_task.delay(str(entry["scan_id"]))

    return {
        "format": report.format,
        "scans": scans,
        "skipped_hosts": skipped_hosts,
        "findings_imported": findings_imported,
        "skipped_no_cve": report.skipped_no_cve,
        "skipped_informational": report.skipped_info,
        "dropped_invalid_cve": report.dropped_bad_cve,
    }


def _persist_host(
    db: Session, report: ParsedReport, host: ParsedHost, target: Target
) -> tuple[Scan, int]:
    source = report.format
    scan = Scan(
        project_id=target.project_id,
        target_id=target.id,
        status=ScanStatus.CORRELATING,
        config={"scanner": source, "import": True},
        # The report's own scan time, not the upload time: remediation sync
        # orders scans by created_at.
        created_at=host.scan_start,
        started_at=host.scan_start,
    )
    db.add(scan)
    db.flush()
    asset = Asset(
        project_id=target.project_id,
        target_id=target.id,
        scan_id=scan.id,
        host=_host_label(host)[:255],
    )
    db.add(asset)
    db.flush()

    services: dict[tuple[int, str], Service] = {}
    for (port, protocol), svc_name in host.ports.items():
        service = Service(
            asset_id=asset.id,
            port=port,
            protocol=protocol,
            state="open",
            service_name=svc_name[:MAX_SERVICE_NAME_LENGTH] if svc_name else None,
            fingerprint_source=source,
            evidence={"source": source},
        )
        db.add(service)
        services[(port, protocol)] = service
    db.flush()

    seen: set[tuple[uuid.UUID, str, str]] = set()
    count = 0
    for result in host.results:
        service = services[(result.port, result.protocol)]
        matched = f"import:{source}:{result.plugin_id}"[:255]
        for cve in result.cve_ids:
            key = (service.id, cve, matched)
            if key in seen:
                continue  # the same plugin/NVT reported twice for one port
            seen.add(key)
            db.add(
                Finding(
                    service_id=service.id,
                    cve_id=cve,
                    matched_cpe=matched,
                    severity=result.severity,
                    cvss_score=result.cvss,
                    cvss_vector=result.cvss_vector,
                    description=result.description or result.name or None,
                    evidence={
                        "scanner": source,
                        "plugin_id": result.plugin_id,
                        "plugin_name": result.name,
                        "scanner_severity": result.scanner_severity,
                        "qod": result.qod,
                    },
                    confidence_score=(
                        result.qod if result.qod is not None else IMPORT_DEFAULT_CONFIDENCE
                    ),
                    source=source,
                )
            )
            count += 1
    return scan, count
