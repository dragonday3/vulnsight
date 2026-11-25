"""Phase 11 remediation lifecycle: rescan sync, SLA, metrics and the API."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding, FindingValidationState
from app.models.project import Project
from app.models.remediation import RemediationItem, RemediationState
from app.models.scan import Scan, ScanStatus
from app.models.service import Service
from app.models.target import Target, TargetType
from app.modules.remediation import metrics
from app.modules.remediation.sync import (
    CVE_NOT_MATCHED,
    SERVICE_NOT_OBSERVED,
    sla_due,
    sync_remediation,
)

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _target(db: Session) -> Target:
    project = Project(name="Remediation Test")
    db.add(project)
    db.flush()
    target = Target(
        project_id=project.id,
        value="bench-upgrade",
        target_type=TargetType.HOSTNAME,
        authorization_confirmed=True,
    )
    db.add(target)
    db.commit()
    return target


def _scan(
    db: Session,
    target: Target,
    services: dict[int, list[str] | None],
    *,
    scanner: str = "nmap",
    lookups_failed: int = 0,
    created: datetime = T0,
    cpe: bool = True,
    findings_state: dict[str, FindingValidationState] | None = None,
) -> tuple[Scan, list[Service]]:
    """A completed scan of `target` whose services (port -> CVE ids, or None
    for a service without findings) are persisted like run_scan_task does."""
    scan = Scan(
        project_id=target.project_id,
        target_id=target.id,
        status=ScanStatus.CORRELATING,
        config={"scanner": scanner},
        created_at=created,
        cve_lookups_total=1,
        cve_lookups_failed=lookups_failed,
    )
    db.add(scan)
    db.flush()
    asset = Asset(
        project_id=target.project_id, target_id=target.id, scan_id=scan.id, host=target.value
    )
    db.add(asset)
    db.flush()
    rows = []
    for port, cves in services.items():
        service = Service(
            asset_id=asset.id,
            port=port,
            protocol="tcp",
            state="open",
            evidence={"cpe": ["cpe:/a:apache:http_server:2.4.49"]} if cpe else {},
        )
        db.add(service)
        db.flush()
        for cve in cves or []:
            db.add(
                Finding(
                    service_id=service.id,
                    cve_id=cve,
                    matched_cpe="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                    severity="CRITICAL",
                    cvss_score=9.8,
                    evidence={},
                    confidence_score=100.0,
                    kev=cve == "CVE-KEV",
                    validation_state=(findings_state or {}).get(
                        cve, FindingValidationState.UNVALIDATED
                    ),
                )
            )
        rows.append(service)
    db.commit()
    for service in rows:
        db.refresh(service)
    return scan, rows


def _items(db: Session, target: Target) -> dict[str, RemediationItem]:
    db.expire_all()
    return {
        i.cve_id: i
        for i in db.query(RemediationItem).filter(RemediationItem.target_id == target.id)
    }


# --- SLA -------------------------------------------------------------------


def test_sla_by_severity_and_kev_cap() -> None:
    assert sla_due(T0, "CRITICAL", False) == T0 + timedelta(days=15)
    assert sla_due(T0, "HIGH", None) == T0 + timedelta(days=30)
    assert sla_due(T0, "MEDIUM", False) == T0 + timedelta(days=90)
    assert sla_due(T0, "LOW", False) == T0 + timedelta(days=180)
    assert sla_due(T0, "NONE", False) == T0 + timedelta(days=180)
    assert sla_due(T0, "LOW", True) == T0 + timedelta(days=14)  # KEV cap


# --- sync ------------------------------------------------------------------


def test_first_scan_creates_open_items_with_deadlines(db: Session) -> None:
    target = _target(db)
    scan, services = _scan(db, target, {80: ["CVE-A", "CVE-KEV"]})
    counts = sync_remediation(db, scan, services)
    items = _items(db, target)
    assert counts["created"] == 2
    assert items["CVE-A"].state == RemediationState.OPEN
    assert items["CVE-A"].due_at == T0 + timedelta(days=15)
    assert items["CVE-KEV"].due_at == T0 + timedelta(days=14)


def test_complete_rescan_verifies_missing_cve_and_keeps_present_one(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A", "CVE-B"]})
    sync_remediation(db, s1, sv1)
    s2, sv2 = _scan(db, target, {80: ["CVE-B"]}, created=T0 + timedelta(days=3))
    counts = sync_remediation(db, s2, sv2)
    items = _items(db, target)
    assert counts["verified"] == 1
    assert items["CVE-A"].state == RemediationState.VERIFIED
    assert items["CVE-A"].verification_reason == CVE_NOT_MATCHED
    assert items["CVE-A"].verified_scan_id == s2.id
    assert items["CVE-B"].state == RemediationState.OPEN
    assert items["CVE-B"].last_seen_scan_id == s2.id


def test_closed_port_verifies_with_weaker_reason(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, s1, sv1)
    s2, sv2 = _scan(db, target, {22: None})  # port 80 no longer open
    sync_remediation(db, s2, sv2)
    item = _items(db, target)["CVE-A"]
    assert item.state == RemediationState.VERIFIED
    assert item.verification_reason == SERVICE_NOT_OBSERVED


def test_incomplete_rescan_changes_nothing(db: Session) -> None:
    """The Phase 9 lesson: a failed CVE lookup looks exactly like "no CVEs",
    so a rescan with any failed lookup must not verify anything."""
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A", "CVE-B"]})
    sync_remediation(db, s1, sv1)
    s2, sv2 = _scan(db, target, {80: None}, lookups_failed=1)
    counts = sync_remediation(db, s2, sv2)
    assert counts["verified"] == 0
    assert {i.state for i in _items(db, target).values()} == {RemediationState.OPEN}


def test_service_without_cpe_evidence_cannot_verify(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, s1, sv1)
    s2, sv2 = _scan(db, target, {80: None}, cpe=False)  # fingerprint lost
    sync_remediation(db, s2, sv2)
    assert _items(db, target)["CVE-A"].state == RemediationState.OPEN


def test_fix_claim_contradicted_by_rescan_goes_back_to_open(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, s1, sv1)
    item = _items(db, target)["CVE-A"]
    item.state, item.fixed_at = RemediationState.FIXED, T0
    db.commit()
    s2, sv2 = _scan(db, target, {80: ["CVE-A"]})
    counts = sync_remediation(db, s2, sv2)
    item = _items(db, target)["CVE-A"]
    assert counts["reopened"] == 1
    assert (item.state, item.fixed_at) == (RemediationState.OPEN, None)


def test_verified_item_that_reappears_is_reopened(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, s1, sv1)
    s2, sv2 = _scan(db, target, {80: None})
    sync_remediation(db, s2, sv2)
    s3, sv3 = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, s3, sv3)
    item = _items(db, target)["CVE-A"]
    assert item.state == RemediationState.OPEN
    assert item.reopened_count == 1
    assert item.verified_at is None and item.verification_reason is None


def test_accepted_item_still_present_stays_accepted(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, s1, sv1)
    item = _items(db, target)["CVE-A"]
    item.state = RemediationState.ACCEPTED
    db.commit()
    s2, sv2 = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, s2, sv2)
    assert _items(db, target)["CVE-A"].state == RemediationState.ACCEPTED


def test_false_positive_findings_create_no_items(db: Session) -> None:
    target = _target(db)
    scan, services = _scan(
        db,
        target,
        {80: ["CVE-A", "CVE-FP"]},
        findings_state={"CVE-FP": FindingValidationState.FALSE_POSITIVE},
    )
    sync_remediation(db, scan, services)
    assert set(_items(db, target)) == {"CVE-A"}


def test_native_scans_never_create_or_verify(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, s1, sv1)
    s2, sv2 = _scan(db, target, {443: None}, scanner="native")
    counts = sync_remediation(db, s2, sv2)
    assert counts == {"created": 0, "updated": 0, "reopened": 0, "verified": 0}
    assert _items(db, target)["CVE-A"].state == RemediationState.OPEN


# --- metrics ----------------------------------------------------------------


def _item(state, severity="HIGH", first=T0, due_days=30, verified_days=None, simulated=False):
    return RemediationItem(
        state=state,
        severity=severity,
        first_seen_at=first,
        due_at=first + timedelta(days=due_days),
        verified_at=first + timedelta(days=verified_days) if verified_days is not None else None,
        simulated=simulated,
    )


def test_metrics_mttr_breach_aging() -> None:
    now = T0 + timedelta(days=40)
    items = [
        _item(RemediationState.VERIFIED, verified_days=10),  # in SLA
        _item(RemediationState.VERIFIED, verified_days=50, due_days=30),  # late (still counts)
        _item(RemediationState.OPEN, due_days=30),  # overdue now (age 40)
        _item(RemediationState.FIXED, first=T0 + timedelta(days=35)),  # not yet due (age 5)
        _item(RemediationState.ACCEPTED),  # outside SLA metrics
    ]
    m = metrics.compute(items, now)
    assert m["mttr_days"] == 30.0  # (10 + 50) / 2
    assert m["overdue_now"] == 1
    # population: 2 verified + 1 overdue unresolved; breached: 1 late + 1 overdue
    assert m["sla_breach_pct"] == round(100 * 2 / 3, 1)
    assert m["aging_unresolved"] == {"0-30": 1, "31-60": 1, "61-90": 0, "90+": 0}
    assert m["by_state"]["accepted"] == 1
    assert m["simulated"] is False


def test_metrics_empty_and_simulated_flag() -> None:
    assert metrics.compute([], T0)["sla_breach_pct"] is None
    assert metrics.compute([_item(RemediationState.OPEN, simulated=True)], T0)["simulated"]


# --- API --------------------------------------------------------------------


def test_api_list_transition_and_metrics(client: TestClient, db: Session) -> None:
    target = _target(db)
    scan, services = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, scan, services)

    resp = client.get(f"/api/v1/projects/{target.project_id}/remediation/items")
    assert resp.status_code == 200
    (item,) = resp.json()
    assert item["state"] == "open"

    resp = client.patch(
        f"/api/v1/remediation/items/{item['id']}",
        json={"state": "accepted", "note": "compensating WAF rule"},
    )
    assert resp.status_code == 200
    assert (resp.json()["state"], resp.json()["note"]) == ("accepted", "compensating WAF rule")

    resp = client.get(f"/api/v1/projects/{target.project_id}/remediation/metrics")
    assert resp.status_code == 200
    assert resp.json()["by_state"]["accepted"] == 1


def test_api_rejects_verified_and_invalid_transitions(client: TestClient, db: Session) -> None:
    target = _target(db)
    scan, services = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, scan, services)
    item_id = _items(db, target)["CVE-A"].id

    resp = client.patch(f"/api/v1/remediation/items/{item_id}", json={"state": "verified"})
    assert resp.status_code == 400
    assert "only a rescan can verify" in resp.json()["detail"]

    assert (
        client.patch(f"/api/v1/remediation/items/{item_id}", json={"state": "fixed"}).status_code
        == 200
    )
    resp = client.patch(f"/api/v1/remediation/items/{item_id}", json={"state": "accepted"})
    assert resp.status_code == 400  # fixed -> accepted is not an analyst move


def test_api_unknown_project_and_item_404(client: TestClient) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/projects/{missing}/remediation/items").status_code == 404
    assert client.get(f"/api/v1/projects/{missing}/remediation/metrics").status_code == 404
    resp = client.patch(f"/api/v1/remediation/items/{missing}", json={"state": "fixed"})
    assert resp.status_code == 404


def test_simulated_seed_is_labelled_and_idempotent(db: Session) -> None:
    from app.scripts.seed_simulated_remediation import PROJECT_NAME, seed

    project = seed(db, now=T0 + timedelta(days=300))
    assert project is not None and project.name.startswith("SIMULATED")
    items = db.query(RemediationItem).filter(RemediationItem.project_id == project.id).all()
    assert len(items) == 40
    assert all(i.simulated for i in items)
    assert all(i.cve_id.startswith("CVE-0000-") for i in items)  # never a real CVE id
    demo_target = db.query(Target).filter(Target.project_id == project.id).one()
    assert demo_target.authorization_confirmed is False  # can't be scanned
    assert metrics.compute(items, T0 + timedelta(days=300))["simulated"] is True
    assert seed(db) is None  # second run is a no-op
    assert db.query(Project).filter(Project.name == PROJECT_NAME).count() == 1


def test_versionless_cpe_rescan_cannot_verify(db: Session) -> None:
    """A version-less CPE is skipped by the correlator without counting as
    a failed lookup; absence after such a rescan proves nothing."""
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, s1, sv1)
    s2, sv2 = _scan(db, target, {80: None})
    sv2[0].evidence = {"cpe": ["cpe:/a:apache:http_server"]}  # no version
    db.commit()
    sync_remediation(db, s2, sv2)
    assert _items(db, target)["CVE-A"].state == RemediationState.OPEN


def test_rescan_with_no_open_ports_verifies_nothing(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, s1, sv1)
    s2, sv2 = _scan(db, target, {})  # host down or firewalled
    counts = sync_remediation(db, s2, sv2)
    assert counts["verified"] == 0
    assert _items(db, target)["CVE-A"].state == RemediationState.OPEN


def test_older_scan_finishing_late_does_not_override_newer(db: Session) -> None:
    target = _target(db)
    newer, sv_new = _scan(db, target, {80: ["CVE-A"]}, created=T0 + timedelta(days=5))
    sync_remediation(db, newer, sv_new)
    older, sv_old = _scan(db, target, {80: None}, created=T0)
    sync_remediation(db, older, sv_old)  # would verify CVE-A if it weren't older
    item = _items(db, target)["CVE-A"]
    assert item.state == RemediationState.OPEN
    assert item.last_seen_scan_id == newer.id


def test_api_accept_requires_reason(client: TestClient, db: Session) -> None:
    target = _target(db)
    scan, services = _scan(db, target, {80: ["CVE-A"]})
    sync_remediation(db, scan, services)
    item_id = _items(db, target)["CVE-A"].id
    resp = client.patch(f"/api/v1/remediation/items/{item_id}", json={"state": "accepted"})
    assert resp.status_code == 400
    assert "requires a reason" in resp.json()["detail"]
