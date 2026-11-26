"""Phase 12 pre-registered tests (benchmarks/phase12-preregistration.md):
R1-R5, the remediation race fix, and I7, source-aware verification."""

from __future__ import annotations

import logging
import threading
from datetime import timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.remediation import RemediationItem, RemediationState
from app.models.scan import Scan
from app.models.service import Service
from app.modules.remediation.sync import (
    CVE_NOT_MATCHED,
    SERVICE_NOT_OBSERVED,
    may_change,
    sync_remediation,
)
from tests.conftest import test_engine
from tests.test_remediation import T0, _items, _scan, _target

DAY = timedelta(days=1)


# --- R: ordering ------------------------------------------------------------


def test_r1_older_same_source_scan_synced_late_is_stale(db: Session) -> None:
    target = _target(db)
    newer, sv_new = _scan(db, target, {80: ["CVE-A"]}, created=T0 + 5 * DAY)
    sync_remediation(db, newer, sv_new)
    older, sv_old = _scan(db, target, {80: ["CVE-A", "CVE-B"]}, created=T0)
    counts = sync_remediation(db, older, sv_old)
    assert counts == {"created": 0, "updated": 0, "reopened": 0, "verified": 0, "stale": 1}
    items = _items(db, target)
    assert set(items) == {"CVE-A"}  # the older scan created nothing
    assert items["CVE-A"].last_seen_scan_id == newer.id


def test_r2_older_scan_cannot_reopen_item_a_newer_scan_verified(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]}, created=T0)
    sync_remediation(db, s1, sv1)
    s3, sv3 = _scan(db, target, {80: None}, created=T0 + 2 * DAY)
    assert sync_remediation(db, s3, sv3)["verified"] == 1
    s2, sv2 = _scan(db, target, {80: ["CVE-A"]}, created=T0 + DAY)  # finishes last
    sync_remediation(db, s2, sv2)
    item = _items(db, target)["CVE-A"]
    assert item.state == RemediationState.VERIFIED
    assert item.verified_scan_id == s3.id
    assert item.reopened_count == 0


def test_r3_old_import_cannot_reopen_but_newer_import_does(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]}, created=T0)
    sync_remediation(db, s1, sv1)
    s2, sv2 = _scan(db, target, {80: None}, created=T0 + 5 * DAY)
    sync_remediation(db, s2, sv2)
    assert _items(db, target)["CVE-A"].state == RemediationState.VERIFIED

    old_import, svo = _scan(db, target, {80: ["CVE-A"]}, scanner="nessus", created=T0 + 2 * DAY)
    counts = sync_remediation(db, old_import, svo)
    assert counts["stale"] == 0  # first nessus import: not stale by source...
    item = _items(db, target)["CVE-A"]
    assert item.state == RemediationState.VERIFIED  # ...but older than the item's last evaluation
    assert item.sources == ["vulnsight"]

    new_import, svn = _scan(db, target, {80: ["CVE-A"]}, scanner="nessus", created=T0 + 6 * DAY)
    assert sync_remediation(db, new_import, svn)["reopened"] == 1
    item = _items(db, target)["CVE-A"]
    assert item.state == RemediationState.OPEN
    assert item.sources == ["vulnsight", "nessus"]


def test_r4_concurrent_syncs_of_one_target_do_not_collide(caplog) -> None:
    """Two real sessions on two threads sync the same target at the same
    moment, both creating the same new item. Without the target lock one
    of them hits the unique key and rolls back its whole sync."""
    caplog.set_level(logging.ERROR, logger="app.modules.remediation.sync")
    for _ in range(20):
        with Session(test_engine) as setup:
            target = _target(setup)
            project_id = target.project_id
            scan_ids = [
                _scan(setup, target, {80: ["CVE-A"]}, created=T0)[0].id,
                _scan(setup, target, {80: ["CVE-A"]}, created=T0)[0].id,
            ]
            target_id = target.id
        barrier = threading.Barrier(2)
        results: list[dict] = []

        def worker(scan_id, barrier: threading.Barrier, results: list[dict]) -> None:
            with Session(test_engine) as s:
                scan = s.get(Scan, scan_id)
                services = s.query(Service).join(Service.asset).filter_by(scan_id=scan_id).all()
                for service in services:
                    _ = service.findings  # load before the race, like run_scan_task
                barrier.wait()
                results.append(sync_remediation(s, scan, services))

        threads = [
            threading.Thread(target=worker, args=(sid, barrier, results)) for sid in scan_ids
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        try:
            assert not [r for r in caplog.records if "failed" in r.getMessage()]
            assert sorted(r["created"] for r in results) == [0, 1]
            assert sorted(r["updated"] for r in results) == [0, 1]
            with Session(test_engine) as check:
                items = check.query(RemediationItem).filter_by(target_id=target_id).all()
                assert len(items) == 1
        finally:
            with Session(test_engine) as cleanup:
                cleanup.execute(delete(Project).where(Project.id == project_id))
                cleanup.commit()


def test_r5_may_change_ordering_rule() -> None:
    assert may_change(T0, T0 + DAY)
    assert may_change(T0, T0)  # the same scan time may re-apply
    assert not may_change(T0 + DAY, T0)


# --- I7: source-aware verification -------------------------------------------


def test_i7_vulnsight_rescan_does_not_verify_nessus_only_item_on_open_port(db: Session) -> None:
    target = _target(db)
    imp, svi = _scan(db, target, {80: ["CVE-N"]}, scanner="nessus", created=T0)
    sync_remediation(db, imp, svi)
    s2, sv2 = _scan(db, target, {80: None}, created=T0 + DAY)  # complete lookup, CVE absent
    assert sync_remediation(db, s2, sv2)["verified"] == 0
    item = _items(db, target)["CVE-N"]
    assert item.state == RemediationState.OPEN
    assert item.sources == ["nessus"]


def test_i7_closed_port_verifies_nessus_only_item(db: Session) -> None:
    target = _target(db)
    imp, svi = _scan(db, target, {80: ["CVE-N"]}, scanner="nessus", created=T0)
    sync_remediation(db, imp, svi)
    s2, sv2 = _scan(db, target, {443: None}, created=T0 + DAY)
    sync_remediation(db, s2, sv2)
    item = _items(db, target)["CVE-N"]
    assert item.state == RemediationState.VERIFIED
    assert item.verification_reason == SERVICE_NOT_OBSERVED


def test_i7_port_zero_is_never_verified_by_a_closed_port(db: Session) -> None:
    target = _target(db)
    imp, svi = _scan(db, target, {0: ["CVE-H"]}, scanner="nessus", created=T0)
    sync_remediation(db, imp, svi)
    s2, sv2 = _scan(db, target, {443: None}, created=T0 + DAY)
    sync_remediation(db, s2, sv2)
    assert _items(db, target)["CVE-H"].state == RemediationState.OPEN


def test_i7_import_never_verifies(db: Session) -> None:
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]}, created=T0)
    sync_remediation(db, s1, sv1)
    imp, svi = _scan(db, target, {80: None, 443: None}, scanner="openvas", created=T0 + DAY)
    assert sync_remediation(db, imp, svi)["verified"] == 0
    assert _items(db, target)["CVE-A"].state == RemediationState.OPEN


def test_i7_vulnsight_rescan_still_verifies_merged_item(db: Session) -> None:
    """An item VulnSight and Nessus both reported can still be verified by
    a VulnSight rescan that no longer matches the CVE."""
    target = _target(db)
    s1, sv1 = _scan(db, target, {80: ["CVE-A"]}, created=T0)
    sync_remediation(db, s1, sv1)
    imp, svi = _scan(db, target, {80: ["CVE-A"]}, scanner="nessus", created=T0 + DAY)
    sync_remediation(db, imp, svi)
    s3, sv3 = _scan(db, target, {80: None}, created=T0 + 2 * DAY)
    sync_remediation(db, s3, sv3)
    item = _items(db, target)["CVE-A"]
    assert item.sources == ["vulnsight", "nessus"]
    assert item.state == RemediationState.VERIFIED
    assert item.verification_reason == CVE_NOT_MATCHED
