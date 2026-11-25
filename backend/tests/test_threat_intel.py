"""Tests for Phase 10 KEV/EPSS enrichment. httpx is mocked; Redis is the
real per-test-flushed test Redis (`redis_client` fixture)."""

from __future__ import annotations

from typing import Any

import httpx
import redis
from sqlalchemy.orm import Session

from app.models.finding import Finding
from app.modules.vulnerability import threat_intel
from tests.test_correlator import _make_service


def _kev_body(*ids: str) -> dict[str, Any]:
    return {"vulnerabilities": [{"cveID": cve} for cve in ids]}


def _epss_body(**scores: tuple[float, float]) -> dict[str, Any]:
    return {
        "data": [
            {"cve": cve.replace("_", "-"), "epss": str(e), "percentile": str(p)}
            for cve, (e, p) in scores.items()
        ]
    }


def test_kev_ids_fetched_once_then_served_from_cache(monkeypatch, redis_client) -> None:
    calls: list[str] = []

    def _get(url: str, **_kw: Any) -> httpx.Response:
        calls.append(url)
        return httpx.Response(200, json=_kev_body("CVE-2021-41773"))

    monkeypatch.setattr(httpx, "get", _get)
    assert threat_intel.kev_ids(redis_client) == {"CVE-2021-41773"}
    assert threat_intel.kev_ids(redis_client) == {"CVE-2021-41773"}
    assert calls == [threat_intel.KEV_URL]


def test_kev_fetch_failure_returns_none_and_caches_nothing(monkeypatch, redis_client) -> None:
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: httpx.Response(503))
    assert threat_intel.kev_ids(redis_client) is None
    assert redis_client.get(threat_intel.KEV_CACHE_KEY) is None


def test_epss_batches_caches_and_distinguishes_no_score_from_failure(
    monkeypatch, redis_client
) -> None:
    monkeypatch.setattr(threat_intel, "EPSS_BATCH_SIZE", 2)
    batches: list[str] = []

    def _get(_url: str, **kw: Any) -> httpx.Response:
        batch = kw["params"]["cve"]
        batches.append(batch)
        if "CVE-3" in batch:
            return httpx.Response(500)  # second batch fails
        # CVE-2 has no EPSS score: FIRST simply omits it.
        return httpx.Response(200, json=_epss_body(CVE_1=(0.9, 0.99)))

    monkeypatch.setattr(httpx, "get", _get)
    scores, failed = threat_intel.epss_scores({"CVE-1", "CVE-2", "CVE-3"}, redis_client)

    assert batches == ["CVE-1,CVE-2", "CVE-3"]
    assert failed == 1
    assert scores == {"CVE-1": (0.9, 0.99), "CVE-2": None}  # CVE-3 absent: failed

    # Second call: CVE-1/CVE-2 from cache (including the cached "no score"),
    # only the failed CVE-3 is fetched again.
    batches.clear()
    scores, failed = threat_intel.epss_scores({"CVE-1", "CVE-2", "CVE-3"}, redis_client)
    assert batches == ["CVE-3"]
    assert scores["CVE-2"] is None and failed == 1


def _add_finding(db: Session, service, cve_id: str, description: str) -> Finding:
    finding = Finding(
        service_id=service.id,
        cve_id=cve_id,
        matched_cpe="cpe:2.3:a:x:y:1:*:*:*:*:*:*:*",
        severity="HIGH",
        cvss_score=7.5,
        description=description,
        evidence={},
        confidence_score=100.0,
    )
    db.add(finding)
    db.commit()
    return finding


def test_enrich_findings_sets_kev_epss_and_prerequisite(
    monkeypatch, db: Session, redis_client: redis.Redis
) -> None:
    service = _make_service(db, evidence={"cpe": ["cpe:/a:x:y:1"]})
    kev_finding = _add_finding(db, service, "CVE-2021-41773", "Path traversal.")
    http2_finding = _add_finding(db, service, "CVE-2023-44487", "The HTTP/2 protocol allows DoS.")

    def _get(url: str, **_kw: Any) -> httpx.Response:
        if url == threat_intel.KEV_URL:
            return httpx.Response(200, json=_kev_body("CVE-2021-41773"))
        return httpx.Response(200, json=_epss_body(CVE_2021_41773=(0.99, 0.999)))

    monkeypatch.setattr(httpx, "get", _get)
    db.refresh(service)
    failed = threat_intel.enrich_findings(db, redis_client, [service])

    db.refresh(kev_finding)
    db.refresh(http2_finding)
    assert failed == 0
    assert (kev_finding.kev, kev_finding.epss, kev_finding.unverified_prerequisite) == (
        True,
        0.99,
        None,
    )
    # Not in KEV, no EPSS row (a real "no score"), HTTP/2 never observed.
    assert (http2_finding.kev, http2_finding.epss, http2_finding.unverified_prerequisite) == (
        False,
        None,
        "http2",
    )


def test_enrich_findings_counts_failures_and_leaves_fields_null(
    monkeypatch, db: Session, redis_client: redis.Redis
) -> None:
    service = _make_service(db, evidence={"cpe": ["cpe:/a:x:y:1"]})
    finding = _add_finding(db, service, "CVE-2021-41773", "Path traversal.")
    monkeypatch.setattr(httpx, "get", lambda *a, **kw: httpx.Response(503))

    db.refresh(service)
    assert threat_intel.enrich_findings(db, redis_client, [service]) == 2  # KEV + 1 EPSS batch
    db.refresh(finding)
    assert (finding.kev, finding.epss) == (None, None)


def test_enrich_findings_with_no_findings_makes_no_requests(
    monkeypatch, db: Session, redis_client: redis.Redis
) -> None:
    service = _make_service(db, evidence=None)

    def _fail(*_a: Any, **_kw: Any) -> httpx.Response:
        raise AssertionError("no network call expected")

    monkeypatch.setattr(httpx, "get", _fail)
    assert threat_intel.enrich_findings(db, redis_client, [service]) == 0


def test_epss_unreachable_stops_and_counts_remaining_batches(monkeypatch, redis_client) -> None:
    monkeypatch.setattr(threat_intel, "EPSS_BATCH_SIZE", 1)
    calls: list[int] = []

    def _get(*_a: Any, **_kw: Any) -> httpx.Response:
        calls.append(1)
        raise httpx.ConnectError("unreachable")

    monkeypatch.setattr(httpx, "get", _get)
    scores, failed = threat_intel.epss_scores({"CVE-1", "CVE-2", "CVE-3"}, redis_client)
    assert (scores, failed, len(calls)) == ({}, 3, 1)


def test_applicability_flags_survive_a_later_enrichment_failure(
    monkeypatch, db: Session, redis_client: redis.Redis
) -> None:
    """The pure flags are committed before any network/Redis work, so an
    unexpected failure there must not roll them back."""
    service = _make_service(db, evidence={"cpe": ["cpe:/a:x:y:1"]})
    finding = _add_finding(db, service, "CVE-2023-44487", "The HTTP/2 protocol allows DoS.")

    def _boom(_redis: redis.Redis) -> set[str]:
        raise RuntimeError("redis down")

    monkeypatch.setattr(threat_intel, "kev_ids", _boom)
    db.refresh(service)
    assert threat_intel.enrich_findings(db, redis_client, [service]) == 1
    db.refresh(finding)
    assert finding.unverified_prerequisite == "http2"
