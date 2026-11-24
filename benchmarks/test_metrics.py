"""Checks for the benchmark harness's metric math (not part of the app's CI
suite). Run inside the backend image:

    docker compose run --rm -v ./benchmarks:/benchmarks backend \
      python /benchmarks/test_metrics.py
"""

from run_benchmark import (
    _ns,
    cvss_score_of,
    rank_range,
    summary,
    target_metrics,
    vulnsight_score_of,
)


def _f(cve, cvss, conf=100.0, state="unvalidated", sev="HIGH"):
    return {"cve_id": cve, "cvss_score": cvss, "confidence_score": conf,
            "validation_state": state, "severity": sev, "description": ""}


def test_ranks_are_tie_aware_ranges():
    fs = [_ns(_f("CVE-B", 9.8, conf=10.0)), _ns(_f("CVE-A", 7.5)), _ns(_f("CVE-C", 9.8))]
    # B and C tie on 9.8: both 1-2, no CVE-id tiebreak.
    assert rank_range("CVE-B", fs, cvss_score_of) == (1, 2)
    assert rank_range("CVE-C", fs, cvss_score_of) == (1, 2)
    assert rank_range("CVE-A", fs, cvss_score_of) == (3, 3)
    # Low confidence pushes B to the bottom under VulnSight's contribution.
    assert rank_range("CVE-B", fs, vulnsight_score_of) == (3, 3)
    assert rank_range("CVE-X", fs, cvss_score_of) is None


def test_unscored_cve_ranks_last_under_cvss_only():
    fs = [_ns(_f("CVE-A", None)), _ns(_f("CVE-B", 1.0))]
    assert rank_range("CVE-A", fs, cvss_score_of) == (2, 2)


def test_target_metrics_recall_dedup_and_other_port():
    expected = {"host": "h", "port": 8080, "documented_cves": ["CVE-1", "CVE-9"]}
    assets = [{"services": [
        {"port": 8080, "evidence": {"product": "Tomcat", "version": "9", "cpe": ["cpe:/a:x"]},
         # same CVE via two CPEs must count once
         "findings": [_f("CVE-2", 5.0), _f("CVE-2", 5.0), _f("CVE-3", 6.0)],
         "misconfigurations": [{"check_id": "missing-hsts"}]},
        {"port": 8009, "evidence": None, "findings": [_f("CVE-1", 9.8)], "misconfigurations": []},
    ]}]
    m = target_metrics(expected, assets)
    assert m["cves_matched"] == 3
    assert m["cves_matched_beyond_documented"] == 2
    d1, d9 = m["documented"]
    assert d1["detected"] and d1["port"] == 8009 and d1["rank_vulnsight"] == (1, 1)
    assert not d9["detected"]
    assert m["misconfigurations"] == ["missing-hsts"]
    s = summary([m])
    assert (s["documented_detected"], s["documented_total"], s["recall"]) == (1, 2, 0.5)


def test_closed_port_is_reported_not_crashed():
    m = target_metrics({"host": "h", "port": 80, "documented_cves": ["CVE-1"]}, [])
    assert not m["port_open"] and m["fingerprint"]["cpe"] == []
    assert summary([m])["mean_rank_vulnsight"] == [None, None]
    assert not summary([m])["valid"]  # port closed: the run can't be trusted


def test_run_invalid_unless_every_target_completed_cleanly():
    ok = {**target_metrics({"host": "h", "port": 80, "documented_cves": []},
                           [{"services": [{"port": 80}]}]),
          "scan_status": "completed", "scan_cve_lookups_failed": 0, "failed_lookups": []}
    assert summary([ok])["valid"]
    assert not summary([ok, {**ok, "failed_lookups": ["cpe:x (lookup failed)"]}])["valid"]
    assert not summary([{**ok, "scan_cve_lookups_failed": 2}])["valid"]
    assert not summary([{**ok, "scan_cve_lookups_failed": None}])["valid"]  # never correlated
    assert not summary([{**ok, "scan_status": "failed"}])["valid"]


def test_lookup_names_include_aliases_skip_versionless():
    from run_benchmark import lookup_names
    assets = [{"services": [
        {"evidence": {"cpe": ["cpe:/a:igor_sysoev:nginx:1.13.2", "cpe:/o:linux:linux_kernel"]}},
        {"evidence": None},
    ]}]
    assert lookup_names(assets) == {
        "cpe:2.3:a:igor_sysoev:nginx:1.13.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:f5:nginx:1.13.2:*:*:*:*:*:*:*",
    }


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
