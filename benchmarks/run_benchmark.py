"""VulnSight benchmark harness (Phase 9).

Runs inside the backend image so it scores findings with the real
`score_finding_contribution` / `dedupe_findings_by_cve`, not a copy:

    docker compose run --rm -v ./benchmarks:/benchmarks \
      -e VULNSIGHT_COMMIT=$(git rev-parse --short HEAD) \
      backend python /benchmarks/run_benchmark.py

For every target in expected.json it creates an authorized hostname target,
runs an nmap scan through the public API, waits for a terminal state, then
computes the metrics fixed in expected.json's pre-registration:
fingerprint, documented-CVE recall, CVEs matched, CVSS-only vs VulnSight
rank of each documented CVE, and misconfigurations. Writes
results/<date>.json (raw + metrics) and results/<date>.md (tables, plus a
top-10 table per target for the manual applicability audit).
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, "/app")  # backend code inside the backend image

import app.db.base  # noqa: E402,F401  (registers every model so the ORM mappers resolve)
from app.db.session import SessionLocal  # noqa: E402
from app.modules.risk.scoring import score_finding_contribution  # noqa: E402
from app.modules.vulnerability import cache, cpe_utils  # noqa: E402
from app.modules.vulnerability.correlator import _is_versionless_cpe23  # noqa: E402
from app.modules.vulnerability.finding_dedup import dedupe_findings_by_cve  # noqa: E402

API = os.environ.get("VULNSIGHT_API", "http://backend:8000/api/v1")
HERE = Path(__file__).resolve().parent
TERMINAL = {"completed", "failed", "cancelled"}
SCAN_TIMEOUT_S = 1800  # NVD keyless limit is 5 req/30s, shared by all scans
TOP_N_AUDIT = 10


# ---------------------------------------------------------------- metrics
# Pure functions; covered by test_metrics.py.


def _ns(finding: dict) -> SimpleNamespace:
    return SimpleNamespace(**finding)


def cvss_key(f: SimpleNamespace) -> tuple:
    # CVSS-only ordering: highest cvss first, unscored last, CVE id tiebreak.
    return (-(f.cvss_score if f.cvss_score is not None else -1.0), f.cve_id)


def vulnsight_key(f: SimpleNamespace) -> tuple:
    return (-score_finding_contribution(f), f.cve_id)


def rank_of(cve_id: str, findings: list[SimpleNamespace], key) -> int | None:
    """1-based rank of cve_id in findings sorted by key, None if absent."""
    for i, f in enumerate(sorted(findings, key=key), start=1):
        if f.cve_id == cve_id:
            return i
    return None


def service_findings(service: dict) -> list[SimpleNamespace]:
    return dedupe_findings_by_cve([_ns(f) for f in service.get("findings", [])])


def target_metrics(expected: dict, assets: list[dict]) -> dict:
    services = [s for a in assets for s in a.get("services", [])]
    by_port = {s["port"]: s for s in services}
    main = by_port.get(expected["port"])
    ev = (main or {}).get("evidence") or {}

    per_service = {s["port"]: service_findings(s) for s in services}
    matched = sorted({f.cve_id for fs in per_service.values() for f in fs})

    documented = []
    for cve in expected["documented_cves"]:
        # Best rank across the asset's services (a CVE can surface on a
        # service other than the expected port, e.g. Tomcat's AJP port).
        best = None
        for port, fs in per_service.items():
            rc, rv = rank_of(cve, fs, cvss_key), rank_of(cve, fs, vulnsight_key)
            if rv is not None and (best is None or rv < best["rank_vulnsight"]):
                best = {"port": port, "rank_cvss": rc, "rank_vulnsight": rv, "of": len(fs)}
        documented.append({"cve": cve, "detected": best is not None, **(best or {})})

    main_fs = per_service.get(expected["port"], [])
    top = sorted(main_fs, key=vulnsight_key)[:TOP_N_AUDIT]
    return {
        "host": expected["host"],
        "port": expected["port"],
        "port_open": main is not None,
        "fingerprint": {
            "product": ev.get("product"),
            "version": ev.get("version"),
            "cpe": ev.get("cpe", []),
        },
        "services": [
            {"port": s["port"], "name": s.get("service_name"), "product": s.get("product"),
             "version": s.get("version"), "findings": len(per_service[s["port"]])}
            for s in services
        ],
        "documented": documented,
        "cves_matched": len(matched),
        "cves_matched_beyond_documented": len(set(matched) - set(expected["documented_cves"])),
        "top_by_vulnsight": [
            {"cve": f.cve_id, "cvss": f.cvss_score, "severity": f.severity,
             "confidence": f.confidence_score,
             "contribution": round(score_finding_contribution(f), 2),
             "description": (f.description or "")[:200]}
            for f in top
        ],
        "misconfigurations": sorted(
            {m["check_id"] for s in services for m in s.get("misconfigurations", [])}
        ),
    }


def lookup_names(assets: list[dict]) -> set[str]:
    """Every CPE 2.3 name the correlator would query for these assets."""
    names: set[str] = set()
    for a in assets:
        for s in a.get("services", []):
            for cpe22 in (s.get("evidence") or {}).get("cpe", []):
                cpe23 = cpe_utils.to_cpe23(cpe22)
                if cpe23 and not _is_versionless_cpe23(cpe23):
                    names |= {cpe23, *cpe_utils.nvd_aliases(cpe23)}
    return names


def failed_lookups(assets: list[dict]) -> list[str]:
    """CPE names whose CVEs never became findings. The API can't tell "no
    CVEs" from "lookup failed" (a known gap); this can, two ways:
    - no cve_cache row: the NVD lookup failed (cache.store refuses failures);
    - cached CVEs but no finding with that matched_cpe: persisting failed.
    """
    persisted = {
        f["matched_cpe"]
        for a in assets for s in a.get("services", []) for f in s.get("findings", [])
    }
    failed = []
    with SessionLocal() as db:
        for name in sorted(lookup_names(assets)):
            entry = cache.get_cached(db, name)
            if entry is None:
                failed.append(f"{name} (lookup failed)")
            elif entry.cves and name not in persisted:
                failed.append(f"{name} (findings not persisted)")
    return failed


def summary(targets: list[dict]) -> dict:
    docs = [d for t in targets for d in t["documented"]]
    hit = [d for d in docs if d["detected"]]

    def mean(xs):
        return round(sum(xs) / len(xs), 2) if xs else None

    return {
        "documented_total": len(docs),
        "documented_detected": len(hit),
        "recall": round(len(hit) / len(docs), 3) if docs else None,
        "fingerprinted_with_cpe": sum(1 for t in targets if t["fingerprint"]["cpe"]),
        "targets": len(targets),
        "mean_rank_cvss_only": mean([d["rank_cvss"] for d in hit]),
        "mean_rank_vulnsight": mean([d["rank_vulnsight"] for d in hit]),
        "cves_matched_total": sum(t["cves_matched"] for t in targets),
        "targets_with_failed_lookups": sum(1 for t in targets if t.get("failed_lookups")),
    }


# ---------------------------------------------------------------- API


def api(method: str, path: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {path} -> {e.code}: {e.read().decode()[:500]}")


def run() -> None:
    expected = json.loads((HERE / "expected.json").read_text())
    started = dt.datetime.now(dt.timezone.utc)
    project = api("POST", "/projects", {
        "name": f"benchmark {started:%Y-%m-%d %H:%M}",
        "description": "Phase 9 benchmark: vulhub targets on the internal compose network",
    })

    scans = {}
    for t in expected["targets"]:
        target = api("POST", f"/projects/{project['id']}/targets", {
            "target_type": "hostname", "value": t["host"], "authorization_confirmed": True,
            "authorization_note": "Local benchmark container, internal Docker network only",
        })
        scan = api("POST", "/scans", {"project_id": project["id"], "target_id": target["id"],
                                      "config": {"scanner": "nmap"}})
        scans[t["host"]] = scan["id"]
        print(f"queued {t['host']}: scan {scan['id']}", flush=True)

    deadline = time.time() + SCAN_TIMEOUT_S
    pending = set(scans)
    while pending and time.time() < deadline:
        for host in sorted(pending):
            st = api("GET", f"/scans/{scans[host]}/status")["status"]
            if st in TERMINAL:
                pending.discard(host)
                print(f"{host}: {st}", flush=True)
        time.sleep(10)
    if pending:
        raise SystemExit(f"timed out waiting for: {sorted(pending)}")

    rows, raw = [], {}
    for t in expected["targets"]:
        scan = api("GET", f"/scans/{scans[t['host']]}")
        assets = api("GET", f"/scans/{scans[t['host']]}/assets")
        raw[t["host"]] = {"scan": scan, "assets": assets}
        m = target_metrics(t, assets)
        m.update(scan_id=scan["id"], scan_status=scan["status"],
                 scan_risk_score=scan["risk_score"], scan_risk_tier=scan["risk_tier"],
                 error_message=scan["error_message"], failed_lookups=failed_lookups(assets))
        rows.append(m)

    result = {
        "run_started_utc": started.isoformat(timespec="seconds"),
        "run_finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "vulnsight_commit": os.environ.get("VULNSIGHT_COMMIT", "unknown"),
        "project_id": project["id"],
        "summary": summary(rows),
        "targets": rows,
        "raw": raw,
    }
    out = HERE / "results"
    out.mkdir(exist_ok=True)
    stem = started.strftime("%Y-%m-%d")
    (out / f"{stem}.json").write_text(json.dumps(result, indent=2, default=str))
    (out / f"{stem}.md").write_text(render_md(result))
    print(json.dumps(result["summary"], indent=2))


def render_md(r: dict) -> str:
    s = r["summary"]
    lines = [
        f"# Benchmark run {r['run_started_utc']}",
        "",
        f"VulnSight commit `{r['vulnsight_commit']}`, scanner nmap, live NVD. "
        "Matched CVEs are *version-applicable* (NVD lists the detected version as "
        "affected), not confirmed exploitable.",
        "",
        "## Summary",
        "",
        f"- Documented CVEs detected: **{s['documented_detected']}/{s['documented_total']}** "
        f"(recall {s['recall']})",
        f"- Targets fingerprinted with a CPE: {s['fingerprinted_with_cpe']}/{s['targets']}",
        f"- Total version-applicable CVEs matched: {s['cves_matched_total']}",
        f"- Targets with at least one failed NVD lookup: {s['targets_with_failed_lookups']}"
        " (their zero/low counts are not a clean result)",
        f"- Mean rank of detected documented CVEs: CVSS-only {s['mean_rank_cvss_only']}, "
        f"VulnSight {s['mean_rank_vulnsight']}",
        "",
        "## Per target",
        "",
        "| Target | nmap product/version | CPE | Documented CVE | Detected | Rank CVSS-only | "
        "Rank VulnSight | CVEs matched | Failed NVD lookups | Misconfigs |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for t in r["targets"]:
        fp = t["fingerprint"]
        for d in t["documented"]:
            lines.append(
                f"| {t['host']}:{t['port']} | {fp['product'] or '-'} {fp['version'] or ''} | "
                f"{', '.join(fp['cpe']) or '-'} | {d['cve']} | {'yes' if d['detected'] else 'no'} | "
                f"{d.get('rank_cvss') or '-'}/{d.get('of') or '-'} | "
                f"{d.get('rank_vulnsight') or '-'}/{d.get('of') or '-'} | {t['cves_matched']} | "
                f"{len(t.get('failed_lookups', [])) or '-'} | "
                f"{', '.join(t['misconfigurations']) or '-'} |"
            )
    lines += ["", "## Manual applicability audit (top 10 per target, by VulnSight rank)", "",
              "Manual judgement: `applicable` = plausible in this container's config; "
              "`not-applicable` = needs a module/platform/config the container lacks; "
              "`unclear` = can't tell from the advisory.", ""]
    for t in r["targets"]:
        if not t["top_by_vulnsight"]:
            continue
        lines += [f"### {t['host']}", "", "| # | CVE | CVSS | Contribution | Audit | Reason |",
                  "|---|---|---|---|---|---|"]
        for i, f in enumerate(t["top_by_vulnsight"], 1):
            lines.append(f"| {i} | {f['cve']} | {f['cvss']} | {f['contribution']} | TODO | |")
        lines.append("")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    run()
