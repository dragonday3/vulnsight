"""VulnSight benchmark harness (Phase 9).

Runs inside the backend image so it scores findings with the real
`score_finding_contribution` / `dedupe_findings_by_cve`, not a copy:

    docker compose run --rm -v ./benchmarks:/benchmarks \
      -e VULNSIGHT_COMMIT=$(git rev-parse --short HEAD) \
      backend python /benchmarks/run_benchmark.py

For every target in expected.json it creates an authorized hostname target,
runs an nmap scan through the public API, waits for a terminal state, then
computes the metrics defined before the first run (in the project's
Phase 9 plan, listed in benchmarks/README.md): fingerprint,
documented-CVE recall, CVEs matched, CVSS-only vs VulnSight rank of each
documented CVE, and misconfigurations. Writes
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
from app.modules.vulnerability import applicability, cache, cpe_utils  # noqa: E402
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


def cvss_score_of(f: SimpleNamespace) -> float:
    # CVSS-only ordering: highest cvss first, unscored last.
    return f.cvss_score if f.cvss_score is not None else -1.0


def vulnsight_score_of(f: SimpleNamespace) -> float:
    return score_finding_contribution(f)


def rank_range(cve_id: str, findings: list[SimpleNamespace], score) -> tuple[int, int] | None:
    """(best, worst) 1-based rank of cve_id when sorted by score, highest
    first, None if absent. Ties are reported as a range instead of being
    broken by CVE id, which would quietly favour older (documented) CVEs."""
    mine = next((score(f) for f in findings if f.cve_id == cve_id), None)
    if mine is None:
        return None
    higher = sum(1 for f in findings if score(f) > mine)
    tied = sum(1 for f in findings if score(f) == mine)
    return higher + 1, higher + tied


def audit_key(f: SimpleNamespace) -> tuple:
    # Deterministic order for the top-N audit list only.
    return (-vulnsight_score_of(f), f.cve_id)


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
            rc, rv = rank_range(cve, fs, cvss_score_of), rank_range(cve, fs, vulnsight_score_of)
            if rv is not None and (best is None or rv < best["rank_vulnsight"]):
                found = next(f for f in fs if f.cve_id == cve)
                best = {"port": port, "rank_cvss": rc, "rank_vulnsight": rv, "of": len(fs),
                        "unverified_prerequisite": getattr(found, "unverified_prerequisite", None)}
        documented.append({"cve": cve, "detected": best is not None, **(best or {})})

    main_fs = per_service.get(expected["port"], [])
    top = sorted(main_fs, key=audit_key)[:TOP_N_AUDIT]
    # CVSS-only top N (CVE-id tiebreak at the cut-off, for a fixed list).
    top_cvss = sorted(main_fs, key=lambda f: (-cvss_score_of(f), f.cve_id))[:TOP_N_AUDIT]
    all_fs = [f for fs in per_service.values() for f in fs]
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
             "kev": getattr(f, "kev", None), "epss": getattr(f, "epss", None),
             "unverified_prerequisite": getattr(f, "unverified_prerequisite", None),
             "contribution": round(score_finding_contribution(f), 2),
             "description": (f.description or "")[:200]}
            for f in top
        ],
        "top_by_cvss": [f.cve_id for f in top_cvss],
        # Full descriptions of the main service's findings, for label sheets.
        "descriptions": {f.cve_id: f.description or "" for f in main_fs},
        # Pre-registered M3: how often the prerequisite discount applies.
        "findings_total": len(all_fs),
        "findings_flagged": sum(1 for f in all_fs if getattr(f, "unverified_prerequisite", None)),
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
    """CPE names whose lookup did not complete, checked independently of
    the scan's own cve_lookups_failed count:
    - no cve_cache row: the NVD lookup failed (cache.store refuses failures);
    - a stale row: this scan's re-fetch must have failed;
    - NVD's total exceeds the cached list: truncated at the page cap;
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
            elif cache.is_stale(entry):
                failed.append(f"{name} (stale cache row)")
            elif entry.total_results > len(entry.cves):
                failed.append(f"{name} (truncated {len(entry.cves)}/{entry.total_results})")
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
        # Mean of best and of worst tie-aware rank over detected documented CVEs.
        "mean_rank_cvss_only": [mean([d["rank_cvss"][0] for d in hit]),
                                mean([d["rank_cvss"][1] for d in hit])],
        "mean_rank_vulnsight": [mean([d["rank_vulnsight"][0] for d in hit]),
                                mean([d["rank_vulnsight"][1] for d in hit])],
        "cves_matched_total": sum(t["cves_matched"] for t in targets),
        "targets_with_failed_lookups": sum(1 for t in targets if t.get("failed_lookups")),
        "findings_total": sum(t.get("findings_total", 0) for t in targets),
        "findings_flagged": sum(t.get("findings_flagged", 0) for t in targets),
        # A run with any incomplete lookup or broken target measures NVD or
        # infrastructure flakiness, not recall: it is INVALID, not a lower score.
        "valid": all(target_valid(t) for t in targets),
    }


def target_valid(t: dict) -> bool:
    return bool(
        not t.get("failed_lookups")
        and t.get("scan_cve_lookups_failed") == 0
        and t.get("scan_threat_intel_failed") == 0
        and t.get("scan_status") == "completed"
        and t["port_open"]
    )


def label_sheet(rows: list[dict], known: dict[str, dict[str, str]]) -> dict[str, list[str]]:
    """CVEs to label blind, per target, sorted by CVE id:
    - held-out targets: union of the CVSS-only and VulnSight top N;
    - other targets: VulnSight top-N CVEs without a Phase 9 label."""
    sheet = {}
    for t in rows:
        top_vs = {f["cve"] for f in t["top_by_vulnsight"]}
        if t.get("heldout"):
            cves = top_vs | set(t["top_by_cvss"])
        else:
            cves = top_vs - set(known.get(t["host"], {}))
        if cves:
            sheet[t["host"]] = sorted(cves)
    return sheet


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
    heldout_path = HERE / "expected-heldout.json"
    if heldout_path.exists():
        expected["targets"] += [
            {**t, "heldout": True} for t in json.loads(heldout_path.read_text())["targets"]
        ]
    started = dt.datetime.now(dt.timezone.utc)
    with SessionLocal() as db:
        cache_rows_at_start = db.query(cache.CveCache).count()
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
                 error_message=scan["error_message"], failed_lookups=failed_lookups(assets),
                 scan_cve_lookups_total=scan.get("cve_lookups_total"),
                 scan_cve_lookups_failed=scan.get("cve_lookups_failed"),
                 scan_threat_intel_failed=scan.get("threat_intel_failed"),
                 heldout=bool(t.get("heldout")))
        rows.append(m)
    main_rows = [m for m in rows if not m["heldout"]]
    heldout_rows = [m for m in rows if m["heldout"]]

    result = {
        "run_started_utc": started.isoformat(timespec="seconds"),
        "run_finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "vulnsight_commit": os.environ.get("VULNSIGHT_COMMIT", "unknown"),
        # 0 = every NVD lookup in this run was live (cold cache).
        "cve_cache_rows_at_start": cache_rows_at_start,
        "project_id": project["id"],
        "summary": {**summary(main_rows), "valid": all(target_valid(t) for t in rows)},
        "heldout_summary": summary(heldout_rows) if heldout_rows else None,
        "applicability_rules": {"features": applicability.RULE_FEATURE_COUNT,
                                "patterns": applicability.RULE_PATTERN_COUNT},
        "targets": rows,
        "raw": raw,
    }
    out = HERE / "results"
    out.mkdir(exist_ok=True)
    stem = started.strftime("%Y-%m-%d-%H%M")  # same-day runs must not overwrite
    (out / f"{stem}.json").write_text(json.dumps(result, indent=2, default=str))
    (out / f"{stem}.md").write_text(render_md(result))
    known_path = HERE / "labels" / "phase9-labels.json"
    known = json.loads(known_path.read_text())["labels"] if known_path.exists() else {}
    sheet = label_sheet(rows, known)
    (out / f"{stem}-labelsheet.json").write_text(json.dumps(sheet, indent=2))
    (out / f"{stem}-labelsheet.md").write_text(render_sheet(sheet, rows))
    print(json.dumps(result["summary"], indent=2))


def render_sheet(sheet: dict[str, list[str]], rows: list[dict]) -> str:
    """Blind labelling sheet: CVE id and description only (no score, rank,
    flag, or which list a CVE came from)."""
    desc = {t["host"]: t["descriptions"] for t in rows}
    lines = ["# Labelling sheet", "",
             "Label each CVE A (applicable to this container as configured), "
             "N (needs a feature/module/platform/config it lacks) or U (unclear).", ""]
    for host, cves in sheet.items():
        lines += [f"## {host}", "", "| CVE | Description | Label | Reason |", "|---|---|---|---|"]
        for cve in cves:
            text = " ".join(desc[host].get(cve, "").split()).replace("|", "/")
            lines.append(f"| {cve} | {text} | | |")
        lines.append("")
    return "\n".join(lines) + "\n"


def _fmt_range(r) -> str:
    if not r or r[0] is None:
        return "-"
    return f"{r[0]}" if r[0] == r[1] else f"{r[0]}-{r[1]}"


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
        ("**Run valid**: every CVE lookup succeeded and was stored." if s["valid"] else
         "**RUN INVALID**: for at least one target, a CVE lookup failed, was "
         "truncated, stale or not stored (Failed NVD lookups column), or the scan "
         "didn't complete, its cve_lookups_failed wasn't 0, or the target port was "
         "closed (see the JSON). Recall below is not a measurement."),
        "",
        f"- Documented CVEs detected: **{s['documented_detected']}/{s['documented_total']}** "
        f"(recall {s['recall']})",
        f"- Targets fingerprinted with a CPE: {s['fingerprinted_with_cpe']}/{s['targets']}",
        f"- Total version-applicable CVEs matched: {s['cves_matched_total']}",
        f"- Targets with at least one failed NVD lookup: {s['targets_with_failed_lookups']}"
        " (their zero/low counts are not a clean result)",
        "- Mean rank of detected documented CVEs (best-worst over ties): CVSS-only "
        f"{_fmt_range(s['mean_rank_cvss_only'])}, VulnSight {_fmt_range(s['mean_rank_vulnsight'])}",
        f"- CVE cache rows at run start: {r['cve_cache_rows_at_start']} (0 = every lookup live)",
        f"- Findings flagged with an unverified prerequisite: {s['findings_flagged']}/"
        f"{s['findings_total']} (rules: {r['applicability_rules']['features']} features, "
        f"{r['applicability_rules']['patterns']} patterns)",
        "",
        "## Per target",
        "",
        "| Target | nmap product/version | CPE | Documented CVE | Detected | Rank CVSS-only | "
        "Rank VulnSight | CVEs matched | Failed NVD lookups | Threat-intel failed | Misconfigs |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    if r.get("heldout_summary"):
        h = r["heldout_summary"]
        lines[lines.index("## Per target") - 1:lines.index("## Per target") - 1] = [
            "",
            f"- Held-out targets (separate row, no claim): documented CVEs detected "
            f"{h['documented_detected']}/{h['documented_total']}; flagged "
            f"{h['findings_flagged']}/{h['findings_total']}",
        ]
    for t in r["targets"]:
        fp = t["fingerprint"]
        for d in t["documented"]:
            lines.append(
                f"| {t['host']}:{t['port']} | {fp['product'] or '-'} {fp['version'] or ''} | "
                f"{', '.join(fp['cpe']) or '-'} | {d['cve']} | {'yes' if d['detected'] else 'no'} | "
                f"{_fmt_range(d.get('rank_cvss'))}/{d.get('of') or '-'} | "
                f"{_fmt_range(d.get('rank_vulnsight'))}/{d.get('of') or '-'} | {t['cves_matched']} | "
                f"{len(t.get('failed_lookups', [])) or '-'} | "
                f"{t.get('scan_threat_intel_failed')} | "
                f"{', '.join(t['misconfigurations']) or '-'} |"
            )
    lines += ["", "## Top 10 per target, by VulnSight rank", "",
              "Applicability labels are made separately (blind label sheet + "
              "score_labels.py), not in this file.", ""]
    for t in r["targets"]:
        if not t["top_by_vulnsight"]:
            continue
        lines += [f"### {t['host']}" + (" (held-out)" if t.get("heldout") else ""), "",
                  "| # | CVE | CVSS | KEV | EPSS | Prerequisite | Contribution |",
                  "|---|---|---|---|---|---|---|"]
        for i, f in enumerate(t["top_by_vulnsight"], 1):
            lines.append(
                f"| {i} | {f['cve']} | {f['cvss']} | {'yes' if f.get('kev') else '-'} | "
                f"{f.get('epss') if f.get('epss') is not None else '-'} | "
                f"{f.get('unverified_prerequisite') or '-'} | {f['contribution']} |"
            )
        lines.append("")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    run()
