"""Phase 11 controlled upgrade test, exactly as pre-registered in
phase11-preregistration.md (U1-U4). Runs on the host:

    py upgrade_test.py --api http://localhost:8001/api/v1

Needs the VulnSight stack running (containers named vulnsight-*), the
`docker` CLI, and the app's compose network `vulnsight_default`.

Steps:
1. Run vulnerable httpd 2.4.49 with network alias `bench-upgrade`; scan 1.
2. Analyst actions: mark CVE-2021-41773 and CVE-2022-36760 fixed, accept
   CVE-2024-38474.
3. Replace the container behind the same alias with httpd 2.4.54; scan 2.
4. U4: delete the cached NVD row for the 2.4.54 CPE and fill the app's
   own NVD rate-limiter window so every lookup times out; scan 3; restore.
5. Score against Apache's fixed-in releases (phase11/apache-fixed-in.json);
   write results/<stamp>-upgrade.{json,md}.

Docker and SQL commands are list-form subprocess calls with fixed
arguments; no shell.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
NETWORK = "vulnsight_default"
ALIAS = "bench-upgrade"
CONTAINER = "vulnsight-bench-upgrade"
IMAGE_OLD = (
    "vulhub/httpd:2.4.49@sha256:a6c32432b1ed40818488e238769e962a4151ef3b74b54416d9d5d396ba8cab5f"
)
IMAGE_NEW = "httpd:2.4.54@sha256:c13feaef62bdb03e65e645f47d9780adea5a080c78eb9e4b3c32e861327262b4"
NEW_VERSION = "2.4.54"
NEW_CPE23 = f"cpe:2.3:a:apache:http_server:{NEW_VERSION}:*:*:*:*:*:*:*"
MARK_FIXED = ["CVE-2021-41773", "CVE-2022-36760"]  # second one is the negative control
MARK_ACCEPTED = "CVE-2024-38474"
RATELIMIT_KEY = "vulnsight:nvd:ratelimit"
TERMINAL = {"completed", "failed", "cancelled"}


# ---------------------------------------------------------------- scoring (pure)


def _ver(v: str) -> tuple[int, ...]:
    return tuple(int(p) for p in v.split("."))


def evaluate(
    scan1_cves: set[str],
    states_after2: dict[str, dict],
    states_after3: dict[str, dict],
    fixed_in: dict[str, str],
) -> dict:
    """U1-U4 from the pre-registration. states_* map CVE -> item dict
    (state, verification_reason) for the bench-upgrade items."""
    listed = sorted(c for c in scan1_cves if c in fixed_in)
    expected_verified = {c for c in listed if _ver(fixed_in[c]) <= _ver(NEW_VERSION)}
    matrix = {"exp_verified": {"verified": [], "not_verified": []},
              "exp_not_verified": {"verified": [], "not_verified": []}}
    by_reason: dict[str, int] = {}
    for cve in listed:
        item = states_after2.get(cve, {})
        actual = "verified" if item.get("state") == "verified" else "not_verified"
        row = "exp_verified" if cve in expected_verified else "exp_not_verified"
        matrix[row][actual].append(cve)
        if actual == "verified":
            reason = item.get("verification_reason") or "unknown"
            by_reason[reason] = by_reason.get(reason, 0) + 1
    correct = len(matrix["exp_verified"]["verified"]) + len(
        matrix["exp_not_verified"]["not_verified"]
    )
    tp = len(matrix["exp_verified"]["verified"])
    fp = len(matrix["exp_not_verified"]["verified"])
    accuracy = round(correct / len(listed), 3) if listed else None
    u1_met = bool(listed) and accuracy >= 0.90 and tp >= 15 and fp <= 1

    def state(cve: str, after: dict) -> str | None:
        return after.get(cve, {}).get("state")

    u2 = {
        "CVE-2021-41773 ends verified": state("CVE-2021-41773", states_after2) == "verified",
        "CVE-2024-38474 ends accepted": state("CVE-2024-38474", states_after2) == "accepted",
        "CVE-2022-36760 ends open (negative control)": state("CVE-2022-36760", states_after2)
        == "open",
    }
    changed = sorted(
        c for c in states_after2 if state(c, states_after2) != state(c, states_after3)
    )
    return {
        "u1": {
            "denominator": len(listed),
            "expected_verified": len(expected_verified),
            "expected_not_verified": len(listed) - len(expected_verified),
            "matrix": matrix,
            "accuracy": accuracy,
            "verified_recall": f"{tp}/{len(expected_verified)}",
            "false_verified": fp,
            "trivial_never_verify_accuracy": (
                round((len(listed) - len(expected_verified)) / len(listed), 3) if listed else None
            ),
            "verified_by_reason": by_reason,
            "claim_met": u1_met,
        },
        "u2": {"assertions": u2, "all_hold": all(u2.values())},
        "u3": {"scan1_items": len(scan1_cves), "apache_listed": len(listed),
               "not_listed": sorted(scan1_cves - set(listed))},
        "u4": {"state_changes_in_failed_rescan": changed, "zero_changes": not changed},
    }


# ---------------------------------------------------------------- plumbing


def run(cmd: list[str], check: bool = True) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, check=check).stdout.strip()


def api(base: str, method: str, path: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {path} -> {e.code}: {e.read().decode()[:500]}")


def start_target(image: str) -> None:
    run(["docker", "rm", "-f", CONTAINER], check=False)
    run(["docker", "run", "-d", "--name", CONTAINER, "--network", NETWORK,
         "--network-alias", ALIAS, image])
    probe = (
        "import socket,time\n"
        "for _ in range(60):\n"
        "    try:\n"
        f"        socket.create_connection(('{ALIAS}',80),2).close(); break\n"
        "    except OSError: time.sleep(1)\n"
        "else: raise SystemExit('target not reachable')\n"
    )
    run(["docker", "exec", "vulnsight-worker-1", "python3", "-c", probe])


def scan(base: str, project_id: str, target_id: str) -> dict:
    s = api(base, "POST", "/scans", {"project_id": project_id, "target_id": target_id,
                                       "config": {"scanner": "nmap"}})
    deadline = time.time() + 1800
    while time.time() < deadline:
        st = api(base, "GET", f"/scans/{s['id']}/status")["status"]
        if st in TERMINAL:
            break
        time.sleep(5)
    full = api(base, "GET", f"/scans/{s['id']}")
    assets = api(base, "GET", f"/scans/{s['id']}/assets")
    svc = next((sv for a in assets for sv in a["services"] if sv["port"] == 80), {})
    print(f"scan {s['id']}: {full['status']}, lookups_failed={full['cve_lookups_failed']}, "
          f"threat_intel_failed={full['threat_intel_failed']}, version={svc.get('version')}",
          flush=True)
    return {"scan": full, "port80": {k: svc.get(k) for k in ("product", "version", "evidence")},
            "cves": sorted({f["cve_id"] for a in assets for sv in a["services"]
                            for f in sv["findings"]})}


def items_by_cve(base: str, project_id: str) -> dict[str, dict]:
    return {i["cve_id"]: i for i in api(base, "GET", f"/projects/{project_id}/remediation/items")}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8001/api/v1")
    base = parser.parse_args().api
    fixed_in = json.loads((HERE / "phase11" / "apache-fixed-in.json").read_text())["fixed_in"]
    started = dt.datetime.now(dt.timezone.utc)

    run(["docker", "exec", "vulnsight-postgres-1", "psql", "-U", "vulnsight", "-d", "vulnsight",
         "-c", "truncate cve_cache"])
    project = api(base, "POST", "/projects", {"name": f"Phase 11 upgrade test {started:%Y-%m-%d %H:%M}",
                                              "description": "Controlled httpd upgrade test"})
    target = api(base, "POST", f"/projects/{project['id']}/targets", {
        "target_type": "hostname", "value": ALIAS, "authorization_confirmed": True,
        "authorization_note": "Local benchmark container, internal Docker network only"})

    start_target(IMAGE_OLD)
    s1 = scan(base, project["id"], target["id"])
    items1 = items_by_cve(base, project["id"])
    for cve in MARK_FIXED:
        api(base, "PATCH", f"/remediation/items/{items1[cve]['id']}", {"state": "fixed"})
    api(base, "PATCH", f"/remediation/items/{items1[MARK_ACCEPTED]['id']}",
        {"state": "accepted", "note": "benchmark: risk accepted before the upgrade"})

    start_target(IMAGE_NEW)
    s2 = scan(base, project["id"], target["id"])
    items2 = items_by_cve(base, project["id"])

    # U4: forced correlation failure through the app's real outage path.
    run(["docker", "exec", "vulnsight-postgres-1", "psql", "-U", "vulnsight", "-d", "vulnsight",
         "-c", f"delete from cve_cache where cpe = '{NEW_CPE23}'"])
    far = str(int(time.time()) + 10**7)
    run(["docker", "exec", "vulnsight-redis-1", "redis-cli", "-n", "0", "ZADD", RATELIMIT_KEY,
         far, "u4-block-1", far, "u4-block-2", far, "u4-block-3", far, "u4-block-4",
         far, "u4-block-5"])
    try:
        s3 = scan(base, project["id"], target["id"])
    finally:
        run(["docker", "exec", "vulnsight-redis-1", "redis-cli", "-n", "0", "DEL", RATELIMIT_KEY])
    items3 = items_by_cve(base, project["id"])
    run(["docker", "rm", "-f", CONTAINER], check=False)

    def ok(s: dict) -> bool:
        sc = s["scan"]
        return (sc["status"] == "completed" and sc["cve_lookups_failed"] == 0
                and sc["threat_intel_failed"] == 0)

    validity = {
        "scan1_complete": ok(s1),
        "scan2_complete": ok(s2),
        "scan2_fingerprint_2.4.54": s2["port80"].get("version") == NEW_VERSION,
        "u4_scan3_lookups_failed": (s3["scan"]["cve_lookups_failed"] or 0) > 0,
    }
    result = {
        "run_started_utc": started.isoformat(timespec="seconds"),
        "vulnsight_commit": run(["git", "-C", str(HERE.parent), "rev-parse", "--short", "HEAD"]),
        "images": {"old": IMAGE_OLD, "new": IMAGE_NEW},
        "validity": validity,
        "valid": all(v for k, v in validity.items() if not k.startswith("u4")),
        "u4_valid": validity["u4_scan3_lookups_failed"],
        "metrics": evaluate(set(s1["cves"]), items2, items3, fixed_in),
        "scans": {"scan1": s1, "scan2": s2, "scan3": s3},
        "items_after": {"scan1": items1, "scan2": items2, "scan3": items3},
    }
    out = HERE / "results"
    stem = f"{started:%Y-%m-%d-%H%M}-upgrade"
    (out / f"{stem}.json").write_text(json.dumps(result, indent=2, default=str))
    (out / f"{stem}.md").write_text(render_md(result))
    print(render_md(result))


def render_md(r: dict) -> str:
    m = r["metrics"]
    u1, u2, u3, u4 = m["u1"], m["u2"], m["u3"], m["u4"]
    mx = u1["matrix"]
    lines = [
        f"# Phase 11 upgrade test {r['run_started_utc']}",
        "",
        f"VulnSight commit `{r['vulnsight_commit']}`. httpd 2.4.49 -> 2.4.54 behind one hostname. "
        "Ground truth: Apache's own fixed-in releases (`phase11/apache-fixed-in.json`).",
        "",
        f"**Run valid (scans 1-2): {r['valid']}**. Validity: {r['validity']}.",
        f"**U4 valid (scan 3 lookups actually failed): {r['u4_valid']}**.",
        "",
        "## U1: verification vs Apache's fixed-in releases",
        "",
        f"Denominator {u1['denominator']} scan-1 items (pre-registered: 88): "
        f"{u1['expected_verified']} expected verified, {u1['expected_not_verified']} not.",
        "",
        "| | actually verified | not verified |",
        "|---|---|---|",
        f"| expected verified | {len(mx['exp_verified']['verified'])} | "
        f"{len(mx['exp_verified']['not_verified'])} |",
        f"| expected not verified | {len(mx['exp_not_verified']['verified'])} | "
        f"{len(mx['exp_not_verified']['not_verified'])} |",
        "",
        f"Accuracy {u1['accuracy']} (trivial never-verify baseline "
        f"{u1['trivial_never_verify_accuracy']}); verified recall {u1['verified_recall']}; "
        f"wrongly verified {u1['false_verified']}; verified by reason {u1['verified_by_reason']}.",
        f"Claim criterion (accuracy >= 0.90, recall >= 15/16, wrongly verified <= 1): "
        f"**{'met' if u1['claim_met'] and r['valid'] else 'not met'}**.",
        "",
        f"Missed (expected verified, not verified): {mx['exp_verified']['not_verified'] or 'none'}",
        f"Wrongly verified: {mx['exp_not_verified']['verified'] or 'none'}",
        "",
        "## U2: analyst actions",
        "",
        *(f"- {k}: **{'holds' if v else 'FAILS'}**" for k, v in u2["assertions"].items()),
        "",
        "## U3: coverage",
        "",
        f"{u3['apache_listed']} of {u3['scan1_items']} scan-1 items are in Apache's list.",
        "",
        "## U4: rescan with failed correlation",
        "",
        f"State changes between scan 2 and the failed scan 3: "
        f"{u4['state_changes_in_failed_rescan'] or 'none'} -> "
        f"**{'holds' if u4['zero_changes'] and r['u4_valid'] else 'not met'}**.",
    ]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
