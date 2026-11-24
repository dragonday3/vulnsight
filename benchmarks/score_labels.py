"""Phase 10 metrics, exactly as pre-registered in phase10-preregistration.md
(M1-M4 plus M2-heldout). Written before the Phase 10 benchmark run.

    py score_labels.py results/<stem>.json results/<stem>-labels.json

`<stem>-labels.json` holds the blind labels for the run's label sheet:
{"method": "...", "labels": {host: {cve: "A"|"N"|"U"}}}. Phase 9 labels
come from labels/phase9-labels.json. Writes results/<stem>-metrics.md and
prints the same text. Stdlib only.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASELINE = {"A": 16, "N": 48, "U": 16}  # Phase 9 run 6, 80 labels


def _counts(labels: list[str]) -> dict[str, int]:
    c = Counter(labels)
    return {k: c.get(k, 0) for k in "ANU"}


def score(run: dict, known: dict, new: dict) -> tuple[str, dict]:
    s = run["summary"]
    out: list[str] = [f"# Phase 10 metrics for run {run['run_started_utc']}", ""]
    out.append(f"Run valid: **{s['valid']}**. VulnSight commit `{run['vulnsight_commit']}`.")
    out.append("")

    # M1: ranking.
    cv, vs = s["mean_rank_cvss_only"], s["mean_rank_vulnsight"]
    m1 = vs[1] is not None and cv[1] is not None and vs[1] < cv[1]
    out += ["## M1: ranking", "",
            f"Mean tie-aware rank of detected documented CVEs: CVSS-only {cv[0]}-{cv[1]}, "
            f"VulnSight {vs[0]}-{vs[1]}. Criterion (VulnSight worst < CVSS-only worst): "
            f"**{'met' if m1 else 'not met'}**.", ""]

    # M2: in-sample applicability.
    main = [t for t in run["targets"] if not t.get("heldout")]
    rows, prev, newly, worst = [], [], [], []
    for t in main:
        labs = []
        for f in t["top_by_vulnsight"]:
            cve = f["cve"]
            if cve in known.get(t["host"], {}):
                lab = known[t["host"]][cve]
                prev.append(lab)
            else:
                lab = new.get(t["host"], {}).get(cve, "?")
                newly.append(lab)
            labs.append(lab)
            worst.append("N" if (lab == "U" and cve not in known.get(t["host"], {})) else lab)
        c = _counts(labs)
        rows.append(f"| {t['host']} | {c['A']} | {c['N']} | {c['U']} |")
    total = _counts(prev + newly)
    wc = _counts(worst)
    m2 = total["N"] <= 36 and total["A"] >= 16
    out += ["## M2: applicability, 8 original targets (in-sample)", "",
            "| Target | A | N | U |", "|---|---|---|---|", *rows,
            f"| **Total** | **{total['A']}** | **{total['N']}** | **{total['U']}** |", "",
            f"Baseline (Phase 9 run 6): A {BASELINE['A']}, N {BASELINE['N']}, U {BASELINE['U']}.",
            f"Previously audited CVEs in the top 10: {len(prev)} {_counts(prev)}; "
            f"newly surfaced: {len(newly)} {_counts(newly)}.",
            f"Worst case (newly surfaced U counted as N): A {wc['A']}, N {wc['N']}, U {wc['U']}.",
            f"Claim criterion (N <= 36 and A >= 16): **{'met' if m2 else 'not met'}**.", ""]
    if "?" in prev + newly:
        out.append("**Warning: some top-10 CVEs have no label.**\n")

    # M2-heldout.
    held = [t for t in run["targets"] if t.get("heldout")]
    if held:
        hv, hc, hrows = [], [], []
        for t in held:
            lab = new.get(t["host"], {})
            v = [lab.get(f["cve"], "?") for f in t["top_by_vulnsight"]]
            c = [lab.get(cve, "?") for cve in t["top_by_cvss"]]
            hv += v
            hc += c
            cv_, cc_ = _counts(v), _counts(c)
            hrows.append(f"| {t['host']} | {cv_['A']}/{cv_['N']}/{cv_['U']} | "
                         f"{cc_['A']}/{cc_['N']}/{cc_['U']} |")
        tv, tc = _counts(hv), _counts(hc)
        m2h = tv["N"] <= 0.75 * tc["N"] and tv["A"] >= tc["A"] and tc["N"] > 0
        out += ["## M2-heldout: applicability, 3 never-audited targets (out-of-sample)", "",
                "| Target | VulnSight top 10 A/N/U | CVSS-only top 10 A/N/U |", "|---|---|---|",
                *hrows,
                f"| **Total** | **{tv['A']}/{tv['N']}/{tv['U']}** | "
                f"**{tc['A']}/{tc['N']}/{tc['U']}** |", "",
                "Claim criterion (VulnSight N <= 0.75 x CVSS-only N, and A not lower): "
                f"**{'met' if m2h else 'not met'}**.", ""]
        if "?" in hv + hc:
            out.append("**Warning: some held-out top-10 CVEs have no label.**\n")

    # M3: harm + flag rate.
    harms = []
    for t in main:
        for d in t["documented"]:
            if not d["detected"]:
                continue
            if d.get("unverified_prerequisite"):
                harms.append(f"{d['cve']} on {t['host']}: flagged "
                             f"({d['unverified_prerequisite']})")
            if d["rank_vulnsight"][1] > d["rank_cvss"][1]:
                harms.append(f"{d['cve']} on {t['host']}: worst rank {d['rank_vulnsight'][1]} "
                             f"vs CVSS-only {d['rank_cvss'][1]}")
    rules = run.get("applicability_rules", {})
    out += ["## M3: harm and flag rate", "",
            *(f"- {h}" for h in harms or ["No detected documented CVE was flagged or ranked worse."]),
            f"- Flag rate (8 original targets): {s['findings_flagged']}/{s['findings_total']} "
            "matched CVEs flagged with an unverified prerequisite.",
            *(f"  - {t['host']}: {t['findings_flagged']}/{t['findings_total']}" for t in main),
            f"- Rules at this commit: {rules.get('features')} features, "
            f"{rules.get('patterns')} patterns.", ""]

    # M4: recall.
    out += ["## M4: recall", "",
            f"Documented CVEs detected: {s['documented_detected']}/{s['documented_total']} "
            "(must stay 6/8).", ""]
    if run.get("heldout_summary"):
        h = run["heldout_summary"]
        out.append(f"Held-out recall (no claim): {h['documented_detected']}/"
                   f"{h['documented_total']}.\n")
    return "\n".join(out) + "\n", {"m1": m1, "m2": m2}


def main() -> None:
    run_path, labels_path = Path(sys.argv[1]), Path(sys.argv[2])
    run = json.loads(run_path.read_text())
    known = json.loads((HERE / "labels" / "phase9-labels.json").read_text())["labels"]
    new = json.loads(labels_path.read_text())["labels"]
    text, _ = score(run, known, new)
    out = run_path.with_name(run_path.stem + "-metrics.md")
    out.write_text(text)
    print(text)


if __name__ == "__main__":
    main()
