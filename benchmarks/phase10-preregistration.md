# Phase 10 pre-registration: exploit likelihood + applicability evidence

Committed on 2026-11-24, **before** any Phase 10 code and any Phase 10
benchmark run. `git log -- benchmarks/phase10-preregistration.md` shows
the order.

## What changes

1. **Threat intel.** Each matched CVE gets CISA KEV membership and an
   EPSS score. These are fetched in the existing correlation stage.
2. **Applicability evidence.** A matched CVE whose description names a
   prerequisite feature gets flagged `unverified_prerequisite` when
   VulnSight has no positive evidence of that feature on the target. The
   features include HTTP/2, TLS, mod_proxy, mod_lua, DIGEST auth and
   others. The finding stays visible; it is never hidden.
3. **Per-finding risk contribution**, with these constants fixed now:

```
severity = cvss*10 (or severity fallback weight), capped at 100
exploit  = 1.0 if KEV else (EPSS probability if known else 0.0)
base     = 0.5*severity + 0.5*100*exploit
contribution = base * confidence/100 * (0.3 if unverified_prerequisite else 1.0)
```

False positives still contribute 0. The noisy-OR aggregation is
unchanged.

## Metrics

**Evaluation setup**:
- one VALID run of `benchmarks/run_benchmark.py` at the final Phase 10
  commit;
- the same 8 targets as Phase 9, with a cold CVE cache;
- validity additionally requires every scan's threat-intel fetches to
  succeed.

| ID | Measure | Baseline (Phase 9 run 6) | Success criterion |
|---|---|---|---|
| M1 | Mean tie-aware rank (best–worst) of detected documented CVEs, VulnSight vs CVSS-only | 3.5–9.33 for both | VulnSight mean worst rank < CVSS-only mean worst rank, in the same run |
| M2 | Not-applicable share of each target's VulnSight top 10, summed over 8 targets | 48/80 not applicable (16 applicable, 16 unclear) | Below 48/80 |
| M3 | Harm: detected documented CVEs flagged `unverified_prerequisite`, or ranked worse than under CVSS-only | — | Reported in full; any case counts against the change |
| M4 | Documented-CVE recall | 6/8 | Unchanged |

**M2 labelling rule.**
- CVEs labelled in the Phase 9 run-6 audit keep their labels.
- A CVE newly entering a top 10 is labelled from the same container
  config facts and rubric, *before* its new rank or flag is looked at.
- Results are reported separately for "previously audited" and "newly
  surfaced" CVEs.

## Amendment 1 (2026-11-24, still before any Phase 10 code or run)

This amendment follows a review of the original pre-registration. It is
committed separately, so the original text above stays as it was.

**Units.** `severity` is on a 0–100 scale: CVSS 0–10 × 10, or the
fallback weight, which is already 0–100. `100*exploit` is also 0–100.
The two terms are equally weighted on the same scale.

**M1 framing.** vulhub environments are chosen *because* their CVEs are
famous and exploited. A KEV/EPSS weighting will push them up almost by
construction. If M1 holds, it shows the ordering does what KEV and EPSS
are meant to do. It is **not** evidence of general ranking skill.

**M2, replaced with a stricter rule** (8 original targets, in-sample):
- Report the A/N/U counts in the VulnSight top 10 per target and in
  total, next to the baseline 16/48/16.
- A **claim** of improvement is made only if both hold:
  - N ≤ 36/80, a cut of at least 25%;
  - A ≥ 16, so the applicable count does not fall.
- **U** (unclear) is reported separately and never counted as an
  improvement.
- The result is also reported with every newly surfaced U counted as N,
  the worst case.

**M2-heldout (new, out-of-sample).** This runs on 3 new targets that were
never scanned or audited: `benchmarks/expected-heldout.json`, committed
with this amendment.
- **Blind labelling.** After the run, the harness writes a labelling sheet
  for each held-out target. The sheet holds the union of that target's
  CVSS-only top 10 and VulnSight top 10. It is sorted by CVE id and shows
  only the CVE id and description: no score, rank, flag, or which list it
  came from.
- Labels are A/N/U, using the same rubric with container config checked
  in place. The labelled sheet is committed *before* the held-out metric
  is computed.
- **Metric**: the N count in the VulnSight top 10 vs the CVSS-only top 10,
  for the same targets in the same run.
- **Claim** only if both hold:
  - VulnSight N ≤ 0.75 × CVSS-only N;
  - VulnSight A ≥ CVSS-only A.
- Documented-CVE recall on the held-out targets is reported as its own
  row. No claim is made for it.

**M3, extended.** Also report:
- the **flag rate**: the share of all matched CVEs, per target and in
  total, that get `unverified_prerequisite`;
- the number of rule features and regexes in the applicability table at
  the run's commit.

## Disclosures

- **KEV/EPSS values were seen first.** The KEV membership and EPSS
  scores of the documented CVEs were looked up *before* the constants
  above were fixed. Four of the six detected documented CVEs are in
  KEV, and all have EPSS ≥ 0.6. **M1 is not a blind test.** It shows the
  mechanism works on known-exploited CVEs.
- **Rules came from the audit.** The applicability rule list was written
  *after* seeing the Phase 9 manual audits, which name the features
  behind the not-applicable matches. **M2 on previously audited CVEs is
  in-sample.** Only the "newly surfaced" group is out-of-sample, weakly.
- Any rule or constant change after the first Phase 10 run will be
  disclosed, and the pre-change result file kept.
