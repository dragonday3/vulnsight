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
