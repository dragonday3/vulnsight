# Errata

Corrections to committed results. The original files are left unchanged.

## 2026-11-25: Phase 9 audit, bench-es11 CVE-2015-1427

**What was wrong.** The run 4 and run 6 audits label CVE-2015-1427 on
**bench-es11** (Elasticsearch 1.1.1) as **A** (applicable), with the
reason "Groovy jar bundled". That is wrong.
`groovy-all-2.3.2.jar` ships only in the Elasticsearch **1.4.2** image
(bench-es); 1.1.1 has no Groovy engine. In the Phase 9 check, one shell
command printed both containers' output under a single heading, and the
jar was attributed to the wrong container.

**Correct label: N** (not applicable).

| | Applicable | Not applicable | Unclear |
|---|---|---|---|
| Original Phase 9 totals (run 6 audit) | 16 | 48 | 16 |
| Corrected totals | 15 | 49 | 16 |

The README and `labels/phase9-labels.json` use the corrected totals.

**Effect on Phase 10.** Found while gathering container facts for the
Phase 10 labelling, before any Phase 10 metric was computed. The
pre-registered Phase 10 thresholds (M2: N ≤ 36 and A ≥ 16) are **not**
changed. Measured against the corrected baseline, A ≥ 16 is now a
slightly harder bar.
