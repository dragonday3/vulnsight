# Recorded benchmark runs

Every run is kept exactly as recorded. Nothing is deleted or edited
after its commit.

**Cache state**: `cve_cache` was emptied before every run, so all NVD
lookups were live. Run 1 started on an empty table, checked before the
run. Later result files also record `cve_cache_rows_at_start`.

**Code that ran**: the worker doesn't hot-reload. Before each run from
run 2 on, the worker was restarted and the fix under test was confirmed
by grepping it inside the container. Run 1 used the unchanged
`b84cf1b` code.

**Images**: the benchmark scans the published vulhub base images
unmodified. The vulhub environments for httpd/CVE-2021-41773 and
tomcat/CVE-2017-12615 add exploit-enabling config on top. Version
detection and CVE matching don't depend on that config, but the manual
audit judges the containers as they actually ran.

**Validity**: a later rule marks a run INVALID if any lookup failed,
was truncated or wasn't stored (see `../README.md`). Applied after the
fact, runs 1–4 are INVALID. Runs 5 and 6 were checked by the harness
itself. **Run 6 is the published result.**

| Run | Backend at | Detected | Valid (today's rule) | What happened |
|---|---|---|---|---|
| [1](2026-11-24-run1.md) | `b84cf1b` (unchanged) | 2/8 | no | Tomcat 8.5.19's NVD lookup timed out (10 s limit). The other misses were nmap-vs-NVD vendor names. |
| [2](2026-11-24-run2.md) | `3c46b94` (+ vendor aliases) | 2/8 | no | NVD answered in ~13 s and 9 of 13 lookups timed out. Unusable. |
| 3, first attempt | `164d027` (+ 45 s timeout) | none | n/a | Scans ran, then the harness crashed before writing a file (`3d0c615` fixed it). |
| [3](2026-11-24-run3.md) | `164d027` | 4/8 | no | nginx/jetty CVEs were fetched but not stored (CVSS v4 vector > varchar(100)). MySQL truncated 200/421. |
| [4](2026-11-24-run4.md) | `cca95e2` (+ text column), harness `9c3f6aa` | 6/8 | no | MySQL truncated 200/421. Pages 2–3 were checked by hand and don't contain CVE-2012-2122. Both misses are NVD config gaps. [Manual audit](2026-11-24-run4-audit.md). |
| [5](2026-11-24-run5.md) | `1caa203` (final: + pagination, completeness counts) | 5/8 | no (harness) | NVD answered 429 to the `elastic:elasticsearch:1.4.2` lookup, so ES 1.4.2's CVE was missed. Repeated with no code change. |
| [6](2026-11-24-run6.md) | `1caa203` (same) | **6/8** | **yes** | All lookups live (cache rows at start: 0) and stored; MySQL fetched in full (422). [Manual audit](2026-11-24-run6-audit.md): 16 applicable, 48 not, 16 unclear of 80. |

All fixes behind runs 2–4 were made after seeing earlier runs on the
same targets. **These are benchmark-informed numbers, not blind ones.**

## Phase 10 (exploit likelihood + applicability)

Pre-registration: [`../phase10-preregistration.md`](../phase10-preregistration.md),
committed before any Phase 10 code.

| Run | App code | Valid | What happened |
|---|---|---|---|
| [2026-11-24-1910](2026-11-24-1910.md) | `ed38b95` | no | 11 scans queued at once. NVD answered 429 to one lookup, and the rate limiter's 60 s wait expired for another. Its label sheet was discarded unused. |
| [2026-11-24-1914](2026-11-24-1914.md) | `ed38b95`; harness `f12b09c` runs scans one at a time | **yes** | Published Phase 10 result. |

Files for the published run (all under `2026-11-24-1914`):

| File | What it holds | Committed |
|---|---|---|
| [labelsheet](2026-11-24-1914-labelsheet.md) | The blind sheet | Before labelling |
| [labeller-facts](2026-11-24-1914-labeller-facts.md) | The raw container facts the labeller was given | With the labels |
| [labels](2026-11-24-1914-labels.json) | The labels, plus a `method` note including a Jetty facts correction | Before scoring |
| [metrics](2026-11-24-1914-metrics.md) | M1–M4 and M2-heldout, computed by `../score_labels.py` | After the labels |

Corrections are in [ERRATA.md](ERRATA.md).

## Phase 11 (remediation lifecycle)

Pre-registration: [`../phase11-preregistration.md`](../phase11-preregistration.md),
with three amendments, all committed before any Phase 11 code or scan.

| Run | App code | Valid | Result |
|---|---|---|---|
| [2026-11-25-1808-upgrade](2026-11-25-1808-upgrade.md) | `ba0ebd7` | **yes** (U4 valid too) | U1 16/16 verified, 0/72 wrongly verified; U2 3/3; U4 0 state changes |
