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
fact, every run below is INVALID. Run 5, at the final commit, is the one
meant to be published.

| Run | Backend at | Detected | Valid (today's rule) | What happened |
|---|---|---|---|---|
| [1](2026-11-24-run1.md) | `b84cf1b` (unchanged) | 2/8 | no | Tomcat 8.5.19's NVD lookup timed out (10 s limit). The other misses were nmap-vs-NVD vendor names. |
| [2](2026-11-24-run2.md) | `3c46b94` (+ vendor aliases) | 2/8 | no | NVD answered in ~13 s and 9 of 13 lookups timed out. Unusable. |
| 3, first attempt | `164d027` (+ 45 s timeout) | none | n/a | Scans ran, then the harness crashed before writing a file (`3d0c615` fixed it). |
| [3](2026-11-24-run3.md) | `164d027` | 4/8 | no | nginx/jetty CVEs were fetched but not stored (CVSS v4 vector > varchar(100)). MySQL truncated 200/421. |
| [4](2026-11-24-run4.md) | `cca95e2` (+ text column), harness `9c3f6aa` | 6/8 | no | MySQL truncated 200/421. Pages 2–3 were checked by hand and don't contain CVE-2012-2122. Both misses are NVD config gaps. [Manual audit](2026-11-24-run4-audit.md). |

All fixes behind runs 2–4 were made after seeing earlier runs on the
same targets. **These are benchmark-informed numbers, not blind ones.**
