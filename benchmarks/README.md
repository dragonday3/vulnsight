# VulnSight benchmark

Scans deliberately vulnerable [vulhub](https://github.com/vulhub/vulhub)
containers with documented CVEs. It measures:

- what VulnSight finds against what it should find;
- how its ranking compares to CVSS-only ranking.

## Honesty rules

- **Pre-registered ground truth.** `expected.json` (targets, the
  documented CVE per target, known risks) was committed in its own
  commit before any VulnSight scan of these targets. `git log --
  benchmarks/expected.json` shows the order.
- **Pinned software.** Every image is pinned by digest.
- **Live data.** Result numbers come from live runs against the live NVD
  API, never fixtures. Each result file records the run date and the
  VulnSight commit.
- **Fixes are disclosed.** If application code is changed after seeing a
  result, the pre-change result file stays committed and the change is
  disclosed. No result is called "blind" or "held-out".
- **"Version-applicable" wording.** Matched CVEs are "version-applicable":
  NVD lists the detected version as affected. That is not "confirmed
  exploitable". A manual top-10 audit per target labels matches
  applicable / not-applicable / unclear, and says it is manual judgement.

## Safety

- Targets publish no host ports.
- Targets are reachable only on the app's own Docker network, so no scan
  leaves the Docker host.
- Stop them when done:
  `docker compose -f benchmarks/docker-compose.bench.yml down`.

## Metrics

These were defined in the project's (unpublished) Phase 9 plan before the
first run. They are listed here after the fact.

| Metric | What it measures |
|---|---|
| Fingerprint | Nmap product/version/CPE for the target port. |
| Documented-CVE recall | Detected / documented. |
| CVEs matched | Per target, after same-CVE dedup. |
| Rank | Best–worst tie-aware rank of each detected documented CVE among its service's findings, under CVSS-only and under VulnSight ordering. |
| Misconfigurations | Informational only. |

The **manual top-10 applicability audit** is done by hand after each run
(e.g. `results/2026-11-24-run4-audit.md`).

A run is **INVALID**, rather than reporting a lower recall, if any of
these is true for any target:
- a CVE lookup failed, was truncated, was stale, or was not stored;
- the scan didn't complete;
- the scan's `cve_lookups_failed` isn't 0;
- the target port was closed.

## Run

```bash
docker compose up -d --build && docker compose exec backend alembic upgrade head
docker compose -f benchmarks/docker-compose.bench.yml up -d
# Optional: start from a cold CVE cache so every lookup is live.
docker compose exec postgres psql -U vulnsight -c "truncate cve_cache"
docker compose run --rm -v ./benchmarks:/benchmarks \
  -e VULNSIGHT_COMMIT=$(git rev-parse --short HEAD) backend \
  python /benchmarks/run_benchmark.py
```

Results land in `benchmarks/results/`. See `results/README.md` for every
recorded run.

Without an NVD API key the limit is 5 requests per 30 s, shared by all
scans. A cold-cache run of all 8 targets makes 13 CPE lookups, aliases
included (about 15 NVD requests with MySQL's extra pages). The last ones can wait close to the rate limiter's 60 s
maximum, so a run can come out INVALID from rate limiting alone. If it
does, re-run it, or set `NVD_API_KEY`.
