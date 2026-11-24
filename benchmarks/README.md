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

## Run

```bash
docker compose up -d --build && docker compose exec backend alembic upgrade head
docker compose -f benchmarks/docker-compose.bench.yml up -d
docker compose run --rm -v ./benchmarks:/benchmarks backend \
  python /benchmarks/run_benchmark.py
```

Results land in `benchmarks/results/`.
