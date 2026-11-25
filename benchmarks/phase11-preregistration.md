# Phase 11 pre-registration: remediation lifecycle, rescan verification

Committed on 2026-11-25, **before** any Phase 11 code and before any
Phase 11 scan. `git log -- benchmarks/phase11-preregistration.md` shows
the order.

## What Phase 11 adds

- **Remediation items.** One persistent remediation item per
  (target, port, protocol, CVE), surviving across scans.
- **States**:
  - `open` and `accepted` (risk accepted, with a reason) are set by an
    analyst;
  - `fixed` means an analyst claims it is fixed;
  - `verified` is set only by a rescan.
- **Per-severity SLA:** due = first seen + 15 / 30 / 90 / 180 days
  (Critical / High / Medium / Low). A CVE in CISA KEV is capped at 14
  days.
- **Rescan sync.** It runs on nmap scans only, inside the existing
  correlation stage, so there is no new pipeline stage.
  - A tracked CVE that a rescan finds again stays, or goes back to,
    `open`. A `verified` item reopens. A `fixed` item whose fix didn't
    hold goes back to `open`. `accepted` stays `accepted`.
  - A tracked CVE that a rescan no longer finds becomes `verified`, but
    only when the rescan can be trusted. Either:
    - the port is no longer open; or
    - the port is open, the service still has CPE evidence, and the
      scan's CVE correlation was complete (`cve_lookups_failed == 0`).

    Otherwise nothing changes. (Phase 9 showed a failed lookup looks
    exactly like "no CVEs".)
- **Metrics:** MTTR, SLA-breach % and aging. These numbers are shown only
  on a clearly labelled **simulated** demo dataset. No MTTR or SLA claim
  is made from it.

## Measurement: controlled upgrade test

**Setup.** One hostname, `bench-upgrade`, on the internal Docker network.
1. **Scan 1** (nmap): vulnerable Apache httpd 2.4.49, the same
   digest-pinned image as Phase 9
   (`vulhub/httpd:2.4.49@sha256:a6c32432b1ed40818488e238769e962a4151ef3b74b54416d9d5d396ba8cab5f`).
2. **Analyst actions before the rescan:**
   - mark CVE-2021-41773 `fixed`;
   - mark CVE-2024-38474 `accepted`, with a reason.
3. **Swap.** Replace the container behind the same hostname with the
   official Apache httpd 2.4.54
   (`httpd:2.4.54@sha256:c13feaef62bdb03e65e645f47d9780adea5a080c78eb9e4b3c32e861327262b4`).
4. **Scan 2** (nmap): the rescan.

**Ground truth (independent of NVD and of VulnSight's code).** Apache's
own security advisories list the release that fixed each CVE. The
snapshot is in `benchmarks/phase11/apache-fixed-in.json`, fetched
2026-11-25: 185 CVEs, using the oldest "Fixed in" section that mentions
each.
- A scan-1 item whose CVE is in that list is **expected verified** if
  fixed-in ≤ 2.4.54.
- It is **expected not verified** (open or accepted) if fixed-in
  > 2.4.54.
- Scan-1 items whose CVE isn't in Apache's list are excluded from the
  accuracy metric and reported as a count.

**Validity.** Both scans must complete with `cve_lookups_failed == 0`
and `threat_intel_failed == 0`. Scan 2 must fingerprint the service as
httpd 2.4.54. Otherwise the run is **INVALID**: it is reported as such
and not scored.

| ID | Measure | Claim criterion |
|---|---|---|
| U1 | Agreement between each Apache-listed scan-1 item's state after scan 2 and the ground truth. Reported as a confusion matrix plus accuracy. | accuracy ≥ 0.90 |
| U2 | Analyst-action assertions: CVE-2021-41773 (marked fixed, fixed in 2.4.50) ends `verified`; CVE-2024-38474 (accepted, fixed in 2.4.60) ends `accepted`. | both hold |
| U3 | Coverage: how many scan-1 items are Apache-listed. | reported only |

## Disclosures

- **Scan-1 CVEs were known in advance.** The list of CVEs VulnSight
  matches for httpd 2.4.49 is known from the Phase 9 and 10 runs, so
  which items exist after scan 1 is not a surprise. What is not known in
  advance is how the sync treats each one after the upgrade, and that is
  what U1 measures.
- **Apache and NVD can disagree.** Apache's advisories and NVD's
  configurations sometimes disagree about affected versions. Any U1
  mismatch is listed with both views; mismatches are not dropped.
- Any code change after the first Phase 11 scan will be disclosed, and
  the pre-change result file kept, as in Phases 9 and 10.
