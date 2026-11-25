"""Remediation SLA policy (Phase 11). Chosen by the user on 2026-11-25 and
pre-registered in benchmarks/phase11-preregistration.md."""

# Days from first sighting to the remediation deadline, by severity.
SLA_DAYS: dict[str, int] = {
    "CRITICAL": 15,
    "HIGH": 30,
    "MEDIUM": 90,
    "LOW": 180,
}
# Severity NONE (no CVSS data) gets the most lenient deadline.
SLA_DAYS_DEFAULT = 180
# A CVE in CISA's KEV catalog is capped at this many days, whatever its
# severity (the deadline style of CISA BOD 22-01).
KEV_SLA_DAYS = 14

# Aging buckets for unresolved items, in days since first seen: (label, max).
AGING_BUCKETS: list[tuple[str, int | None]] = [
    ("0-30", 30),
    ("31-60", 60),
    ("61-90", 90),
    ("90+", None),
]
