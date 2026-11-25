"""Remediation metrics (Phase 11): pure function over items. No DB, no
network; never raises on well-formed items.

Definitions:
- unresolved: open or fixed (a fix claim isn't a fix until a rescan
  verifies it). Accepted (risk-accepted) items are reported separately
  and are outside the SLA.
- MTTR: mean days from first_seen_at to verified_at, over verified items.
- SLA breach %: over items whose deadline has passed or that were
  verified, the share verified after the deadline or still unresolved
  past it.
- aging: unresolved items bucketed by days since first seen.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from app.models.remediation import RemediationItem, RemediationState
from app.modules.remediation.config import AGING_BUCKETS

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE")
_UNRESOLVED = {RemediationState.OPEN, RemediationState.FIXED}


def _days(delta_seconds: float) -> float:
    return delta_seconds / 86400.0


def compute(items: Iterable[RemediationItem], now: datetime) -> dict:
    items = list(items)
    unresolved = [i for i in items if i.state in _UNRESOLVED]
    # (item, verified_at) so the timestamp is known non-null below.
    verified_pairs = [
        (i, i.verified_at)
        for i in items
        if i.state == RemediationState.VERIFIED and i.verified_at is not None
    ]
    verified = [i for i, _ in verified_pairs]

    def mttr(severity: str | None = None) -> float | None:
        days = [
            _days((at - i.first_seen_at).total_seconds())
            for i, at in verified_pairs
            if severity is None or i.severity == severity
        ]
        return round(sum(days) / len(days), 1) if days else None

    overdue = [i for i in unresolved if i.due_at < now]
    breach_population: list[RemediationItem] = verified + overdue
    breached = [i for i, at in verified_pairs if at > i.due_at] + overdue

    aging = {label: 0 for label, _ in AGING_BUCKETS}
    for item in unresolved:
        age = _days((now - item.first_seen_at).total_seconds())
        for label, upper in AGING_BUCKETS:
            if upper is None or age <= upper:
                aging[label] += 1
                break

    return {
        "total": len(items),
        "by_state": {s.value: sum(1 for i in items if i.state == s) for s in RemediationState},
        "unresolved_by_severity": {
            sev: sum(1 for i in unresolved if i.severity == sev) for sev in _SEVERITIES
        },
        "overdue_now": len(overdue),
        "sla_breach_pct": (
            round(100.0 * len(breached) / len(breach_population), 1) if breach_population else None
        ),
        "mttr_days": mttr(),
        "mttr_days_by_severity": {sev: mttr(sev) for sev in _SEVERITIES},
        "aging_unresolved": aging,
        "simulated": any(i.simulated for i in items),
    }
