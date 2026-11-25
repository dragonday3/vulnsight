"""Seed a SIMULATED remediation demo project (Phase 11).

Everything this creates is fake and labelled so in the data:
- the project name starts with "SIMULATED";
- every RemediationItem has simulated=True, which makes the UI show a
  "SIMULATED DATA" banner and a badge on each row;
- the target is never scanned.

It exists only to show what MTTR, SLA-breach and aging metrics look like
over months of activity, which a real scan of a lab target can't
produce. No number derived from it may be presented as a measurement.

    docker compose exec backend python -m app.scripts.seed_simulated_remediation

Idempotent: does nothing if the demo project already exists.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

import app.db.base  # noqa: F401  (registers every model)
from app.db.session import SessionLocal
from app.models.project import Project
from app.models.remediation import RemediationItem, RemediationState
from app.models.target import Target, TargetType
from app.modules.remediation.sync import sla_due

PROJECT_NAME = "SIMULATED remediation demo"
SEED = 11  # fixed, so the demo is reproducible
SEVERITIES = [("CRITICAL", 9.8), ("HIGH", 7.5), ("MEDIUM", 5.3), ("LOW", 3.1)]


def seed(db: Session, now: datetime | None = None) -> Project | None:
    if db.query(Project).filter(Project.name == PROJECT_NAME).first() is not None:
        return None
    now = now or datetime.now(UTC)
    rng = random.Random(SEED)

    project = Project(
        name=PROJECT_NAME,
        description="SIMULATED demo data for the remediation metrics. Not real scans.",
    )
    db.add(project)
    db.flush()
    target = Target(
        project_id=project.id,
        value="simulated-demo.invalid",
        target_type=TargetType.HOSTNAME,
        authorization_confirmed=True,
        authorization_note="Simulated demo target; never scanned.",
    )
    db.add(target)
    db.flush()

    for n in range(40):
        severity, cvss = SEVERITIES[n % 4]
        kev = n % 9 == 0
        first_seen = now - timedelta(days=rng.randint(1, 200))
        due = sla_due(first_seen, severity, kev)
        state = rng.choices(
            [
                RemediationState.VERIFIED,
                RemediationState.OPEN,
                RemediationState.ACCEPTED,
                RemediationState.FIXED,
            ],
            weights=[50, 30, 10, 10],
        )[0]
        item = RemediationItem(
            project_id=project.id,
            target_id=target.id,
            port=[80, 443, 8080, 3306][n % 4],
            protocol="tcp",
            cve_id=f"CVE-0000-{n:04d}",  # deliberately not a real CVE id
            severity=severity,
            cvss_score=cvss,
            kev=kev,
            state=state,
            note="simulated" if state == RemediationState.ACCEPTED else None,
            first_seen_at=first_seen,
            last_seen_at=first_seen,
            due_at=due,
            state_changed_at=first_seen,
            simulated=True,
        )
        if state == RemediationState.VERIFIED:
            fixed_after = timedelta(days=rng.randint(2, 120))
            item.verified_at = min(first_seen + fixed_after, now)
            item.fixed_at = item.verified_at
            item.verification_reason = "cve_not_matched"
            item.last_seen_at = item.verified_at - timedelta(days=1)
        db.add(item)
    db.commit()
    return project


def main() -> None:
    with SessionLocal() as db:
        project = seed(db)
        print(
            f"Seeded SIMULATED project {project.id}"
            if project
            else f"'{PROJECT_NAME}' already exists; nothing seeded."
        )


if __name__ == "__main__":
    main()
