"""Remediation items (Phase 11): list, analyst transitions, metrics.

Items are created and verified only by modules/remediation/sync.py during
a scan; this service lets an analyst move an item between open, accepted
and fixed, and computes the project's metrics.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError, ValidationConflictError
from app.models.project import Project
from app.models.remediation import RemediationItem, RemediationState
from app.modules.remediation import metrics
from app.schemas.remediation import RemediationUpdate

# Analyst transitions. `verified` is never a target: only a rescan verifies.
_ALLOWED: dict[RemediationState, set[RemediationState]] = {
    RemediationState.OPEN: {RemediationState.ACCEPTED, RemediationState.FIXED},
    RemediationState.ACCEPTED: {RemediationState.OPEN},
    RemediationState.FIXED: {RemediationState.OPEN},
    RemediationState.VERIFIED: set(),
}


def _get_project(db: Session, project_id: uuid.UUID) -> Project:
    project = db.get(Project, project_id)
    if project is None:
        raise NotFoundError(f"Project {project_id} not found")
    return project


def list_items(
    db: Session, project_id: uuid.UUID, state: RemediationState | None = None
) -> list[RemediationItem]:
    _get_project(db, project_id)
    query = db.query(RemediationItem).filter(RemediationItem.project_id == project_id)
    if state is not None:
        query = query.filter(RemediationItem.state == state)
    return query.order_by(RemediationItem.due_at, RemediationItem.cve_id).all()


def update_item(db: Session, item_id: uuid.UUID, data: RemediationUpdate) -> RemediationItem:
    # Row lock: waits for a running rescan sync of this item to commit, so
    # the analyst's change is never decided on, or overwritten by, a stale read.
    item = db.get(RemediationItem, item_id, with_for_update=True, populate_existing=True)
    if item is None:
        raise NotFoundError(f"Remediation item {item_id} not found")
    if data.state != item.state and data.state not in _ALLOWED[item.state]:
        raise ValidationConflictError(
            f"Cannot move a remediation item from {item.state.value} to {data.state.value}"
            + (" (only a rescan can verify)" if data.state == RemediationState.VERIFIED else "")
        )
    if data.state == RemediationState.ACCEPTED and not (data.note or "").strip():
        raise ValidationConflictError("Accepting the risk requires a reason in `note`")
    now = datetime.now(UTC)
    if data.state != item.state:
        item.state = data.state
        item.state_changed_at = now
        item.fixed_at = now if data.state == RemediationState.FIXED else None
    item.note = data.note
    db.commit()
    db.refresh(item)
    return item


def project_metrics(db: Session, project_id: uuid.UUID) -> dict:
    _get_project(db, project_id)
    items = db.query(RemediationItem).filter(RemediationItem.project_id == project_id).all()
    return metrics.compute(items, datetime.now(UTC))
