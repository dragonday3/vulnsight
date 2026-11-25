import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.models.remediation import RemediationItem, RemediationState
from app.schemas.remediation import RemediationItemRead, RemediationMetrics, RemediationUpdate
from app.services import remediation_service

router = APIRouter(tags=["remediation"])


@router.get("/projects/{project_id}/remediation/items", response_model=list[RemediationItemRead])
def list_remediation_items(
    project_id: uuid.UUID,
    state: RemediationState | None = None,
    db: Session = Depends(get_db),
) -> list[RemediationItem]:
    return remediation_service.list_items(db, project_id, state)


@router.get("/projects/{project_id}/remediation/metrics", response_model=RemediationMetrics)
def get_remediation_metrics(project_id: uuid.UUID, db: Session = Depends(get_db)) -> dict:
    return remediation_service.project_metrics(db, project_id)


@router.patch("/remediation/items/{item_id}", response_model=RemediationItemRead)
def update_remediation_item(
    item_id: uuid.UUID, data: RemediationUpdate, db: Session = Depends(get_db)
) -> RemediationItem:
    return remediation_service.update_item(db, item_id, data)
