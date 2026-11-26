import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.deps import get_db
from app.schemas.importing import ImportResult
from app.services import import_service

router = APIRouter(tags=["imports"])

MAX_IMPORT_BYTES = 20 * 1024 * 1024


@router.post(
    "/projects/{project_id}/imports",
    response_model=ImportResult,
    status_code=status.HTTP_201_CREATED,
)
async def import_scan_report(
    project_id: uuid.UUID, request: Request, db: Session = Depends(get_db)
) -> dict:
    """Body: the raw .nessus v2 or OpenVAS/Greenbone XML file (no multipart).
    Read with a hard cap, so an oversized upload is refused before it is
    buffered whole."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_IMPORT_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"Report file is larger than {MAX_IMPORT_BYTES // (1024 * 1024)} MB",
            )
        chunks.append(chunk)
    # Parsing and the DB writes are blocking: keep them off the event loop.
    return await run_in_threadpool(import_service.import_report, db, project_id, b"".join(chunks))
