from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.enums import ScanProfile, ScanStatus
from apps.api.models.user import User
from apps.api.schemas.scan_jobs import (
    ScanJobCreate,
    ScanJobListResponse,
    ScanJobResponse,
    ScanJobStatusUpdate,
)
from apps.api.security import get_current_user
from apps.api.services import scan_jobs as sj_service
from worker.scan_tasks import run_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scan-jobs", tags=["scan-jobs"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]


@router.post("", response_model=ScanJobResponse, status_code=201)
async def create_scan_job(
    data: ScanJobCreate, db: _DB, current_user: _CurrentUser
) -> ScanJobResponse:
    try:
        job = await sj_service.create_scan_job(db, data, user_id=current_user.id)
    except sj_service.WebsiteNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    try:
        task = run_scan.delay(str(job.id), job.requested_url, job.profile.value)
        job.celery_task_id = task.id
    except Exception:
        logger.warning("failed to enqueue scan task for job %s", job.id)
    await db.commit()
    return ScanJobResponse.model_validate(job)


@router.get("", response_model=ScanJobListResponse)
async def list_scan_jobs(
    db: _DB,
    current_user: _CurrentUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    website_id: uuid.UUID | None = None,
    status: ScanStatus | None = None,
    profile: ScanProfile | None = None,
) -> ScanJobListResponse:
    items, total = await sj_service.list_scan_jobs(
        db,
        limit=limit,
        offset=offset,
        website_id=website_id,
        status=status,
        profile=profile.value if profile else None,
        user_id=current_user.id,
    )
    return ScanJobListResponse(
        items=[ScanJobResponse.model_validate(j) for j in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{scan_job_id}", response_model=ScanJobResponse)
async def get_scan_job(
    scan_job_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> ScanJobResponse:
    job = await sj_service.get_scan_job(db, scan_job_id, user_id=current_user.id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanJobResponse.model_validate(job)


@router.patch("/{scan_job_id}/cancel", response_model=ScanJobResponse)
async def cancel_scan_job(
    scan_job_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> ScanJobResponse:
    try:
        job = await sj_service.cancel_scan_job(
            db, scan_job_id, user_id=current_user.id
        )
    except sj_service.InvalidStatusTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    await db.commit()
    return ScanJobResponse.model_validate(job)


@router.patch("/{scan_job_id}/status", response_model=ScanJobResponse)
async def update_scan_job_status(
    scan_job_id: uuid.UUID,
    data: ScanJobStatusUpdate,
    db: _DB,
    current_user: _CurrentUser,
) -> ScanJobResponse:
    try:
        job = await sj_service.update_scan_job_status(
            db, scan_job_id, data, user_id=current_user.id
        )
    except sj_service.InvalidStatusTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    await db.commit()
    return ScanJobResponse.model_validate(job)
