from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.billing.quota import (
    admin_quota_bypass,
    check_concurrent_scan_quota,
    check_scan_profile_allowed,
    check_scan_quota,
    violation_to_dict,
)
from apps.api.database import get_db
from apps.api.pagination import page_meta
from apps.api.models.enums import ScanProfile, ScanStatus
from apps.api.models.user import User
from apps.api.rate_limit import cooldown_acquire
from apps.api.target_validation import TargetRejected, validate_target
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


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.post("", response_model=ScanJobResponse, status_code=201)
async def create_scan_job(
    data: ScanJobCreate, db: _DB, current_user: _CurrentUser
) -> ScanJobResponse:
    if not admin_quota_bypass(current_user):
        # Profile-level gate first — surface a "this tier doesn't include
        # X" message before we even count usage.
        profile_v = check_scan_profile_allowed(current_user, data.profile.value)
        if profile_v is not None:
            raise HTTPException(
                status_code=402, detail=violation_to_dict(profile_v),
            )
        for check in (check_scan_quota, check_concurrent_scan_quota):
            v = await check(db, current_user)
            if v is not None:
                raise HTTPException(status_code=402, detail=violation_to_dict(v))
        # Scan cooldown: at most one scan per 60s per (user, website).
        # Stops users from accidentally hammering their own site or
        # automated jobs from looping.
        cd_key = f"scan_cd:{current_user.id}:{data.website_id}"
        remaining = await cooldown_acquire(cd_key, seconds=60)
        if remaining > 0:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "scan_cooldown",
                    "message": f"Another scan was started on this website "
                               f"{60 - remaining}s ago. Try again in "
                               f"{remaining}s.",
                    "retry_after_seconds": remaining,
                },
                headers={"Retry-After": str(remaining)},
            )
    try:
        job = await sj_service.create_scan_job(
            db, data, user_id=current_user.id, is_admin=current_user.is_admin
        )
    except sj_service.WebsiteNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except sj_service.WebsiteNotVerifiedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    # Validate the final target URL — defense in depth against website
    # rows that point at private IPs.
    try:
        validate_target(job.requested_url)
    except TargetRejected as exc:
        await db.rollback()
        raise HTTPException(
            status_code=422,
            detail={"error": exc.code, "message": exc.reason},
        )
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
        user_id=_uid(current_user),
    )
    return ScanJobListResponse(
        items=[ScanJobResponse.model_validate(j) for j in items],
        total=total,
        limit=limit,
        offset=offset,
        **page_meta(total, limit, offset),
    )


@router.get("/{scan_job_id}", response_model=ScanJobResponse)
async def get_scan_job(
    scan_job_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> ScanJobResponse:
    job = await sj_service.get_scan_job(db, scan_job_id, user_id=_uid(current_user))
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanJobResponse.model_validate(job)


@router.patch("/{scan_job_id}/cancel", response_model=ScanJobResponse)
async def cancel_scan_job(
    scan_job_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> ScanJobResponse:
    try:
        job = await sj_service.cancel_scan_job(
            db, scan_job_id, user_id=_uid(current_user)
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
            db, scan_job_id, data, user_id=_uid(current_user)
        )
    except sj_service.InvalidStatusTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if job is None:
        raise HTTPException(status_code=404, detail="Scan job not found")
    await db.commit()
    return ScanJobResponse.model_validate(job)
