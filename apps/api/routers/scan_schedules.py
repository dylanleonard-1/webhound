from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.billing.quota import check_monitoring_allowed, violation_to_dict
from apps.api.database import get_db
from apps.api.pagination import page_meta
from apps.api.models.user import User
from apps.api.schemas.scan_schedules import (
    ScanScheduleCreate,
    ScanScheduleListResponse,
    ScanSchedulePatch,
    ScanScheduleResponse,
)
from apps.api.security import get_current_user
from apps.api.services import scan_schedules as ss_service

router = APIRouter(prefix="/scan-schedules", tags=["scan-schedules"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.post("", response_model=ScanScheduleResponse, status_code=201)
async def create_scan_schedule(
    data: ScanScheduleCreate, db: _DB, current_user: _CurrentUser
) -> ScanScheduleResponse:
    if not current_user.is_admin:
        v = check_monitoring_allowed(current_user)
        if v is not None:
            raise HTTPException(status_code=402, detail=violation_to_dict(v))
    try:
        schedule = await ss_service.create_schedule(
            db, data, user_id=current_user.id, is_admin=current_user.is_admin
        )
    except ss_service.WebsiteNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    await db.commit()
    return ScanScheduleResponse.model_validate(schedule)


@router.get("", response_model=ScanScheduleListResponse)
async def list_scan_schedules(
    db: _DB,
    current_user: _CurrentUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    website_id: uuid.UUID | None = None,
) -> ScanScheduleListResponse:
    items, total = await ss_service.list_schedules(
        db, _uid(current_user), website_id=website_id, limit=limit, offset=offset
    )
    return ScanScheduleListResponse(
        items=[ScanScheduleResponse.model_validate(s) for s in items],
        total=total,
        limit=limit,
        offset=offset,
        **page_meta(total, limit, offset),
    )


@router.get("/{schedule_id}", response_model=ScanScheduleResponse)
async def get_scan_schedule(
    schedule_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> ScanScheduleResponse:
    schedule = await ss_service.get_schedule(db, schedule_id, _uid(current_user))
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return ScanScheduleResponse.model_validate(schedule)


@router.patch("/{schedule_id}", response_model=ScanScheduleResponse)
async def update_scan_schedule(
    schedule_id: uuid.UUID,
    data: ScanSchedulePatch,
    db: _DB,
    current_user: _CurrentUser,
) -> ScanScheduleResponse:
    schedule = await ss_service.update_schedule(db, schedule_id, data, _uid(current_user))
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.commit()
    return ScanScheduleResponse.model_validate(schedule)


@router.delete("/{schedule_id}", status_code=204)
async def delete_scan_schedule(
    schedule_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> None:
    deleted = await ss_service.delete_schedule(db, schedule_id, _uid(current_user))
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.commit()
