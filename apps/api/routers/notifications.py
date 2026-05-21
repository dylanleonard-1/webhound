from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.pagination import page_meta
from apps.api.models.enums import NotificationSeverity, NotificationType
from apps.api.models.user import User
from apps.api.schemas.notifications import (
    NotificationListResponse,
    NotificationResponse,
    UnreadCountResponse,
)
from apps.api.security import get_current_user
from apps.api.services import notifications as notif_service

router = APIRouter(prefix="/notifications", tags=["notifications"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]


@router.get("", response_model=NotificationListResponse)
async def list_notifications(
    db: _DB,
    current_user: _CurrentUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    is_read: bool | None = None,
    type: NotificationType | None = None,
    severity: NotificationSeverity | None = None,
    website_id: uuid.UUID | None = None,
) -> NotificationListResponse:
    items, total = await notif_service.list_notifications(
        db,
        current_user.id,
        is_read=is_read,
        type=type,
        severity=severity,
        website_id=website_id,
        limit=limit,
        offset=offset,
    )
    return NotificationListResponse(
        items=[NotificationResponse.model_validate(n) for n in items],
        total=total,
        limit=limit,
        offset=offset,
        **page_meta(total, limit, offset),
    )


@router.get("/unread-count", response_model=UnreadCountResponse)
async def get_unread_count(db: _DB, current_user: _CurrentUser) -> UnreadCountResponse:
    count = await notif_service.get_unread_count(db, current_user.id)
    return UnreadCountResponse(count=count)


@router.get("/{notification_id}", response_model=NotificationResponse)
async def get_notification(
    notification_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> NotificationResponse:
    n = await notif_service.get_notification(db, notification_id, current_user.id)
    if n is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    return NotificationResponse.model_validate(n)


@router.patch("/read-all", response_model=UnreadCountResponse)
async def mark_all_read(db: _DB, current_user: _CurrentUser) -> UnreadCountResponse:
    await notif_service.mark_all_read(db, current_user.id)
    await db.commit()
    return UnreadCountResponse(count=0)


@router.patch("/{notification_id}/read", response_model=NotificationResponse)
async def mark_notification_read(
    notification_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> NotificationResponse:
    n = await notif_service.mark_read(db, notification_id, current_user.id)
    if n is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    await db.commit()
    return NotificationResponse.model_validate(n)


@router.delete("/{notification_id}", status_code=204)
async def delete_notification(
    notification_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> None:
    deleted = await notif_service.delete_notification(db, notification_id, current_user.id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Notification not found")
    await db.commit()
