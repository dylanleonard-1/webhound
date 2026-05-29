# WebHound — apps/api/routers/suppressions.py
# Phase-5F: suppression CRUD endpoints.

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.suppression import SuppressionScope
from apps.api.models.user import User
from apps.api.security import get_active_org_id, get_current_user
from apps.api.services.suppressions import (
    SuppressionError,
    create_suppression,
    deactivate_suppression,
    list_suppressions,
)

router = APIRouter(prefix="/suppressions", tags=["suppressions"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]
_ActiveOrg = Annotated[uuid.UUID | None, Depends(get_active_org_id)]


class SuppressionView(BaseModel):
    id: uuid.UUID
    org_id: uuid.UUID | None
    scope: SuppressionScope
    pattern: str
    scanner_engine: str | None
    reason: str
    creator_email: str | None
    expires_at: datetime | None
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class SuppressionCreate(BaseModel):
    scope: SuppressionScope
    pattern: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=1, max_length=2000)
    scanner_engine: str | None = Field(default=None, max_length=64)
    expires_at: datetime | None = None


class SuppressionListResponse(BaseModel):
    items: list[SuppressionView]
    total: int


@router.get("", response_model=SuppressionListResponse)
async def list_suppressions_endpoint(
    db: _DB, current_user: _CurrentUser, active_org_id: _ActiveOrg,
    include_inactive: bool = False,
) -> SuppressionListResponse:
    rows = await list_suppressions(
        db, org_id=active_org_id, include_inactive=include_inactive,
    )
    return SuppressionListResponse(
        items=[SuppressionView.model_validate(s) for s in rows],
        total=len(rows),
    )


@router.post("", response_model=SuppressionView, status_code=201)
async def create_suppression_endpoint(
    payload: SuppressionCreate,
    db: _DB, current_user: _CurrentUser, active_org_id: _ActiveOrg,
) -> SuppressionView:
    try:
        s = await create_suppression(
            db,
            org_id=active_org_id,
            scope=payload.scope,
            pattern=payload.pattern,
            reason=payload.reason,
            scanner_engine=payload.scanner_engine,
            creator_email=current_user.email,
            creator_user_id=current_user.id,
            expires_at=payload.expires_at,
        )
    except SuppressionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await db.commit()
    return SuppressionView.model_validate(s)


@router.delete("/{suppression_id}", status_code=204)
async def deactivate_suppression_endpoint(
    suppression_id: uuid.UUID,
    db: _DB, current_user: _CurrentUser,
) -> None:
    s = await deactivate_suppression(db, suppression_id)
    if s is None:
        raise HTTPException(status_code=404, detail="not found")
    await db.commit()
