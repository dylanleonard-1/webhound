from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.enums import VerificationStatus
from apps.api.models.user import User
from apps.api.schemas.websites import (
    WebsiteCreate,
    WebsiteListResponse,
    WebsitePatch,
    WebsiteResponse,
)
from apps.api.security import get_current_user
from apps.api.services import websites as ws_service

router = APIRouter(prefix="/websites", tags=["websites"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]


@router.post("", response_model=WebsiteResponse, status_code=201)
async def create_website(
    data: WebsiteCreate, db: _DB, current_user: _CurrentUser
) -> WebsiteResponse:
    try:
        website = await ws_service.create_website(db, data, user_id=current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except ws_service.DuplicateWebsiteError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    await db.commit()
    return WebsiteResponse.model_validate(website)


@router.get("", response_model=WebsiteListResponse)
async def list_websites(
    db: _DB,
    current_user: _CurrentUser,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
    verification_status: VerificationStatus | None = None,
    hostname: str | None = None,
) -> WebsiteListResponse:
    items, total = await ws_service.list_websites(
        db,
        limit=limit,
        offset=offset,
        verification_status=verification_status,
        hostname=hostname,
        user_id=current_user.id,
    )
    return WebsiteListResponse(
        items=[WebsiteResponse.model_validate(w) for w in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{website_id}", response_model=WebsiteResponse)
async def get_website(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> WebsiteResponse:
    website = await ws_service.get_website(db, website_id, user_id=current_user.id)
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    return WebsiteResponse.model_validate(website)


@router.patch("/{website_id}", response_model=WebsiteResponse)
async def patch_website(
    website_id: uuid.UUID, data: WebsitePatch, db: _DB, current_user: _CurrentUser
) -> WebsiteResponse:
    website = await ws_service.update_website(
        db, website_id, data, user_id=current_user.id
    )
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    await db.commit()
    return WebsiteResponse.model_validate(website)


@router.delete("/{website_id}", status_code=204)
async def delete_website(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser
) -> None:
    deleted = await ws_service.delete_website(
        db, website_id, user_id=current_user.id
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Website not found")
    await db.commit()
