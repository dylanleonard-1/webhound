from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.security import get_current_user
from apps.api.services import phase3_audit as audit_service
from apps.api.services import websites as ws_service

router = APIRouter(prefix="/websites", tags=["audit"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.get("/{website_id}/audit")
async def get_website_audit(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """The append-only Phase-3 onboarding audit trail for a website — timeline +
    dashboard contract. Owner-scoped (tenant isolation)."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    return await audit_service.get_onboarding_history(db, website)
