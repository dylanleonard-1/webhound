from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.security import get_active_org_id, get_current_user
from apps.api.services import onboarding_wizard as wiz_service
from apps.api.services import websites as ws_service

router = APIRouter(prefix="/websites", tags=["onboarding-wizard"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]
_ActiveOrg = Annotated[uuid.UUID | None, Depends(get_active_org_id)]


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.get("/{website_id}/onboarding/wizard")
async def get_onboarding_wizard(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """Live 6-step onboarding wizard view (read-only; resumes from current_step)."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    return await wiz_service.get_wizard_view(db, website)


@router.post("/{website_id}/onboarding/wizard/sync")
async def sync_onboarding_wizard(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
    active_org: _ActiveOrg = None,
) -> dict:
    """Refresh + persist the wizard snapshot and emit step progress events."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    result = await wiz_service.sync_wizard(
        db, website, user_id=current_user.id, org_id=active_org)
    await db.commit()
    return result
