from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.security import get_active_org_id, get_current_user
from apps.api.services import onboarding_automation as auto_service
from apps.api.services import onboarding_readiness as ob_service
from apps.api.services import websites as ws_service

router = APIRouter(prefix="/websites", tags=["onboarding"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]
_ActiveOrg = Annotated[uuid.UUID | None, Depends(get_active_org_id)]


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.get("/{website_id}/onboarding")
async def get_onboarding_readiness(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """Live onboarding readiness for the dashboard (read-only — no side effects)."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    return await ob_service.get_readiness_view(db, website)


@router.post("/{website_id}/onboarding/activate-monitoring")
async def activate_monitoring(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
    active_org: _ActiveOrg = None,
) -> dict:
    """Activate monitoring if onboarding readiness permits (READY/LIMITED).
    Blocks when NOT_READY. Does not change existing scan/scanner behaviour."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    try:
        result = await ob_service.activate_monitoring(
            db, website, user_id=current_user.id, org_id=active_org)
    except ob_service.NotReadyError as exc:
        await db.commit()  # persist the evaluation + blocked-activation audit
        raise HTTPException(409, {"error": exc.code,
                                  "message": "Website is not ready for monitoring — complete onboarding first."})
    await db.commit()
    return result


@router.post("/{website_id}/onboarding/automate")
async def automate_onboarding(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
    active_org: _ActiveOrg = None,
) -> dict:
    """Run the onboarding automation conductor: advance every stage that needs
    no customer action (provider discovery, trusted-access guidance, validation,
    readiness, monitoring activation) and pause at the customer gates with
    guidance. Resumable — re-run to continue. Owner-scoped; never bypasses
    verification or readiness, and never modifies customer infrastructure."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    state = await auto_service.run_automation(
        db, website, user_id=current_user.id, org_id=active_org)
    await db.commit()
    return state

