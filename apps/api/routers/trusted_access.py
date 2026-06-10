from __future__ import annotations

import uuid
from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.provider_profile import ProviderProfile
from apps.api.models.user import User
from apps.api.security import get_active_org_id, get_current_user
from apps.api.services import trusted_access as ta_service
from apps.api.services import websites as ws_service

router = APIRouter(prefix="/websites", tags=["trusted-access"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]
_ActiveOrg = Annotated[uuid.UUID | None, Depends(get_active_org_id)]


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.post("/{website_id}/trusted-access/start")
async def start_trusted_access(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
    active_org: _ActiveOrg = None,
) -> dict:
    """Create/refresh the trusted-access record for a verified website and
    return provider guidance. Requires verified ownership + a provider profile.
    Does not start a scan or change scan behaviour."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    try:
        profile, guidance = await ta_service.start_trusted_access(
            db, website, user_id=current_user.id, org_id=active_org)
    except ta_service.OwnershipRequiredError as exc:
        raise HTTPException(409, {"error": exc.code,
                                  "message": "Verify domain ownership before configuring trusted scanner access."})
    except ta_service.ProviderDiscoveryRequiredError as exc:
        raise HTTPException(409, {"error": exc.code,
                                  "message": "Run provider discovery before configuring trusted scanner access."})
    await db.commit()
    return {**ta_service.dashboard_view(profile, None), "guidance": guidance}


@router.get("/{website_id}/trusted-access")
async def get_trusted_access(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """Dashboard contract — returns not_configured when no record exists yet."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    profile = await ta_service.get_trusted_access(db, website)
    provider_profile = await db.scalar(
        sa.select(ProviderProfile).where(ProviderProfile.website_id == website.id)
    )
    return ta_service.dashboard_view(profile, provider_profile)


@router.post("/{website_id}/trusted-access/revoke")
async def revoke_trusted_access(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
    active_org: _ActiveOrg = None,
) -> dict:
    """Revoke trusted access (status -> revoked)."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    profile = await ta_service.get_trusted_access(db, website)
    if profile is None:
        raise HTTPException(404, "No trusted access configured")
    await ta_service.revoke_trusted_access(
        db, website, profile, reason="customer_revoked",
        user_id=current_user.id, org_id=active_org)
    await db.commit()
    return ta_service.dashboard_view(profile, None)
