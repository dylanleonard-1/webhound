from __future__ import annotations

import logging
import uuid
from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.provider_profile import ProviderProfile
from apps.api.models.user import User
from apps.api.schemas.provider_profile import ProviderProfileResponse
from apps.api.security import get_current_user
from apps.api.services import provider_discovery as pd_service
from apps.api.services import websites as ws_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/websites", tags=["provider-discovery"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.post("/{website_id}/providers/discover", response_model=ProviderProfileResponse)
async def discover_providers(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> ProviderProfileResponse:
    """Run provider discovery for a verified-or-not website and persist the
    resulting ProviderProfile. Detection-only — does not start a scan."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    try:
        profile = await pd_service.run_provider_discovery(db, website)
    except ImportError:
        logger.exception("provider discovery unavailable: scanner package import failed")
        raise HTTPException(503, "Provider discovery is temporarily unavailable")
    await db.commit()
    return ProviderProfileResponse.model_validate(profile)


@router.get("/{website_id}/providers", response_model=ProviderProfileResponse)
async def get_provider_profile(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> ProviderProfileResponse:
    """Return the stored provider profile for a website (404 if none yet)."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    profile = await db.scalar(
        sa.select(ProviderProfile).where(ProviderProfile.website_id == website.id)
    )
    if profile is None:
        raise HTTPException(404, "No provider profile yet — run discovery first")
    return ProviderProfileResponse.model_validate(profile)
