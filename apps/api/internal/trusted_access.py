from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
from apps.api.models.enums import AdminRole
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.services import trusted_access as ta_service

router = APIRouter(prefix="/internal/websites", tags=["internal-trusted-access"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_Admin = Annotated[User, Depends(require_admin(AdminRole.ADMIN))]


@router.post("/{website_id}/trusted-access/mark-active")
async def mark_trusted_access_active(
    website_id: uuid.UUID, db: _DB, actor: _Admin,
) -> dict:
    """Manual admin promote-to-active (until Phase 3.5 coverage validation
    drives this automatically). Staff action — written to the admin audit log."""
    website = await db.get(Website, website_id)
    if website is None:
        raise HTTPException(404, "Website not found")
    profile = await ta_service.get_trusted_access(db, website)
    if profile is None:
        raise HTTPException(404, "No trusted access configured")
    await ta_service.mark_active(
        db, website, profile, reason="admin_marked_active",
        user_id=actor.id, org_id=profile.org_id)
    await record_action(
        db, actor=actor, action="trusted_access.mark_active",
        target_type="website", target_id=str(website_id))
    await db.commit()
    return ta_service.dashboard_view(profile, None)
