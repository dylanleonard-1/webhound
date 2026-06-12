from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.security import get_active_org_id, get_current_user
from apps.api.services import access_validation as av_service
from apps.api.services import websites as ws_service

router = APIRouter(prefix="/websites", tags=["access-validation"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]
_ActiveOrg = Annotated[uuid.UUID | None, Depends(get_active_org_id)]


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.post("/{website_id}/access-validation/run")
async def run_access_validation(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
    active_org: _ActiveOrg = None,
) -> dict:
    """Validate visibility from the latest scan's metadata (consumes existing
    output — runs no new scan). Requires verified ownership + a trusted-access
    profile. Updates the trusted-access status as a side effect."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    try:
        result = await av_service.validate_access(
            db, website, user_id=current_user.id, org_id=active_org)
    except av_service.OwnershipRequiredError as exc:
        raise HTTPException(409, {"error": exc.code,
                                  "message": "Verify domain ownership before validating access."})
    except av_service.TrustedAccessRequiredError as exc:
        raise HTTPException(409, {"error": exc.code,
                                  "message": "Configure trusted scanner access before validating."})
    await db.commit()
    return av_service.dashboard_view(result)


@router.get("/{website_id}/access-validation")
async def get_access_validation(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """Dashboard contract — pending when validation hasn't run yet."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    return av_service.dashboard_view(await av_service.get_validation(db, website))


@router.get("/{website_id}/platform-access")
async def get_platform_access(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """PlatformAccessWizard view: detected CDN/WAF provider, wizard state,
    registry-driven remediation (with the dynamic scanner IPs), and the
    verification status. Pure data — the UI renders it with no provider logic."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    from apps.api.services import cloudflare as cf
    from apps.api.services import platform_access as pa_service
    conn = await cf.get_connection(db, website.id)
    cloudflare_connected = bool(conn and getattr(conn, "zone_id", None))
    return await pa_service.get_platform_access(
        db, website, cloudflare_connected=cloudflare_connected)


@router.post("/{website_id}/platform-access/support-ticket")
async def create_platform_access_ticket(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """Escalate a failed/blocked platform-access setup to the support queue.
    Auto-attaches the detected provider, website, scan id, challenge type, and
    access state via the existing ticket system. Never includes secrets/tokens."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(404, "Website not found")
    from apps.api.services import cloudflare as cf
    from apps.api.services import platform_access as pa_service
    from apps.api.services import support
    conn = await cf.get_connection(db, website.id)
    cloudflare_connected = bool(conn and getattr(conn, "zone_id", None))
    view = await pa_service.get_platform_access(
        db, website, cloudflare_connected=cloudflare_connected)
    payload = pa_service.build_support_payload(
        view, hostname=website.hostname, website_id=str(website.id))
    ticket = await support.create_ticket(
        db, user=current_user, subject=payload["subject"],
        description=payload["description"], category=payload["category"],
        priority=payload["priority"], author_email=current_user.email)
    await db.commit()
    return {"id": str(ticket.id), "number": ticket.number, "status": ticket.status}
