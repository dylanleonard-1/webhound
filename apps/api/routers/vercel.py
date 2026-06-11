from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.security import get_active_org_id, get_current_user
from apps.api.services import provider_oauth
from apps.api.services import vercel as v
from apps.api.services import websites as ws_service
from apps.api.services.key_management import get_key_management
from apps.api.services.onboarding_automation import run_automation_for_website
from apps.api.services.verification import OwnershipConflictError

logger = logging.getLogger(__name__)
router = APIRouter(tags=["vercel"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]
_ActiveOrg = Annotated[uuid.UUID | None, Depends(get_active_org_id)]


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.post("/websites/{website_id}/providers/vercel/connect")
async def vercel_connect(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
) -> dict:
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    if not v.is_configured():
        raise HTTPException(status_code=503, detail="Vercel connect is not configured")
    if not get_key_management().is_configured:
        raise HTTPException(status_code=503, detail="Secure secret storage is not configured")

    org_id = active_org if active_org is not None else website.org_id
    state = v.sign_state(website_id=website.id, user_id=current_user.id, org_id=org_id)
    provider_oauth.audit_event(db, v.V_OAUTH_STARTED, website, provider=v.VERCEL_PROVIDER,
                               user_id=current_user.id, org_id=org_id, status="connecting")
    await db.commit()
    return {"authorization_url": v.build_authorize_url(state)}


@router.get("/providers/vercel/callback")
async def vercel_callback(
    state: str, db: _DB, background_tasks: BackgroundTasks, code: str = "", error: str = "",
) -> RedirectResponse:
    """UNAUTHENTICATED by necessity — the signed `state` is the sole identity.
    Never log the request URL / `code`."""
    settings = get_settings()
    base = f"{settings.frontend_url}/dashboard"

    def _fail(reason: str, website_id: uuid.UUID | None = None) -> RedirectResponse:
        path = f"{base}/websites/{website_id}" if website_id else base
        return RedirectResponse(f"{path}?vercel=error&reason={reason}")

    try:
        st = v.verify_state(state)
    except provider_oauth.InvalidStateError:
        return _fail("invalid_state")
    website = await db.get(Website, uuid.UUID(st["wid"]))
    if website is None:
        return _fail("website_not_found")
    if error or not code:
        return _fail("oauth_denied", website.id)

    user_id = uuid.UUID(st["uid"]) if st.get("uid") else None
    org_id = uuid.UUID(st["oid"]) if st.get("oid") else None
    try:
        result = await v.complete_connection(
            db, website=website, code=code, user_id=user_id, org_id=org_id)
    except provider_oauth.EncryptionNotConfiguredError:
        await db.commit()
        return _fail("encryption_not_configured", website.id)
    except v.VercelOAuthError:
        await db.commit()
        return _fail("connection_failed", website.id)
    except OwnershipConflictError:
        await db.rollback()
        return _fail("ownership_conflict", website.id)
    except Exception:  # noqa: BLE001
        await db.rollback()
        logger.exception("vercel callback failed for website %s", website.id)
        return _fail("connection_failed", website.id)

    await db.commit()
    if not result.get("matched"):
        return RedirectResponse(f"{base}/websites/{website.id}?vercel=no_project")

    background_tasks.add_task(run_automation_for_website, website.id,
                             user_id=user_id, org_id=org_id)
    return RedirectResponse(f"{base}/websites/{website.id}?vercel=connected")


@router.get("/websites/{website_id}/providers/vercel")
async def vercel_status(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    return v.dashboard_view(await v.get_connection(db, website.id))


@router.get("/websites/{website_id}/providers/vercel/scanner-access")
async def vercel_scanner_access_status(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """Honest Vercel scanner-access status (active / pending_permissions /
    blocked_non_bypassable / failed). Read-only; never exposes tokens."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    from apps.api.services import vercel_scanner_state as v_state
    return await v_state.scanner_access_view(db, website)


class _ProtectionBypassBody(BaseModel):
    secret: str


@router.post("/websites/{website_id}/providers/vercel/protection-bypass")
async def vercel_set_protection_bypass(
    website_id: uuid.UUID, body: _ProtectionBypassBody, db: _DB,
    current_user: _CurrentUser, active_org: _ActiveOrg = None,
) -> dict:
    """Store the customer's Vercel Protection-Bypass-for-Automation secret (encrypted).
    The scanner injects it as x-vercel-protection-bypass to clear Vercel's BotID/Security
    Checkpoint. Marks trusted access ACTIVE. The secret is never returned or logged."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    if not get_key_management().is_configured:
        raise HTTPException(status_code=503, detail="Secure secret storage is not configured")
    org_id = active_org if active_org is not None else website.org_id
    from apps.api.services import vercel_scanner_access as v_scanner
    result = await v_scanner.store_protection_bypass(
        db, website=website, secret=body.secret, user_id=current_user.id, org_id=org_id)
    await db.commit()
    return result


@router.post("/websites/{website_id}/providers/vercel/scanner-access/disconnect")
async def vercel_scanner_access_disconnect(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
) -> dict:
    """Remove the WebHound scanner bypass rule from Vercel and revert trusted access to
    pending. Reversible + idempotent."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    org_id = active_org if active_org is not None else website.org_id
    from apps.api.services import vercel_rules as v_rules
    from apps.api.services import vercel_scanner_access as v_scanner
    try:
        result = await v_scanner.disconnect_scanner_bypass(
            db, website=website, user_id=current_user.id, org_id=org_id)
    except v_rules.VercelRuleError as exc:
        await db.rollback()
        logger.warning("vercel scanner-rule removal failed for website %s: http_status=%s",
                       website.id, getattr(exc, "http_status", None))
        raise HTTPException(status_code=502, detail="Could not remove scanner rules from Vercel")
    await db.commit()
    return result


@router.get("/websites/{website_id}/providers/connections")
async def provider_connections(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """Phase-4.3 multi-provider view (Cloudflare + Vercel + …). Customer-safe —
    per-provider connection state only, no secrets/ids."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    return {"connections": await provider_oauth.list_connection_views(db, website.id)}
