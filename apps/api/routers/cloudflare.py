from __future__ import annotations

import logging
import uuid
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.security import get_active_org_id, get_current_user
from apps.api.services import cloudflare as cf
from apps.api.services import websites as ws_service
from apps.api.services.key_management import get_key_management
from apps.api.services.onboarding_automation import run_automation_for_website
from apps.api.services.verification import OwnershipConflictError

logger = logging.getLogger(__name__)
router = APIRouter(tags=["cloudflare"])

_DB = Annotated[AsyncSession, Depends(get_db)]
_CurrentUser = Annotated[User, Depends(get_current_user)]
_ActiveOrg = Annotated[uuid.UUID | None, Depends(get_active_org_id)]


def _uid(user: User) -> uuid.UUID | None:
    return None if user.is_admin else user.id


@router.post("/websites/{website_id}/providers/cloudflare/connect")
async def cloudflare_connect(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
) -> dict:
    """Start the Cloudflare OAuth flow. Returns an authorization URL; no secrets.
    Tenant ownership enforced; signed state carries the identity to the callback."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    if not cf.is_configured():
        raise HTTPException(status_code=503, detail="Cloudflare connect is not configured")
    # Preflight: fail closed if we cannot encrypt the token we will receive.
    if not get_key_management().is_configured:
        raise HTTPException(status_code=503, detail="Secure secret storage is not configured")

    org_id = active_org if active_org is not None else website.org_id
    state = cf.sign_state(website_id=website.id, user_id=current_user.id, org_id=org_id)
    cf._audit(db, cf.CF_OAUTH_STARTED, website, user_id=current_user.id, org_id=org_id,
              status="connecting")
    await db.commit()
    return {"authorization_url": cf.build_authorize_url(state)}


@router.get("/integrations/cloudflare/callback")
async def cloudflare_callback(
    db: _DB,
    background_tasks: BackgroundTasks,
    state: str = "",
    code: str = "",
    error: str = "",
    error_description: str = "",
) -> RedirectResponse:
    """OAuth callback. UNAUTHENTICATED by necessity — the signed `state` is the
    sole identity. Never log the request URL / `code` (they leak via access logs).
    """
    settings = get_settings()
    base = f"{settings.frontend_url}/dashboard"

    def _debug_qs(cf_error: str = "", cf_desc: str = "",
                  cf_status: int | None = None) -> str:
        # TEMPORARY DEBUG (remove with the logging below once the live failure is
        # diagnosed): surface the SAFE, non-secret OAuth error to the browser so
        # the failure is readable without server-log access. Only the OAuth
        # `error`/`error_description` and token-exchange HTTP status — NEVER the
        # code, tokens, client_secret, or state.
        parts = []
        if cf_error:
            parts.append(f"cf_error={quote(cf_error, safe='')}")
        if cf_desc:
            parts.append(f"cf_desc={quote(cf_desc[:200], safe='')}")
        if cf_status is not None:
            parts.append(f"cf_status={cf_status}")
        return ("&" + "&".join(parts)) if parts else ""

    def _fail(reason: str, website_id: uuid.UUID | None = None, *,
              cf_error: str = "", cf_desc: str = "",
              cf_status: int | None = None) -> RedirectResponse:
        path = f"{base}/websites/{website_id}" if website_id else base
        return RedirectResponse(
            f"{path}?cloudflare=error&reason={reason}"
            f"{_debug_qs(cf_error, cf_desc, cf_status)}")

    # ── TEMPORARY DEBUG: safe structured logging of the OAuth callback path. ──
    # Logs ONLY non-secret fields: the verbatim OAuth error/description (not
    # secret), booleans for code/state presence, and status strings. NEVER logs
    # the code value, the raw state, or any token. Remove once diagnosed.
    logger.info(
        "cf_callback stage=received query_error=%r query_error_description=%r "
        "has_code=%s has_state=%s",
        error, error_description, bool(code), bool(state),
    )

    if not state:
        logger.info("cf_callback stage=state_lookup result=missing")
        return _fail("invalid_state", cf_error=error, cf_desc=error_description)
    try:
        st = cf.verify_state(state)
    except cf.InvalidStateError:
        logger.info("cf_callback stage=state_lookup result=invalid_or_expired")
        return _fail("invalid_state", cf_error=error, cf_desc=error_description)
    website = await db.get(Website, uuid.UUID(st["wid"]))
    if website is None:
        logger.info("cf_callback stage=state_lookup result=website_not_found")
        return _fail("website_not_found", cf_error=error, cf_desc=error_description)
    logger.info("cf_callback stage=state_lookup result=valid")

    if error or not code:
        # Cloudflare bounced us at the authorize step (e.g. access_denied) — the
        # token exchange never runs. The query error/description is the real cause.
        logger.info("cf_callback stage=authorize result=oauth_denied query_error=%r", error)
        return _fail("oauth_denied", website.id,
                     cf_error=error, cf_desc=error_description)

    user_id = uuid.UUID(st["uid"]) if st.get("uid") else None
    org_id = uuid.UUID(st["oid"]) if st.get("oid") else None
    try:
        result = await cf.complete_connection(
            db, website=website, code=code, user_id=user_id, org_id=org_id)
    except cf.EncryptionNotConfiguredError:
        await db.commit()  # persist the failed-connection + audit row
        return _fail("encryption_not_configured", website.id)
    except cf.CloudflareOAuthError as exc:
        await db.commit()
        # TEMPORARY DEBUG: log + surface the token-exchange HTTP status and the
        # whitelisted OAuth error fields (never the body/tokens).
        http_status = getattr(exc, "http_status", None)
        oauth_error = getattr(exc, "oauth_error", None) or {}
        logger.warning(
            "cf_callback stage=token_exchange result=failed http_status=%s "
            "oauth_error=%r oauth_error_description=%r oauth_message=%r",
            http_status, oauth_error.get("error"),
            oauth_error.get("error_description"), oauth_error.get("message"),
        )
        return _fail("connection_failed", website.id,
                     cf_error=oauth_error.get("error") or "",
                     cf_desc=(oauth_error.get("error_description")
                              or oauth_error.get("message") or ""),
                     cf_status=http_status)
    except OwnershipConflictError:
        await db.rollback()  # undo token store + connection (nothing persists)
        return _fail("ownership_conflict", website.id)
    except Exception:  # noqa: BLE001
        await db.rollback()
        logger.exception("cloudflare callback failed for website %s", website.id)
        return _fail("connection_failed", website.id)

    await db.commit()
    if not result.get("matched"):
        return RedirectResponse(f"{base}/websites/{website.id}?cloudflare=no_zone")

    # Connection committed -> resume onboarding automation (reuse Phase 3.10; it
    # opens its own session and must see committed state). Best-effort.
    background_tasks.add_task(run_automation_for_website, website.id,
                             user_id=user_id, org_id=org_id)
    return RedirectResponse(f"{base}/websites/{website.id}?cloudflare=connected")


@router.get("/websites/{website_id}/providers/cloudflare")
async def cloudflare_status(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """Customer-safe connection state (no account/zone ids, tokens, or permissions)."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    conn = await cf.get_connection(db, website.id)
    return cf.dashboard_view(conn)
