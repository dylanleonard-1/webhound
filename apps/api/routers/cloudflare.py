from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.database import get_db
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.security import get_active_org_id, get_current_user
from apps.api.services import cloudflare as cf
from apps.api.services import cloudflare_rules as cf_rules
from apps.api.services import cloudflare_scanner_access as cf_scanner
from apps.api.services import scanner_access_diagnosis as cf_diag
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


@router.post("/websites/{website_id}/providers/cloudflare/scanner-access/start")
async def cloudflare_scanner_access_start(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
) -> dict:
    """Start the ELEVATED scanner-access OAuth re-consent (separate from the
    read-only connect). Requires an existing connected Cloudflare zone. Returns an
    authorize URL requesting the firewall-write + telemetry-read scopes; the signed
    state carries phase=scanner_access so the callback creates the skip rules."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    if not cf.is_configured():
        raise HTTPException(status_code=503, detail="Cloudflare connect is not configured")
    if not get_key_management().is_configured:
        raise HTTPException(status_code=503, detail="Secure secret storage is not configured")
    conn = await cf.get_connection(db, website.id)
    if conn is None or not conn.zone_id:
        # Scanner rules target the owning zone — require the read-only connect first.
        raise HTTPException(status_code=409,
                            detail="Connect Cloudflare (zone discovery) before setting up scanner access")

    org_id = active_org if active_org is not None else website.org_id
    state = cf.sign_scanner_state(website_id=website.id, user_id=current_user.id, org_id=org_id)
    cf._audit(db, cf.CF_SCANNER_ACCESS_STARTED, website, user_id=current_user.id, org_id=org_id,
              status="connecting")
    await db.commit()
    return {"authorization_url": cf.build_scanner_access_authorize_url(state)}


@router.post("/websites/{website_id}/providers/cloudflare/scanner-access/disconnect")
async def cloudflare_scanner_access_disconnect(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
) -> dict:
    """Remove the WebHound scanner firewall rules, revoke the elevated token, and
    revert trusted access to pending. Reversible + idempotent."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    org_id = active_org if active_org is not None else website.org_id
    try:
        result = await cf_scanner.disconnect_scanner_access(
            db, website=website, user_id=current_user.id, org_id=org_id)
    except cf_rules.CloudflareRuleError as exc:
        await db.rollback()
        logger.warning("cloudflare scanner-rule removal failed for website %s: http_status=%s",
                       website.id, getattr(exc, "http_status", None))
        raise HTTPException(status_code=502, detail="Could not remove scanner rules from Cloudflare")
    await db.commit()
    return result


@router.get("/websites/{website_id}/providers/cloudflare/scanner-access")
async def cloudflare_scanner_access_status(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser,
) -> dict:
    """Layered, honest scanner-access diagnosis: verified? cloudflare connected? is
    Cloudflare actually the blocker? CF scanner-access status + the real next action
    (which may be a different provider, e.g. Vercel). No secrets."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    return await cf_diag.diagnose_scanner_access(db, website)


@router.get("/websites/{website_id}/providers/cloudflare/scanner-access/telemetry")
async def cloudflare_scanner_access_telemetry(
    website_id: uuid.UUID, db: _DB, current_user: _CurrentUser, active_org: _ActiveOrg = None,
) -> dict:
    """Foundation-only security telemetry (Security Center / Page Shield) read with
    the elevated token. Returns availability + counts; never any secret."""
    website = await ws_service.get_website(db, website_id, user_id=_uid(current_user))
    if website is None:
        raise HTTPException(status_code=404, detail="Website not found")
    org_id = active_org if active_org is not None else website.org_id
    result = await cf_scanner.read_telemetry(
        db, website=website, user_id=current_user.id, org_id=org_id)
    await db.commit()
    return result


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

    def _fail(reason: str, website_id: uuid.UUID | None = None) -> RedirectResponse:
        # Redirect back with a short, non-secret reason code the dashboard maps to
        # a friendly message. Never carries the OAuth code, tokens, or state.
        path = f"{base}/websites/{website_id}" if website_id else base
        return RedirectResponse(f"{path}?cloudflare=error&reason={reason}")

    if not state:
        return _fail("invalid_state")
    try:
        st = cf.verify_state(state)
    except cf.InvalidStateError:
        return _fail("invalid_state")
    website = await db.get(Website, uuid.UUID(st["wid"]))
    if website is None:
        return _fail("website_not_found")

    if error or not code:
        # Cloudflare bounced us at the authorize step (e.g. access_denied) — the
        # token exchange never runs. Log the safe OAuth error as the cause.
        logger.warning("cloudflare authorize denied for website %s: error=%r",
                       website.id, error)
        return _fail("oauth_denied", website.id)

    user_id = uuid.UUID(st["uid"]) if st.get("uid") else None
    org_id = uuid.UUID(st["oid"]) if st.get("oid") else None

    # Elevated scanner-access phase: exchange + create/verify the firewall skip
    # rules, then flip trusted access ACTIVE. Separate redirect statuses.
    if st.get("phase") == cf.SCANNER_ACCESS_PHASE:
        try:
            sresult = await cf_scanner.complete_scanner_access(
                db, website=website, code=code, user_id=user_id, org_id=org_id)
        except cf.EncryptionNotConfiguredError:
            await db.commit()
            return _fail("encryption_not_configured", website.id)
        except cf.CloudflareOAuthError as exc:
            await db.commit()
            logger.warning(
                "cloudflare scanner-access token exchange failed for website %s: "
                "http_status=%s error=%r", website.id, getattr(exc, "http_status", None),
                (getattr(exc, "oauth_error", None) or {}).get("error"))
            return _fail("scanner_token_failed", website.id)
        except cf_rules.CloudflareRuleError as exc:
            await db.commit()
            logger.warning("cloudflare scanner-rule creation failed for website %s: http_status=%s",
                           website.id, getattr(exc, "http_status", None))
            return _fail("scanner_rule_failed", website.id)
        except Exception:  # noqa: BLE001
            await db.rollback()
            logger.exception("cloudflare scanner-access failed for website %s", website.id)
            return _fail("scanner_access_failed", website.id)
        await db.commit()
        if sresult.get("status") == "active":
            return RedirectResponse(f"{base}/websites/{website.id}?cloudflare=scanner_active")
        return RedirectResponse(
            f"{base}/websites/{website.id}?cloudflare=scanner_failed"
            f"&reason={sresult.get('reason', 'unknown')}")

    try:
        result = await cf.complete_connection(
            db, website=website, code=code, user_id=user_id, org_id=org_id)
    except cf.EncryptionNotConfiguredError:
        await db.commit()  # persist the failed-connection + audit row
        return _fail("encryption_not_configured", website.id)
    except cf.CloudflareOAuthError as exc:
        await db.commit()
        # Sane error logging: the token-exchange HTTP status + whitelisted OAuth
        # error fields (never the body/tokens) for server-side diagnosis.
        http_status = getattr(exc, "http_status", None)
        oauth_error = getattr(exc, "oauth_error", None) or {}
        logger.warning(
            "cloudflare token exchange failed for website %s: http_status=%s error=%r",
            website.id, http_status, oauth_error.get("error"),
        )
        return _fail("connection_failed", website.id)
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
