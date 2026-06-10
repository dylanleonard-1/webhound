# WebHound — apps/api/services/cloudflare.py
# Phase 4.2 — Cloudflare provider integration (the reference provider). Reuses
# Phase 4.1 secret storage (tokens), Phase 3.2 verification, Phase 3.4 trusted
# access, Phase 3.8 audit. Does NOT touch scanner logic, and does NOT change any
# customer WAF/firewall settings (read-only scopes; §8 deferred — guidance only).
#
# Security invariants:
#  - Ownership is granted ONLY when a name-matching Cloudflare zone is ACTIVE
#    (a merely-added pending zone proves nothing). Unrelated/pending -> no grant.
#  - The OAuth token is exchanged in-memory and persisted (via Phase 4.1) ONLY
#    after a successful active-zone match. On no match it is discarded, never stored.
#  - The signed-state JWT is the callback's identity (the callback is
#    unauthenticated by necessity); tenant identity comes from nowhere else.
#  - Never log the authorization code or any token. Connection row stores only
#    encrypted-secret REFERENCES.

from __future__ import annotations

import logging
from datetime import datetime, timezone
from urllib.parse import urlencode

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.models.enums import ProviderConnectionStatus
from apps.api.models.website import Website
from apps.api.services import provider_oauth
from apps.api.services import trusted_access as ta_service
from apps.api.services import verification as verify_service
from apps.api.services.key_management import get_key_management
from apps.api.services.provider_oauth import EncryptionNotConfiguredError, InvalidStateError
from apps.api.services.secret_storage import store_secret

logger = logging.getLogger(__name__)

CLOUDFLARE_PROVIDER = "cloudflare"

# Cloudflare OAuth + API endpoints. Read-only scopes only — we never request
# firewall/WAF write access in this foundation (§8 deferred).
_CF_AUTHORIZE = "https://dash.cloudflare.com/oauth2/auth"
_CF_TOKEN = "https://dash.cloudflare.com/oauth2/token"
_CF_API = "https://api.cloudflare.com/client/v4"
_CF_SCOPES = "account:read zone:read"

# Audit events (admin_audit_log via record_phase3_event). NEVER carry secrets.
CF_OAUTH_STARTED = "cloudflare.oauth.started"
CF_OAUTH_COMPLETED = "cloudflare.oauth.completed"
CF_OAUTH_FAILED = "cloudflare.oauth.failed"
CF_ZONE_MATCHED = "cloudflare.zone.matched"
CF_ZONE_NOT_FOUND = "cloudflare.zone.not_found"
CF_CONNECTED = "cloudflare.connected"
CF_DISCONNECTED = "cloudflare.disconnected"
CF_TRUSTED_ACCESS_PENDING = "cloudflare.trusted_access.pending"
CF_VALIDATION_QUEUED = "cloudflare.validation.queued"


class CloudflareNotConfiguredError(RuntimeError):
    """Cloudflare OAuth client credentials are not configured."""


class CloudflareOAuthError(RuntimeError):
    """Token exchange / API call failed."""


def is_configured() -> bool:
    s = get_settings()
    return bool(s.cloudflare_client_id and s.cloudflare_client_secret)


def _redirect_uri() -> str:
    return f"{get_settings().api_base_url}/providers/cloudflare/callback"


# ── OAuth state (signed JWT = CSRF protection + callback identity) ─────────────

def sign_state(*, website_id, user_id, org_id) -> str:
    return provider_oauth.sign_state(CLOUDFLARE_PROVIDER, website_id=website_id,
                                     user_id=user_id, org_id=org_id)


def verify_state(state: str) -> dict:
    return provider_oauth.verify_state(CLOUDFLARE_PROVIDER, state)


def build_authorize_url(state: str) -> str:
    s = get_settings()
    params = {
        "client_id": s.cloudflare_client_id,
        "redirect_uri": _redirect_uri(),
        "response_type": "code",
        "scope": _CF_SCOPES,
        "state": state,
    }
    return f"{_CF_AUTHORIZE}?{urlencode(params)}"


# ── Cloudflare API (token exchange + zone discovery) ───────────────────────────

async def _exchange_code(code: str) -> dict:
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(_CF_TOKEN, data={
            "client_id": s.cloudflare_client_id,
            "client_secret": s.cloudflare_client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": _redirect_uri(),
        }, headers={"Accept": "application/json"})
    r.raise_for_status()
    return r.json()


async def _fetch_zones(access_token: str) -> list[dict]:
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.get(f"{_CF_API}/zones",
                             headers={"Authorization": f"Bearer {access_token}"},
                             params={"per_page": 50})
    r.raise_for_status()
    return r.json().get("result") or []


def match_active_zone(hostname: str, zones: list[dict]) -> dict | None:
    """Return the most-specific ACTIVE Cloudflare zone whose name owns the
    hostname, else None. SECURITY: only ``status == "active"`` proves DNS
    control; a pending/initializing zone (a domain merely added to the account)
    does NOT, and an unrelated zone never matches."""
    host = (hostname or "").lower().strip().rstrip(".")
    best: dict | None = None
    for z in zones:
        name = (z.get("name") or "").lower().strip().rstrip(".")
        if not name:
            continue
        if host != name and not host.endswith("." + name):
            continue  # unrelated zone
        if (z.get("status") or "").lower() != "active":
            continue  # pending/initializing/moved -> proves no control
        if best is None or len(name) > len(str(best.get("name") or "")):
            best = z
    return best


def _capabilities(zone: dict) -> dict:
    """Safe, non-secret capability metadata only."""
    return {
        "zone_status": zone.get("status"),
        "plan": (zone.get("plan") or {}).get("name"),
        "name_servers_configured": bool(zone.get("name_servers")),
    }


async def get_connection(db: AsyncSession, website_id):
    return await provider_oauth.get_connection(db, website_id, CLOUDFLARE_PROVIDER)


async def _get_or_create(db: AsyncSession, website: Website, user_id, org_id):
    return await provider_oauth.get_or_create_connection(
        db, website, CLOUDFLARE_PROVIDER, user_id, org_id)


def _audit(db, event, website, *, user_id, org_id, status, reason=None):
    provider_oauth.audit_event(db, event, website, provider=CLOUDFLARE_PROVIDER,
                               user_id=user_id, org_id=org_id, status=status, reason=reason)


async def complete_connection(db: AsyncSession, *, website: Website, code: str,
                              user_id, org_id) -> dict:
    """Exchange the code, match an ACTIVE owning zone, and ONLY then persist the
    token (via Phase 4.1) + verify ownership + start trusted access. Returns a
    result dict for the callback redirect. Never logs the code or token."""
    # Preflight: fail closed if we cannot encrypt the token at rest.
    if not get_key_management().is_configured:
        conn = await _get_or_create(db, website, user_id, org_id)
        conn.connection_status = ProviderConnectionStatus.FAILED.value
        _audit(db, CF_OAUTH_FAILED, website, user_id=user_id, org_id=org_id,
               status="failed", reason="encryption_not_configured")
        raise EncryptionNotConfiguredError()

    # Exchange code -> token (held in memory only).
    try:
        token_data = await _exchange_code(code)
    except Exception as exc:  # noqa: BLE001 — never surface the code/token
        conn = await _get_or_create(db, website, user_id, org_id)
        conn.connection_status = ProviderConnectionStatus.FAILED.value
        _audit(db, CF_OAUTH_FAILED, website, user_id=user_id, org_id=org_id,
               status="failed", reason="token_exchange_failed")
        raise CloudflareOAuthError("token exchange failed") from exc

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    scope = token_data.get("scope") or _CF_SCOPES
    if not access_token:
        conn = await _get_or_create(db, website, user_id, org_id)
        conn.connection_status = ProviderConnectionStatus.FAILED.value
        _audit(db, CF_OAUTH_FAILED, website, user_id=user_id, org_id=org_id,
               status="failed", reason="no_access_token")
        raise CloudflareOAuthError("no access_token in response")
    _audit(db, CF_OAUTH_COMPLETED, website, user_id=user_id, org_id=org_id, status="connecting")

    # Discover zones with the in-memory token, then match an ACTIVE owning zone.
    zones = await _fetch_zones(access_token)
    zone = match_active_zone(website.hostname, zones)

    conn = await _get_or_create(db, website, user_id, org_id)
    if zone is None:
        # No active owning zone — discard the token (never stored), mark failed.
        conn.connection_status = ProviderConnectionStatus.FAILED.value
        conn.match_confidence = "none"
        conn.disconnected_at = datetime.now(timezone.utc)
        _audit(db, CF_ZONE_NOT_FOUND, website, user_id=user_id, org_id=org_id,
               status="failed", reason="no_active_matching_zone")
        await db.flush()
        return {"matched": False, "status": "failed",
                "message": "No active Cloudflare zone controls this website's domain."}

    # Matched active zone -> NOW persist tokens via Phase 4.1 (encrypted at rest).
    access_secret = await store_secret(
        db, resource_type=CLOUDFLARE_PROVIDER, secret_type="oauth_access_token",
        plaintext=access_token, org_id=org_id, user_id=user_id, website_id=website.id,
        metadata={"scope": scope})
    refresh_ref = None
    if refresh_token:
        refresh_secret = await store_secret(
            db, resource_type=CLOUDFLARE_PROVIDER, secret_type="oauth_refresh_token",
            plaintext=refresh_token, org_id=org_id, user_id=user_id, website_id=website.id)
        refresh_ref = str(refresh_secret.id)

    zone_name = zone.get("name")
    conn.account_id = (zone.get("account") or {}).get("id")
    conn.zone_id = zone.get("id")
    conn.zone_name = zone_name
    conn.connection_status = ProviderConnectionStatus.CONNECTED.value
    conn.match_confidence = "high"
    conn.connected_at = datetime.now(timezone.utc)
    conn.last_sync_at = conn.connected_at
    conn.disconnected_at = None
    conn.permissions_granted = scope.split()
    conn.access_secret_reference = str(access_secret.id)
    conn.refresh_secret_reference = refresh_ref
    conn.connection_metadata = _capabilities(zone)
    conn.evidence = [f"Cloudflare zone '{zone_name}' is active and controls {website.hostname}"]
    await db.flush()
    _audit(db, CF_ZONE_MATCHED, website, user_id=user_id, org_id=org_id,
           status="connected", reason=f"zone:{zone_name}")
    _audit(db, CF_CONNECTED, website, user_id=user_id, org_id=org_id, status="connected")

    # Reuse Phase 3.2 verification (active-zone control is strong ownership
    # evidence) — the cross-account conflict guard still runs inside.
    await verify_service.mark_verified_via_provider(
        db, website, provider=CLOUDFLARE_PROVIDER, evidence=conn.evidence,
        actor_user_id=user_id, org_id=org_id)

    # Reuse Phase 3.4 trusted access -> PENDING (we have NOT configured scanner
    # access / WAF rules; Phase 3.5 validation remains the single 'active' gate).
    await ta_service.start_provider_oauth_access(
        db, website, provider=CLOUDFLARE_PROVIDER,
        evidence=conn.evidence, user_id=user_id, org_id=org_id)
    _audit(db, CF_TRUSTED_ACCESS_PENDING, website, user_id=user_id, org_id=org_id,
           status="pending", reason="scanner access validation is next")
    _audit(db, CF_VALIDATION_QUEUED, website, user_id=user_id, org_id=org_id, status="queued")

    return {"matched": True, "status": "connected", "zone": zone_name}


def dashboard_view(conn) -> dict:
    return provider_oauth.dashboard_view(conn, provider=CLOUDFLARE_PROVIDER)
