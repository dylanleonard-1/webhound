# WebHound — apps/api/services/vercel.py
# Phase 4.3 — Vercel provider integration. Reuses the Phase 4.2 reference pattern
# via services/provider_oauth.py (shared signed-state CSRF, ProviderConnection
# upsert, audit, dashboard) + the generic ProviderConnection model (no new model,
# no migration) + Phase 4.1 secret storage + Phase 3 verification/trusted-access.
#
# Security invariants (same as Cloudflare 4.2):
#  - Ownership granted ONLY when the website's hostname EXACTLY matches a Vercel
#    project domain with verified == true. A domain merely added to a project
#    (verified == false) proves nothing; an unrelated project never matches. We
#    deliberately do NOT do subdomain (endswith) inheritance: Vercel domains are
#    per-entry, so example.com being verified does not prove control of
#    www.example.com — the exact hostname's domain entry must be verified.
#  - The token is exchanged in-memory and persisted (via 4.1) ONLY after a
#    verified-domain match; discarded on no match.
#  - Fails CLOSED without ENCRYPTION_KEYS. Never logs the code/token.
#  - This phase implements NO Vercel protection-bypass: trusted access stays
#    PENDING, the WebHound-owned-domain bypass is NEVER applied to customer
#    domains, and no bypass headers are sent for customer domains (§7 deferred).
#
# KNOWN RISK (confirm before live creds, like the CF OAuth note): the Vercel API
# shapes assumed here — the project-domain `verified` boolean, `accountId` on the
# project object, and the projects/domains response envelope — are not verified
# against a live Vercel app in this foundation; tests mock the HTTP. Confirm the
# exact fields/endpoints against Vercel's REST docs when wiring real credentials.

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
from apps.api.services.provider_oauth import EncryptionNotConfiguredError, InvalidStateError  # noqa: F401 (re-export)
from apps.api.services.secret_storage import store_secret

logger = logging.getLogger(__name__)

VERCEL_PROVIDER = "vercel"

# Vercel CLASSIC Integration endpoints (Integration Console), NOT "Sign in with
# Vercel". Integration permissions (read-only: project/domain read) are configured on
# the integration itself, not via a scope query param. The connect ENTRY point is the
# install URL built from the integration SLUG — NOT the /oauth/authorize
# authorization-server endpoint (that one only accepts Sign-in-with-Vercel App ids and
# rejects an oac_* integration id as "the app ID is invalid").
#   install:  https://vercel.com/integrations/<slug>/new?state=<state>
#   token:    POST https://api.vercel.com/v2/oauth/access_token  (client_id+secret+code+redirect_uri)
# Ref: vercel.com/docs/integrations/create-integration/submit-integration (External
# installation flow) + .../vercel-api-integrations (Exchange code for Access Token).
_V_INSTALL_BASE = "https://vercel.com/integrations"
_V_TOKEN = "https://api.vercel.com/v2/oauth/access_token"
_V_API = "https://api.vercel.com"

V_OAUTH_STARTED = "vercel.oauth.started"
V_OAUTH_COMPLETED = "vercel.oauth.completed"
V_OAUTH_FAILED = "vercel.oauth.failed"
V_PROJECT_MATCHED = "vercel.project.matched"
V_PROJECT_NOT_FOUND = "vercel.project.not_found"
V_CONNECTED = "vercel.connected"
V_DISCONNECTED = "vercel.disconnected"
V_TRUSTED_ACCESS_PENDING = "vercel.trusted_access.pending"
V_VALIDATION_QUEUED = "vercel.validation.queued"


class VercelNotConfiguredError(RuntimeError):
    """Vercel OAuth client credentials are not configured."""


class VercelOAuthError(RuntimeError):
    """Token exchange / API call failed."""


def is_configured() -> bool:
    # All three are required for a WORKING classic-integration connect: the slug builds
    # the install URL, and the oac_* client id + secret exchange the returned code. A
    # missing slug must fail closed here (503 "not configured") rather than send users
    # to a broken authorize URL that Vercel rejects as "the app ID is invalid".
    s = get_settings()
    return bool(s.vercel_client_id and s.vercel_client_secret and s.vercel_integration_slug)


def _redirect_uri() -> str:
    return f"{get_settings().api_base_url}/providers/vercel/callback"


def sign_state(*, website_id, user_id, org_id) -> str:
    return provider_oauth.sign_state(VERCEL_PROVIDER, website_id=website_id,
                                     user_id=user_id, org_id=org_id)


def verify_state(state: str) -> dict:
    return provider_oauth.verify_state(VERCEL_PROVIDER, state)


def build_authorize_url(state: str) -> str:
    # Classic Integration External installation flow: send the user to the integration
    # install page identified by the SLUG, carrying only our signed CSRF `state`. The
    # redirect_uri / client_id are NOT query params here — Vercel uses the Redirect URL
    # configured on the Integration Console and appends code/teamId/configurationId/
    # state to it. (The oac_* client id + secret are used only at token exchange.)
    s = get_settings()
    return f"{_V_INSTALL_BASE}/{s.vercel_integration_slug}/new?{urlencode({'state': state})}"


async def get_connection(db: AsyncSession, website_id):
    return await provider_oauth.get_connection(db, website_id, VERCEL_PROVIDER)


def dashboard_view(conn) -> dict:
    return provider_oauth.dashboard_view(conn, provider=VERCEL_PROVIDER)


# ── Vercel API (token exchange + project/domain discovery) ─────────────────────

async def _exchange_code(code: str) -> dict:
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.post(_V_TOKEN, data={
            "client_id": s.vercel_client_id,
            "client_secret": s.vercel_client_secret,
            "code": code,
            "redirect_uri": _redirect_uri(),
        }, headers={"Accept": "application/json"})
    r.raise_for_status()
    return r.json()


async def _fetch_projects(access_token: str, team_id: str | None) -> list[dict]:
    """Projects (each augmented with its domains: [{name, verified}, ...])."""
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"limit": 50}
    if team_id:
        params["teamId"] = team_id
    async with httpx.AsyncClient(timeout=15) as client:
        pr = await client.get(f"{_V_API}/v9/projects", headers=headers, params=params)
        pr.raise_for_status()
        projects = pr.json().get("projects") or []
        for proj in projects:
            if "domains" in proj:
                continue
            dp = {"teamId": team_id} if team_id else None
            dr = await client.get(f"{_V_API}/v9/projects/{proj['id']}/domains",
                                  headers=headers, params=dp)
            proj["domains"] = dr.json().get("domains") or [] if dr.is_success else []
    return projects


def match_verified_domain(hostname: str, projects: list[dict]) -> tuple[dict | None, dict | None]:
    """Return (project, domain) where a project domain EXACTLY equals the hostname
    AND is verified, else (None, None). SECURITY: exact match + verified only — no
    subdomain inheritance (Vercel domains are per-entry), and an unverified or
    unrelated domain never proves control."""
    host = (hostname or "").lower().strip().rstrip(".")
    for proj in projects:
        for d in (proj.get("domains") or []):
            name = (d.get("name") or "").lower().strip().rstrip(".")
            if name == host and bool(d.get("verified")):
                return proj, d
    return None, None


def _capabilities(project: dict) -> dict:
    """Safe, non-secret capability metadata only."""
    return {
        "framework": project.get("framework"),
        "project_name": project.get("name"),
        "domains_count": len(project.get("domains") or []),
    }


async def complete_connection(db: AsyncSession, *, website: Website, code: str,
                              user_id, org_id) -> dict:
    """Exchange the code, match an EXACT verified Vercel domain, and ONLY then
    persist the token (via 4.1) + verify ownership + start trusted access
    (PENDING). Returns a result dict for the callback redirect. No bypass is
    configured; never logs the code/token."""
    if not get_key_management().is_configured:
        conn = await provider_oauth.get_or_create_connection(db, website, VERCEL_PROVIDER, user_id, org_id)
        conn.connection_status = ProviderConnectionStatus.FAILED.value
        provider_oauth.audit_event(db, V_OAUTH_FAILED, website, provider=VERCEL_PROVIDER,
                                   user_id=user_id, org_id=org_id, status="failed",
                                   reason="encryption_not_configured")
        raise EncryptionNotConfiguredError()

    try:
        token_data = await _exchange_code(code)
    except Exception as exc:  # noqa: BLE001 — never surface the code/token
        conn = await provider_oauth.get_or_create_connection(db, website, VERCEL_PROVIDER, user_id, org_id)
        conn.connection_status = ProviderConnectionStatus.FAILED.value
        provider_oauth.audit_event(db, V_OAUTH_FAILED, website, provider=VERCEL_PROVIDER,
                                   user_id=user_id, org_id=org_id, status="failed",
                                   reason="token_exchange_failed")
        raise VercelOAuthError("token exchange failed") from exc

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    team_id = token_data.get("team_id")
    if not access_token:
        conn = await provider_oauth.get_or_create_connection(db, website, VERCEL_PROVIDER, user_id, org_id)
        conn.connection_status = ProviderConnectionStatus.FAILED.value
        provider_oauth.audit_event(db, V_OAUTH_FAILED, website, provider=VERCEL_PROVIDER,
                                   user_id=user_id, org_id=org_id, status="failed",
                                   reason="no_access_token")
        raise VercelOAuthError("no access_token in response")
    provider_oauth.audit_event(db, V_OAUTH_COMPLETED, website, provider=VERCEL_PROVIDER,
                               user_id=user_id, org_id=org_id, status="connecting")

    projects = await _fetch_projects(access_token, team_id)
    project, domain = match_verified_domain(website.hostname, projects)

    conn = await provider_oauth.get_or_create_connection(db, website, VERCEL_PROVIDER, user_id, org_id)
    if project is None:
        conn.connection_status = ProviderConnectionStatus.FAILED.value
        conn.match_confidence = "none"
        conn.disconnected_at = datetime.now(timezone.utc)
        provider_oauth.audit_event(db, V_PROJECT_NOT_FOUND, website, provider=VERCEL_PROVIDER,
                                   user_id=user_id, org_id=org_id, status="failed",
                                   reason="no_verified_matching_domain")
        await db.flush()
        return {"matched": False, "status": "failed",
                "message": "No verified Vercel domain matches this website."}

    access_secret = await store_secret(
        db, resource_type=VERCEL_PROVIDER, secret_type="oauth_access_token",
        plaintext=access_token, org_id=org_id, user_id=user_id, website_id=website.id,
        metadata={"team_id": team_id})
    refresh_ref = None
    if refresh_token:
        refresh_secret = await store_secret(
            db, resource_type=VERCEL_PROVIDER, secret_type="oauth_refresh_token",
            plaintext=refresh_token, org_id=org_id, user_id=user_id, website_id=website.id)
        refresh_ref = str(refresh_secret.id)

    matched_domain = domain.get("name")
    conn.account_id = team_id or project.get("accountId")
    conn.zone_id = project.get("id")
    conn.zone_name = matched_domain
    conn.connection_status = ProviderConnectionStatus.CONNECTED.value
    conn.match_confidence = "high"
    conn.connected_at = datetime.now(timezone.utc)
    conn.last_sync_at = conn.connected_at
    conn.disconnected_at = None
    conn.permissions_granted = ["read-only"]
    conn.access_secret_reference = str(access_secret.id)
    conn.refresh_secret_reference = refresh_ref
    conn.connection_metadata = _capabilities(project)
    conn.evidence = [f"Vercel project '{project.get('name')}' has verified domain {matched_domain}"]
    await db.flush()
    provider_oauth.audit_event(db, V_PROJECT_MATCHED, website, provider=VERCEL_PROVIDER,
                               user_id=user_id, org_id=org_id, status="connected",
                               reason=f"domain:{matched_domain}")
    provider_oauth.audit_event(db, V_CONNECTED, website, provider=VERCEL_PROVIDER,
                               user_id=user_id, org_id=org_id, status="connected")

    await verify_service.mark_verified_via_provider(
        db, website, provider=VERCEL_PROVIDER, evidence=conn.evidence,
        actor_user_id=user_id, org_id=org_id)

    await ta_service.start_provider_oauth_access(
        db, website, provider=VERCEL_PROVIDER, evidence=conn.evidence,
        user_id=user_id, org_id=org_id)
    provider_oauth.audit_event(db, V_TRUSTED_ACCESS_PENDING, website, provider=VERCEL_PROVIDER,
                               user_id=user_id, org_id=org_id, status="pending",
                               reason="access validation is next")
    provider_oauth.audit_event(db, V_VALIDATION_QUEUED, website, provider=VERCEL_PROVIDER,
                               user_id=user_id, org_id=org_id, status="queued")

    return {"matched": True, "status": "connected", "domain": matched_domain}
