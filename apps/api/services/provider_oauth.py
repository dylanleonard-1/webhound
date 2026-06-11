# WebHound — apps/api/services/provider_oauth.py
# Phase 4.3 — shared provider-OAuth base (Cloudflare 4.2 was the reference; this
# is the generic pattern reused by Cloudflare, Vercel, and future providers).
# Holds only the PROVIDER-AGNOSTIC pieces: signed-state CSRF, connection lookup/
# upsert on the generic ProviderConnection model, audit, and the customer-safe
# dashboard view. Provider-specific OAuth URLs / token exchange / API discovery /
# domain matching live in each provider's own service module.

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.models.provider_connection import ProviderConnection
from apps.api.models.website import Website
from apps.api.services.key_management import get_key_management
from apps.api.services.phase3_audit import record_phase3_event

_STATE_TTL_MINUTES = 15


class InvalidStateError(RuntimeError):
    """OAuth state is missing, tampered, expired, or has the wrong purpose/provider."""


class EncryptionNotConfiguredError(RuntimeError):
    """ENCRYPTION_KEYS not configured — refuse to persist tokens (fail closed)."""


def encryption_ready() -> bool:
    return get_key_management().is_configured


# ── Signed-state CSRF (the unauthenticated callback's only identity) ──────────

def sign_state(provider: str, *, website_id, user_id, org_id, phase: str = "connect") -> str:
    s = get_settings()
    payload = {
        "wid": str(website_id),
        "uid": str(user_id) if user_id else None,
        "oid": str(org_id) if org_id else None,
        "provider": provider,
        "purpose": f"{provider}_oauth",
        # OAuth sub-phase: "connect" (read-only zone discovery) vs "scanner_access"
        # (elevated re-consent that creates the scanner firewall rule). The shared
        # callback branches on this. Older states without it default to "connect".
        "phase": phase,
        "jti": secrets.token_urlsafe(8),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=_STATE_TTL_MINUTES),
    }
    return jwt_encode(payload, s.secret_key, s.algorithm)


def verify_state(provider: str, state: str) -> dict:
    s = get_settings()
    try:
        payload = jwt_decode(state, s.secret_key, s.algorithm)
    except Exception as exc:  # PyJWT errors -> uniform InvalidStateError
        raise InvalidStateError(str(exc)) from exc
    if (payload.get("purpose") != f"{provider}_oauth"
            or payload.get("provider") != provider
            or not payload.get("wid")):
        raise InvalidStateError("bad state purpose/provider")
    return payload


# Thin jwt indirection keeps this module import-light + easy to reason about.
def jwt_encode(payload: dict, key: str, alg: str) -> str:
    import jwt
    return jwt.encode(payload, key, algorithm=alg)


def jwt_decode(token: str, key: str, alg: str) -> dict:
    import jwt
    return jwt.decode(token, key, algorithms=[alg])


# ── ProviderConnection lookup / upsert (generic, provider-discriminated) ──────

async def get_connection(db: AsyncSession, website_id, provider: str) -> ProviderConnection | None:
    return await db.scalar(
        sa.select(ProviderConnection).where(
            ProviderConnection.website_id == website_id,
            ProviderConnection.provider == provider))


async def get_or_create_connection(
    db: AsyncSession, website: Website, provider: str, user_id, org_id,
) -> ProviderConnection:
    conn = await get_connection(db, website.id, provider)
    if conn is None:
        conn = ProviderConnection(website_id=website.id, provider=provider)
        db.add(conn)
    conn.user_id = user_id if user_id is not None else website.user_id
    conn.org_id = org_id if org_id is not None else website.org_id
    return conn


def audit_event(db, event, website, *, provider, user_id, org_id, status, reason=None):
    """Append a provider audit event to the Phase-3.8 trail. NEVER carries secrets."""
    record_phase3_event(
        db, event_type=event, website=website, actor_user_id=user_id, org_id=org_id,
        provider=provider, status=status, reason=reason, resource_type="provider_connection")


# ── Customer-safe dashboard ───────────────────────────────────────────────────

def dashboard_view(conn: ProviderConnection | None, *, provider: str | None = None) -> dict:
    """One provider's connection state — NO account/team/project/zone ids, tokens,
    permissions, or raw metadata. Only the state + the customer's own domain."""
    if conn is None:
        return {"provider": provider, "connection_status": "not_connected",
                "connected": False, "connected_at": None, "domain": None}
    return {
        "provider": conn.provider,
        "connection_status": conn.connection_status,
        "connected": conn.connection_status == "connected",
        "connected_at": conn.connected_at.isoformat() if conn.connected_at else None,
        "domain": conn.zone_name,
    }


async def list_connection_views(db: AsyncSession, website_id) -> list[dict]:
    """Per-provider connection state for a website (a site has N connections —
    e.g. Cloudflare AND Vercel). Customer-safe; no secrets."""
    conns = (await db.scalars(
        sa.select(ProviderConnection).where(ProviderConnection.website_id == website_id)
        .order_by(ProviderConnection.provider))).all()
    return [dashboard_view(c) for c in conns]
