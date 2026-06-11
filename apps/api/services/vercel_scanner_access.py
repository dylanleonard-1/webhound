# WebHound — apps/api/services/vercel_scanner_access.py
# Phase 4.3 scanner-access orchestration (Vercel). Mirrors cloudflare_scanner_access:
# create + verify the Vercel WAF scanner bypass rule with the connect token (which
# already carries read-write:project — no second consent), persist reversible rule
# metadata, and ONLY THEN flip TrustedAccessProfile -> ACTIVE. Honest states:
#   active                 rule created AND verified
#   pending_permissions    token lacks firewall write (401/403) -> re-authorize
#   blocked_non_bypassable Vercel Attack Challenge Mode is on (a bypass rule can't
#                          override a project-wide challenge) -> tell the customer
#   failed                 rule setup/verify attempted and errored
# Disconnect removes the rule and reverts trusted access. NEVER logs the token.

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.encrypted_secret import EncryptedSecret
from apps.api.models.enums import SecretStatus, TrustedAccessMethod
from apps.api.models.website import Website
from apps.api.services import provider_oauth
from apps.api.services import trusted_access as ta_service
from apps.api.services import vercel as v
from apps.api.services import vercel_rules as v_rules
from apps.api.services.key_management import get_key_management
from apps.api.services.provider_oauth import EncryptionNotConfiguredError
from apps.api.services.secret_storage import (
    get_active_secret,
    reveal_secret,
    revoke_secret,
    store_secret,
)

# The read-only connect token (read-write:project) doubles as the firewall-write token
# — no separate elevated secret type, unlike Cloudflare's re-consent.
V_ACCESS_TOKEN_TYPE = "oauth_access_token"
SCANNER_ACCESS_META_KEY = "scanner_access"

# Audit events (never carry tokens).
V_SCANNER_RULE_CREATED = "vercel.scanner.rule.created"
V_SCANNER_RULE_VERIFIED = "vercel.scanner.rule.verified"
V_SCANNER_RULE_REMOVED = "vercel.scanner.rule.removed"
V_SCANNER_ACCESS_ACTIVE = "vercel.scanner.access.active"
V_SCANNER_ACCESS_PENDING_PERMS = "vercel.scanner.access.pending_permissions"
V_SCANNER_ACCESS_PENDING_FIREWALL = "vercel.scanner.access.pending_firewall_setup"
V_BYPASS_STORED = "vercel.protection_bypass.stored"
V_BYPASS_REMOVED = "vercel.protection_bypass.removed"

# Customer-provided Vercel "Protection Bypass for Automation" secret. The marketplace
# integration token cannot mint OR read it (native-integrations only), so the customer
# creates it in the dashboard and provides it; we store it encrypted and the scanner
# injects it as `x-vercel-protection-bypass` to clear the BotID/Security Checkpoint.
V_BYPASS_SECRET_TYPE = "vercel_protection_bypass"
V_SCANNER_NON_BYPASSABLE = "vercel.scanner.access.non_bypassable"
V_SCANNER_ACCESS_FAILED = "vercel.scanner.access.failed"

# Status strings returned to callers / dashboard (honest layered model).
ST_ACTIVE = "active"
ST_PENDING_PERMISSIONS = "pending_permissions"
ST_PENDING_FIREWALL_SETUP = "pending_firewall_setup"
ST_BLOCKED_NON_BYPASSABLE = "blocked_non_bypassable"
ST_FAILED = "failed"

_FIREWALL_INIT_ACTION = ("Enable the Firewall once in Vercel (Project → Firewall), then "
                         "reconnect Vercel. If it persists, grant the integration firewall access.")


def _audit(db, event, website, *, user_id, org_id, status, reason=None):
    provider_oauth.audit_event(db, event, website, provider=v.VERCEL_PROVIDER,
                               user_id=user_id, org_id=org_id, status=status, reason=reason)


async def _fail(db, website, *, user_id, org_id, reason: str) -> None:
    _audit(db, V_SCANNER_ACCESS_FAILED, website, user_id=user_id, org_id=org_id,
           status="failed", reason=reason)
    profile = await ta_service.get_trusted_access(db, website)
    if profile is not None:
        await ta_service.mark_failed(db, website, profile, reason=f"vercel_scanner_access:{reason}",
                                     user_id=user_id, org_id=org_id)
    await db.flush()


async def _ensure_profile(db, website, *, user_id, org_id):
    profile = await ta_service.get_trusted_access(db, website)
    if profile is None:
        profile = await ta_service.start_provider_oauth_access(
            db, website, provider=v.VERCEL_PROVIDER, user_id=user_id, org_id=org_id)
    return profile


def _store_rule_metadata(conn, *, project_id, team_id, attack_mode) -> None:
    if conn is None:
        return
    now_iso = datetime.now(timezone.utc).isoformat()
    md = dict(conn.connection_metadata or {})
    md[SCANNER_ACCESS_META_KEY] = {
        "rule_ref": v_rules.REF, "project_id": project_id, "team_id": team_id,
        "rule_type": "bypass", "created_by_webhound": True,
        "created_at": now_iso, "last_validated_at": now_iso, "attack_mode": attack_mode,
    }
    conn.connection_metadata = md


async def apply_scanner_bypass(
    db: AsyncSession, *, website: Website, access_token: str,
    project_id: str | None, team_id: str | None, user_id, org_id,
) -> dict:
    """Create + verify the Vercel scanner bypass rule with an ALREADY-exchanged token
    and flip trusted access ACTIVE — honestly. If the token can't write firewall
    (401/403) the dashboard shows pending_permissions (no failure). If Vercel Attack
    Challenge Mode is on, surface blocked_non_bypassable (trusted access LIMITED, not
    active — we never fake active). Never logs the token."""
    if not project_id:
        return {"applied": False, "status": ST_FAILED, "reason": "no_project"}

    try:
        created = await v_rules.ensure_bypass_rule(access_token, project_id, team_id)
    except v_rules.VercelFirewallUnavailableError:
        # Firewall config not initialized for this project (Vercel 404s GET+PUT). Honest
        # pending — NOT failed, NOT active. Keep trusted access PENDING and store a marker
        # so the dashboard shows the exact one-time customer action.
        _audit(db, V_SCANNER_ACCESS_PENDING_FIREWALL, website, user_id=user_id, org_id=org_id,
               status="pending", reason="firewall_not_initialized")
        await ta_service.start_provider_oauth_access(
            db, website, provider=v.VERCEL_PROVIDER, user_id=user_id, org_id=org_id)  # reset->pending
        conn = await v.get_connection(db, website.id)
        if conn is not None:
            md = dict(conn.connection_metadata or {})
            md[SCANNER_ACCESS_META_KEY] = {"firewall_status": "not_initialized",
                                           "created_by_webhound": False, "project_id": project_id}
            conn.connection_metadata = md
        await db.flush()
        return {"applied": False, "status": ST_PENDING_FIREWALL_SETUP,
                "reason": "firewall_not_initialized", "customer_action": _FIREWALL_INIT_ACTION}
    except v_rules.VercelRuleError as exc:
        if exc.http_status in (401, 403):
            _audit(db, V_SCANNER_ACCESS_PENDING_PERMS, website, user_id=user_id, org_id=org_id,
                   status="pending", reason="missing_firewall_write")
            await db.flush()
            return {"applied": False, "status": ST_PENDING_PERMISSIONS,
                    "reason": "missing_firewall_write"}
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="rule_create_failed")
        return {"applied": False, "status": ST_FAILED, "reason": "rule_create_failed"}

    _audit(db, V_SCANNER_RULE_CREATED, website, user_id=user_id, org_id=org_id,
           status="connecting",
           reason=",".join(created.get("created", []) + created.get("updated", [])
                           + created.get("existing", [])) or "none")
    try:
        verify = await v_rules.verify_bypass_rule(access_token, project_id, team_id)
    except v_rules.VercelRuleError:
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="rule_verify_failed")
        return {"applied": False, "status": ST_FAILED, "reason": "rule_verify_failed"}
    if not verify.get("verified"):
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="rule_verify_failed")
        return {"applied": False, "status": ST_FAILED, "reason": "rule_verify_failed", "verify": verify}
    _audit(db, V_SCANNER_RULE_VERIFIED, website, user_id=user_id, org_id=org_id, status="connected")

    conn = await v.get_connection(db, website.id)
    _store_rule_metadata(conn, project_id=project_id, team_id=team_id,
                         attack_mode=bool(verify.get("attack_mode")))

    # Attack Challenge Mode: a project-wide challenge our bypass rule cannot override.
    # The rule IS in place, but coverage is NOT guaranteed -> LIMITED, never 'active'.
    if verify.get("attack_mode"):
        _audit(db, V_SCANNER_NON_BYPASSABLE, website, user_id=user_id, org_id=org_id,
               status="limited", reason="attack_challenge_mode")
        profile = await _ensure_profile(db, website, user_id=user_id, org_id=org_id)
        await ta_service.mark_limited(db, website, profile, reason="vercel:attack_challenge_mode",
                                      user_id=user_id, org_id=org_id)
        await db.flush()
        return {"applied": True, "status": ST_BLOCKED_NON_BYPASSABLE,
                "customer_action": "Turn off Attack Challenge Mode in Vercel → Project → Firewall "
                                   "(or scope it to exclude the WebHound scanner), then re-validate.",
                "verify": verify}

    profile = await _ensure_profile(db, website, user_id=user_id, org_id=org_id)
    profile.access_method = TrustedAccessMethod.PROVIDER_OAUTH.value
    profile.evidence = [f"Vercel WAF scanner bypass rule created + verified for {website.hostname}"]
    await ta_service.mark_active(db, website, profile, reason="vercel:scanner_bypass_verified",
                                 user_id=user_id, org_id=org_id)
    _audit(db, V_SCANNER_ACCESS_ACTIVE, website, user_id=user_id, org_id=org_id, status="active")
    await db.flush()
    return {"applied": True, "status": ST_ACTIVE, "rules": created, "verify": verify}


# ── token retrieval / disconnect ──────────────────────────────────────────────

async def _load_access_token(db: AsyncSession, website_id) -> str | None:
    sec = await db.scalar(
        sa.select(EncryptedSecret).where(
            EncryptedSecret.website_id == website_id,
            EncryptedSecret.resource_type == v.VERCEL_PROVIDER,
            EncryptedSecret.secret_type == V_ACCESS_TOKEN_TYPE,
            EncryptedSecret.status == SecretStatus.ACTIVE.value,
        ).order_by(EncryptedSecret.created_at.desc()))
    if sec is None:
        return None
    return await reveal_secret(db, sec)  # in-process only; NEVER logged


async def _revoke_bypass_secrets(db: AsyncSession, website_id) -> None:
    rows = await db.scalars(
        sa.select(EncryptedSecret).where(
            EncryptedSecret.website_id == website_id,
            EncryptedSecret.resource_type == v.VERCEL_PROVIDER,
            EncryptedSecret.secret_type == V_BYPASS_SECRET_TYPE,
            EncryptedSecret.status == SecretStatus.ACTIVE.value,
        ))
    for sec in rows.all():
        await revoke_secret(db, sec)


async def store_protection_bypass(
    db: AsyncSession, *, website: Website, secret: str, user_id, org_id,
) -> dict:
    """Store the customer's Vercel Protection-Bypass-for-Automation secret (encrypted,
    Phase 4.1) and mark trusted access ACTIVE — the scanner will inject
    `x-vercel-protection-bypass` on this project's domains to clear Vercel's BotID/
    Security Checkpoint. Single active secret (revokes any prior). Reversible on
    disconnect. NEVER logs the secret."""
    if not get_key_management().is_configured:
        raise EncryptionNotConfiguredError()
    secret = (secret or "").strip()
    if not secret:
        return {"status": ST_FAILED, "reason": "empty_secret"}

    await _revoke_bypass_secrets(db, website.id)
    sec = await store_secret(
        db, resource_type=v.VERCEL_PROVIDER, secret_type=V_BYPASS_SECRET_TYPE,
        plaintext=secret, org_id=org_id, user_id=user_id, website_id=website.id,
        metadata={"method": "protection_bypass"})

    conn = await v.get_connection(db, website.id)
    if conn is not None:
        md = dict(conn.connection_metadata or {})
        md[SCANNER_ACCESS_META_KEY] = {
            "method": "protection_bypass", "created_by_webhound": True,
            "secret_ref": str(sec.id),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        conn.connection_metadata = md

    _audit(db, V_BYPASS_STORED, website, user_id=user_id, org_id=org_id, status="active")
    profile = await _ensure_profile(db, website, user_id=user_id, org_id=org_id)
    profile.access_method = TrustedAccessMethod.PROVIDER_OAUTH.value
    profile.evidence = [f"Vercel protection-bypass-for-automation configured; scanner "
                        f"trusted via x-vercel-protection-bypass for {website.hostname}"]
    await ta_service.mark_active(db, website, profile, reason="vercel:protection_bypass_stored",
                                 user_id=user_id, org_id=org_id)
    _audit(db, V_SCANNER_ACCESS_ACTIVE, website, user_id=user_id, org_id=org_id, status="active")
    await db.flush()
    return {"status": ST_ACTIVE}


async def load_protection_bypass(db: AsyncSession, website_id) -> str | None:
    """Decrypt + return the website's Vercel protection-bypass secret (worker hot path).
    Returns None when not configured. The caller MUST NOT log the value."""
    sec = await get_active_secret(
        db, resource_type=v.VERCEL_PROVIDER, secret_type=V_BYPASS_SECRET_TYPE, website_id=website_id)
    if sec is None:
        return None
    return await reveal_secret(db, sec)


async def disconnect_scanner_bypass(
    db: AsyncSession, *, website: Website, user_id, org_id,
) -> dict:
    """Remove the WebHound scanner bypass rule from Vercel and revert trusted access to
    PENDING. Reversible + idempotent — a missing rule/token is simply a no-op."""
    conn = await v.get_connection(db, website.id)
    project_id = conn.zone_id if conn else None
    team_id = conn.account_id if conn else None
    token = await _load_access_token(db, website.id)
    removed: list[str] = []
    if token and project_id:
        result = await v_rules.remove_bypass_rule(token, project_id, team_id)
        removed = result.get("removed", [])
        _audit(db, V_SCANNER_RULE_REMOVED, website, user_id=user_id, org_id=org_id,
               status="disconnected", reason=",".join(removed) or "none")

    # Revoke the stored protection-bypass secret (if any) — scanner stops sending it.
    await _revoke_bypass_secrets(db, website.id)

    if conn is not None and conn.connection_metadata:
        md = dict(conn.connection_metadata)
        md.pop(SCANNER_ACCESS_META_KEY, None)
        conn.connection_metadata = md

    profile = await ta_service.get_trusted_access(db, website)
    if profile is not None:
        await ta_service.start_provider_oauth_access(
            db, website, provider=v.VERCEL_PROVIDER, user_id=user_id, org_id=org_id)
    await db.flush()
    return {"status": "disconnected", "removed": removed}
