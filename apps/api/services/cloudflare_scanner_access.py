# WebHound — apps/api/services/cloudflare_scanner_access.py
# Phase 3.4 scanner-access orchestration. Completes the ELEVATED Cloudflare OAuth
# re-consent, creates + verifies the scanner firewall skip rules, persists the
# elevated token encrypted (Phase 4.1, separate from the read-only connect token),
# and ONLY THEN flips TrustedAccessProfile -> ACTIVE. Disconnect removes the rules
# and reverts trusted access. NEVER logs tokens.

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.encrypted_secret import EncryptedSecret
from apps.api.models.enums import SecretStatus, TrustedAccessMethod
from apps.api.models.website import Website
from apps.api.services import cloudflare as cf
from apps.api.services import cloudflare_rules as cf_rules
from apps.api.services import cloudflare_scopes as cf_scopes
from apps.api.services import cloudflare_telemetry as cf_telemetry
from apps.api.services import trusted_access as ta_service
from apps.api.services.key_management import get_key_management
from apps.api.services.provider_oauth import EncryptionNotConfiguredError
from apps.api.services.secret_storage import reveal_secret, revoke_secret, store_secret

# Distinct secret types so the elevated token lives SEPARATELY from the read-only
# connect token (oauth_access_token) and is retrievable by (website, type) — no new
# DB column required.
SCANNER_TOKEN_TYPE = "oauth_scanner_access_token"
SCANNER_REFRESH_TYPE = "oauth_scanner_refresh_token"
# Reversible rule metadata is stored under this key in ProviderConnection.metadata.
SCANNER_ACCESS_META_KEY = "scanner_access"


async def _fail(db, website, *, user_id, org_id, reason: str) -> None:
    cf._audit(db, cf.CF_SCANNER_ACCESS_FAILED, website, user_id=user_id, org_id=org_id,
              status="failed", reason=reason)
    profile = await ta_service.get_trusted_access(db, website)
    if profile is not None:
        await ta_service.mark_failed(db, website, profile, reason=f"scanner_access:{reason}",
                                     user_id=user_id, org_id=org_id)
    await db.flush()


async def _zone_id(db: AsyncSession, website: Website) -> str | None:
    conn = await cf.get_connection(db, website.id)
    return conn.zone_id if conn else None


async def apply_scanner_rules(
    db: AsyncSession, *, website: Website, access_token: str, refresh_token: str | None,
    scope: str, zone_id: str | None, user_id, org_id,
) -> dict:
    """Create + verify the scanner skip rules with an ALREADY-exchanged token, persist
    the token + reversible rule metadata, and flip trusted access ACTIVE.

    Permission-gated: if `scope` lacks a firewall WRITE scope, NO rules are created
    (the dashboard then shows pending_permissions). Shared by the single Connect
    Cloudflare flow AND the standalone re-consent. Never logs the token."""
    if not zone_id:
        return {"applied": False, "reason": "no_zone"}
    if not cf_scopes.has_rule_edit_permission(scope):
        # No firewall write granted -> can't create the rule. Honest, not a failure.
        cf._audit(db, cf.CF_SCANNER_ACCESS_FAILED, website, user_id=user_id, org_id=org_id,
                  status="pending", reason="missing_rule_edit_permission")
        return {"applied": False, "reason": "no_permission"}

    cf._audit(db, cf.CF_SCANNER_ACCESS_AUTHORIZED, website, user_id=user_id, org_id=org_id,
              status="connecting")
    # Create the skip rules, then read them back to verify.
    try:
        created = await cf_rules.ensure_scanner_rules(access_token, zone_id)
        verify = await cf_rules.verify_scanner_rules(access_token, zone_id)
    except cf_rules.CloudflareRuleError:
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="rule_create_failed")
        raise
    cf._audit(db, cf.CF_SCANNER_RULE_CREATED, website, user_id=user_id, org_id=org_id,
              status="connecting",
              reason=",".join(created.get("created", []) + created.get("updated", [])
                              + created.get("existing", [])) or "none")
    if not verify.get("verified"):
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="rule_verify_failed")
        return {"applied": False, "reason": "rule_verify_failed", "verify": verify}
    cf._audit(db, cf.CF_SCANNER_RULE_VERIFIED, website, user_id=user_id, org_id=org_id,
              status="connected")

    # Persist the token (for later disconnect/telemetry/re-validate) + rule metadata.
    await store_secret(
        db, resource_type=cf.CLOUDFLARE_PROVIDER, secret_type=SCANNER_TOKEN_TYPE,
        plaintext=access_token, org_id=org_id, user_id=user_id, website_id=website.id,
        metadata={"scope": scope})
    if refresh_token:
        await store_secret(
            db, resource_type=cf.CLOUDFLARE_PROVIDER, secret_type=SCANNER_REFRESH_TYPE,
            plaintext=refresh_token, org_id=org_id, user_id=user_id, website_id=website.id)
    now_iso = datetime.now(timezone.utc).isoformat()
    conn = await cf.get_connection(db, website.id)
    if conn is not None:
        md = dict(conn.connection_metadata or {})
        md[SCANNER_ACCESS_META_KEY] = {
            "rule_ids": created.get("rule_ids"), "ruleset_id": created.get("ruleset_id"),
            "zone_id": zone_id, "rule_type": "skip", "created_by_webhound": True,
            "created_at": now_iso, "last_validated_at": now_iso,
            "degraded": created.get("degraded", False),
        }
        conn.connection_metadata = md

    profile = await ta_service.get_trusted_access(db, website)
    if profile is None:
        profile = await ta_service.start_provider_oauth_access(
            db, website, provider=cf.CLOUDFLARE_PROVIDER, user_id=user_id, org_id=org_id)
    profile.access_method = TrustedAccessMethod.PROVIDER_OAUTH.value
    profile.permissions_granted = scope.split()
    profile.evidence = [f"Cloudflare firewall skip rules created + verified for {website.hostname}"]
    await ta_service.mark_active(db, website, profile, reason="cloudflare:scanner_rules_verified",
                                 user_id=user_id, org_id=org_id)
    await db.flush()
    return {"applied": True, "verified": True, "rules": created}


async def complete_scanner_access(
    db: AsyncSession, *, website: Website, code: str, user_id, org_id,
) -> dict:
    """Standalone scanner-access re-consent (kept for backward-compat / re-authorize).
    The PRIMARY path is now the single Connect Cloudflare flow, which calls
    apply_scanner_rules directly with the already-exchanged token."""
    cf._audit(db, cf.CF_SCANNER_ACCESS_STARTED, website, user_id=user_id, org_id=org_id,
              status="connecting")
    if not get_key_management().is_configured:
        await _fail(db, website, user_id=user_id, org_id=org_id,
                    reason="encryption_not_configured")
        raise EncryptionNotConfiguredError()
    zone_id = await _zone_id(db, website)
    if not zone_id:
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="no_connected_zone")
        return {"status": "failed", "reason": "no_connected_zone"}
    token_data = await cf._exchange_code(code)
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    scope = token_data.get("scope") or cf._scanner_scopes()
    if not access_token:
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="no_access_token")
        raise cf.CloudflareOAuthError("no access_token in scanner-access response")
    result = await apply_scanner_rules(
        db, website=website, access_token=access_token, refresh_token=refresh_token,
        scope=scope, zone_id=zone_id, user_id=user_id, org_id=org_id)
    if result.get("applied"):
        return {"status": "active", "rules": result.get("rules")}
    return {"status": "failed", "reason": result.get("reason", "unknown")}


# ── token retrieval / disconnect ──────────────────────────────────────────────

async def _scanner_secrets(db: AsyncSession, website_id) -> list[EncryptedSecret]:
    rows = await db.scalars(
        sa.select(EncryptedSecret).where(
            EncryptedSecret.website_id == website_id,
            EncryptedSecret.resource_type == cf.CLOUDFLARE_PROVIDER,
            EncryptedSecret.secret_type.in_((SCANNER_TOKEN_TYPE, SCANNER_REFRESH_TYPE)),
            EncryptedSecret.status == SecretStatus.ACTIVE.value,
        ).order_by(EncryptedSecret.created_at.desc()))
    return list(rows.all())


async def _load_scanner_token(db: AsyncSession, website_id) -> str | None:
    sec = await db.scalar(
        sa.select(EncryptedSecret).where(
            EncryptedSecret.website_id == website_id,
            EncryptedSecret.resource_type == cf.CLOUDFLARE_PROVIDER,
            EncryptedSecret.secret_type == SCANNER_TOKEN_TYPE,
            EncryptedSecret.status == SecretStatus.ACTIVE.value,
        ).order_by(EncryptedSecret.created_at.desc()))
    if sec is None:
        return None
    return await reveal_secret(db, sec)  # in-process only; NEVER logged


async def read_telemetry(db: AsyncSession, *, website: Website, user_id, org_id) -> dict:
    """Foundation-only security-telemetry read using the elevated token's read
    scopes. Returns a compact summary; never raises on a missing product."""
    zone_id = await _zone_id(db, website)
    token = await _load_scanner_token(db, website.id)
    if not token or not zone_id:
        return {"available": False, "reason": "scanner_access_not_configured"}
    summary = await cf_telemetry.read_security_telemetry(token, zone_id)
    cf._audit(db, cf.CF_SCANNER_TELEMETRY_READ, website, user_id=user_id, org_id=org_id,
              status="active")
    await db.flush()
    return {"available": True, "telemetry": summary}


async def disconnect_scanner_access(
    db: AsyncSession, *, website: Website, user_id, org_id,
) -> dict:
    """Remove the WebHound scanner rules from Cloudflare, revoke the stored elevated
    token, and revert trusted access to PENDING. Reversible + idempotent."""
    zone_id = await _zone_id(db, website)
    token = await _load_scanner_token(db, website.id)
    removed: list[str] = []
    if token and zone_id:
        result = await cf_rules.remove_scanner_rules(token, zone_id)
        removed = result.get("removed", [])
        cf._audit(db, cf.CF_SCANNER_RULE_REMOVED, website, user_id=user_id, org_id=org_id,
                  status="disconnected", reason=",".join(removed) or "none")

    # Revoke the elevated token secret(s) — nothing decryptable remains.
    for sec in await _scanner_secrets(db, website.id):
        await revoke_secret(db, sec)

    # Clear the stored rule metadata (rule is gone).
    conn = await cf.get_connection(db, website.id)
    if conn is not None and conn.connection_metadata:
        md = dict(conn.connection_metadata)
        md.pop(SCANNER_ACCESS_META_KEY, None)
        conn.connection_metadata = md

    # Revert trusted access to PENDING (back to the pre-scanner-access state).
    profile = await ta_service.get_trusted_access(db, website)
    if profile is not None:
        await ta_service.start_provider_oauth_access(
            db, website, provider=cf.CLOUDFLARE_PROVIDER, user_id=user_id, org_id=org_id)
    await db.flush()
    return {"status": "disconnected", "removed": removed}
