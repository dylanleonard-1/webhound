# WebHound — apps/api/services/cloudflare_scanner_access.py
# Phase 3.4 scanner-access orchestration. Completes the ELEVATED Cloudflare OAuth
# re-consent, creates + verifies the scanner firewall skip rules, persists the
# elevated token encrypted (Phase 4.1, separate from the read-only connect token),
# and ONLY THEN flips TrustedAccessProfile -> ACTIVE. Disconnect removes the rules
# and reverts trusted access. NEVER logs tokens.

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.encrypted_secret import EncryptedSecret
from apps.api.models.enums import SecretStatus, TrustedAccessMethod
from apps.api.models.website import Website
from apps.api.services import cloudflare as cf
from apps.api.services import cloudflare_rules as cf_rules
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


async def complete_scanner_access(
    db: AsyncSession, *, website: Website, code: str, user_id, org_id,
) -> dict:
    """Exchange the elevated code, create + verify the scanner skip rules, persist
    the elevated token, and mark trusted access ACTIVE. Returns a result dict for
    the callback redirect. Never logs the code or token."""
    cf._audit(db, cf.CF_SCANNER_ACCESS_STARTED, website, user_id=user_id, org_id=org_id,
              status="connecting")

    # Fail closed if we cannot encrypt the elevated token at rest.
    if not get_key_management().is_configured:
        await _fail(db, website, user_id=user_id, org_id=org_id,
                    reason="encryption_not_configured")
        raise EncryptionNotConfiguredError()

    # The read-only connect already matched + stored the owning zone; we need its id
    # to target the Rulesets API.
    zone_id = await _zone_id(db, website)
    if not zone_id:
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="no_connected_zone")
        return {"status": "failed", "reason": "no_connected_zone"}

    # Exchange elevated code -> token (held in memory only). Reuses the proven
    # client_secret_post(+basic fallback) exchange.
    token_data = await cf._exchange_code(code)
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    scope = token_data.get("scope") or cf._scanner_scopes()
    if not access_token:
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="no_access_token")
        raise cf.CloudflareOAuthError("no access_token in scanner-access response")
    cf._audit(db, cf.CF_SCANNER_ACCESS_AUTHORIZED, website, user_id=user_id, org_id=org_id,
              status="connecting")

    # Create the skip rules, then read them back to verify (rules in memory token).
    try:
        created = await cf_rules.ensure_scanner_rules(access_token, zone_id)
        verify = await cf_rules.verify_scanner_rules(access_token, zone_id)
    except cf_rules.CloudflareRuleError:
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="rule_create_failed")
        raise
    cf._audit(db, cf.CF_SCANNER_RULE_CREATED, website, user_id=user_id, org_id=org_id,
              status="connecting",
              reason=",".join(created.get("created", []) + created.get("existing", [])) or "none")

    if not verify.get("verified"):
        # Rules didn't read back as present+enabled — do NOT claim active. The
        # elevated token is discarded (never stored).
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="rule_verify_failed")
        return {"status": "failed", "reason": "rule_verify_failed", "verify": verify}
    cf._audit(db, cf.CF_SCANNER_RULE_VERIFIED, website, user_id=user_id, org_id=org_id,
              status="connected")

    # Rules verified -> persist the elevated token(s) encrypted (Phase 4.1).
    await store_secret(
        db, resource_type=cf.CLOUDFLARE_PROVIDER, secret_type=SCANNER_TOKEN_TYPE,
        plaintext=access_token, org_id=org_id, user_id=user_id, website_id=website.id,
        metadata={"scope": scope})
    if refresh_token:
        await store_secret(
            db, resource_type=cf.CLOUDFLARE_PROVIDER, secret_type=SCANNER_REFRESH_TYPE,
            plaintext=refresh_token, org_id=org_id, user_id=user_id, website_id=website.id)

    # Flip trusted access -> ACTIVE (rules are the proof access actually works).
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
    return {"status": "active", "rules": created, "verify": verify}


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

    # Revert trusted access to PENDING (back to the pre-scanner-access state).
    profile = await ta_service.get_trusted_access(db, website)
    if profile is not None:
        await ta_service.start_provider_oauth_access(
            db, website, provider=cf.CLOUDFLARE_PROVIDER, user_id=user_id, org_id=org_id)
    await db.flush()
    return {"status": "disconnected", "removed": removed}
