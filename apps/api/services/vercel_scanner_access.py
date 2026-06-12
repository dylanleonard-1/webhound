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
V_IP_BYPASS_CREATED = "vercel.scanner.ip_bypass.created"
V_IP_BYPASS_VERIFIED = "vercel.scanner.ip_bypass.verified"
V_IP_BYPASS_REMOVED = "vercel.scanner.ip_bypass.removed"
V_SCANNER_PENDING_MANUAL = "vercel.scanner.access.pending_manual_setup"

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
ST_PENDING_MANUAL_SETUP = "pending_manual_setup"
ST_CONFIGURED = "configured"
ST_BLOCKED_NON_BYPASSABLE = "blocked_non_bypassable"
ST_FAILED = "failed"


def manual_setup_action(ips: list[str]) -> str:
    """The exact customer step to allowlist the scanner by IP via a Vercel System Bypass."""
    ip_list = ", ".join(ips) if ips else "the WebHound scanner IP"
    return (f"Add a System Bypass Rule for {ip_list} in Vercel: Project → Firewall → "
            f"DDoS Mitigations & System Bypasses → Add Bypass Rule → Source IP → {ip_list}. "
            f"Then re-validate (we'll re-scan to confirm).")

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


# ── IP-scoped System Bypass orchestration (the primary connect path) ───────────

def _store_ip_metadata(conn, *, project_id, team_id, ips, method, created_by_webhound) -> None:
    if conn is None:
        return
    now_iso = datetime.now(timezone.utc).isoformat()
    md = dict(conn.connection_metadata or {})
    md[SCANNER_ACCESS_META_KEY] = {
        "method": method, "rule_type": "ip_system_bypass",
        "scanner_ips": list(ips), "project_id": project_id, "team_id": team_id,
        "created_by_webhound": created_by_webhound,
        "created_at": now_iso, "last_validated_at": now_iso,
    }
    conn.connection_metadata = md


async def apply_ip_scanner_access(
    db: AsyncSession, *, website: Website, access_token: str,
    project_id: str | None, team_id: str | None, user_id, org_id,
) -> dict:
    """PRIMARY Vercel scanner-access path: allowlist the WebHound scanner egress IP(s)
    (WEBHOUND_SCANNER_OUTBOUND_IPS) via a project-scoped Vercel System Bypass — IP-based,
    never UA, never global. If the token is FORBIDDEN (the marketplace-integration case),
    fall back to honest guided manual setup (pending_manual_setup) with the exact IP(s)
    and Vercel steps. NEVER marks trusted access ACTIVE here — only a scan that actually
    crawls past the challenge can do that. Never logs the token."""
    from apps.api.config import scanner_outbound_ips as _outbound_ips
    if not project_id:
        return {"applied": False, "status": ST_FAILED, "reason": "no_project"}
    ips = _outbound_ips()

    try:
        created = await v_rules.ensure_ip_system_bypass(access_token, project_id, team_id, ips)
    except v_rules.VercelBypassForbiddenError:
        # Forbidden (integration token can't write firewall/ipBlocking) -> guided manual
        # setup. Honest: trusted access stays PENDING; surface the IP(s) + steps + ticket.
        _audit(db, V_SCANNER_PENDING_MANUAL, website, user_id=user_id, org_id=org_id,
               status="pending", reason="ip_bypass_forbidden")
        await ta_service.start_provider_oauth_access(
            db, website, provider=v.VERCEL_PROVIDER, user_id=user_id, org_id=org_id)
        conn = await v.get_connection(db, website.id)
        _store_ip_metadata(conn, project_id=project_id, team_id=team_id, ips=ips,
                           method="manual_ip_bypass", created_by_webhound=False)
        await db.flush()
        # Registry-driven structured remediation (numbered steps + copy metadata)
        # for the PlatformAccessWizard, alongside the legacy single-string action.
        from apps.api.services.provider_access_registry import render_remediation
        remediation = render_remediation("vercel", ips)
        return {"applied": False, "status": ST_PENDING_MANUAL_SETUP, "scanner_ips": ips,
                "ticketable": True, "customer_action": manual_setup_action(ips),
                "remediation": remediation}
    except v_rules.VercelRuleError:
        await _fail(db, website, user_id=user_id, org_id=org_id, reason="ip_bypass_failed")
        return {"applied": False, "status": ST_FAILED, "reason": "ip_bypass_failed"}

    # Token HAD permission (future-proof / native integration): rule created. Verify, but
    # do NOT claim active — a scan must prove the IP bypass actually clears the challenge.
    _audit(db, V_IP_BYPASS_CREATED, website, user_id=user_id, org_id=org_id, status="configured",
           reason=",".join(created.get("created", []) + created.get("existing", [])) or "none")
    verify = await v_rules.verify_ip_system_bypass(access_token, project_id, team_id, ips)
    if verify.get("verified"):
        _audit(db, V_IP_BYPASS_VERIFIED, website, user_id=user_id, org_id=org_id, status="configured")
    conn = await v.get_connection(db, website.id)
    _store_ip_metadata(conn, project_id=project_id, team_id=team_id, ips=ips,
                       method="ip_system_bypass", created_by_webhound=True)
    # Keep trusted access PENDING — validated by the next scan (no fake active).
    await ta_service.start_provider_oauth_access(
        db, website, provider=v.VERCEL_PROVIDER, user_id=user_id, org_id=org_id)
    await db.flush()
    return {"applied": True, "status": ST_CONFIGURED, "scanner_ips": ips, "verify": verify,
            "note": "Vercel IP System Bypass created for the scanner IP(s); coverage is "
                    "confirmed on the next scan."}


async def remove_ip_scanner_access(db: AsyncSession, *, website: Website, user_id, org_id) -> dict:
    """Best-effort removal of the scanner IP System Bypass on disconnect. Idempotent;
    swallows a forbidden token (nothing was created)."""
    from apps.api.config import scanner_outbound_ips as _outbound_ips
    conn = await v.get_connection(db, website.id)
    project_id = conn.zone_id if conn else None
    team_id = conn.account_id if conn else None
    token = await _load_access_token(db, website.id)
    removed: list[str] = []
    if token and project_id:
        try:
            res = await v_rules.remove_ip_system_bypass(token, project_id, team_id, _outbound_ips())
            removed = res.get("removed", [])
            if removed:
                _audit(db, V_IP_BYPASS_REMOVED, website, user_id=user_id, org_id=org_id,
                       status="disconnected", reason=",".join(removed))
        except v_rules.VercelRuleError:
            pass  # forbidden / nothing to remove — best-effort
    return {"removed": removed}


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

    # Storing the secret CONFIGURES the bypass — it does NOT prove coverage. Some Vercel
    # protections (notably BotID's client-side "Security Checkpoint") are not cleared by
    # the automation-bypass header, so we must NEVER claim active on store. Trusted access
    # stays PENDING; only a scan that actually crawls past the challenge promotes it.
    _audit(db, V_BYPASS_STORED, website, user_id=user_id, org_id=org_id,
           status="configured", reason="pending_scan_validation")
    profile = await _ensure_profile(db, website, user_id=user_id, org_id=org_id)
    profile.access_method = TrustedAccessMethod.PROVIDER_OAUTH.value
    profile.evidence = [f"Vercel protection-bypass-for-automation secret stored; scanner will "
                        f"inject x-vercel-protection-bypass for {website.hostname} — coverage "
                        f"confirmed on the next scan"]
    await db.flush()
    return {"status": "configured",
            "note": "Bypass secret stored; the scanner will use it. Coverage is confirmed by "
                    "the next scan — Vercel BotID/Security Checkpoint may still challenge the "
                    "headless scanner, which the automation-bypass header does not always clear."}


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
        try:
            result = await v_rules.remove_bypass_rule(token, project_id, team_id)
            removed = result.get("removed", [])
            if removed:
                _audit(db, V_SCANNER_RULE_REMOVED, website, user_id=user_id, org_id=org_id,
                       status="disconnected", reason=",".join(removed))
        except v_rules.VercelRuleError:
            pass  # firewall API unavailable/forbidden — nothing to remove

    # Remove the IP System Bypass entries (best-effort; forbidden token = no-op).
    ip_removed = (await remove_ip_scanner_access(db, website=website, user_id=user_id, org_id=org_id)).get("removed", [])
    removed = list(removed) + list(ip_removed)

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
