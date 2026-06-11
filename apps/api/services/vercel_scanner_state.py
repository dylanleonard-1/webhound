# WebHound — apps/api/services/vercel_scanner_state.py
# Phase 4.3 scanner-access — derive the HONEST Vercel scanner-access status from the
# block diagnosis + rule/permission facts. Pure + testable. Cardinal rule: NEVER
# report `active` unless Vercel is actually the blocker AND our bypass rule was created
# and verified. If Attack Challenge Mode (project-wide) is on, a bypass rule can't
# override it — say blocked_non_bypassable, not active. If another layer (Cloudflare)
# is the real wall, say so.

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import TrustedAccessStatus
from apps.api.models.website import Website
from apps.api.services import scanner_block_detection as det
from apps.api.services import trusted_access as ta_service
from apps.api.services import vercel as v
from apps.api.services.vercel_scanner_access import SCANNER_ACCESS_META_KEY

STATUS_NOT_NEEDED = "not_needed"                       # Vercel connected but not blocking
STATUS_PENDING_PERMISSIONS = "pending_permissions"     # Vercel may block but token lacks firewall write
STATUS_PENDING_MANUAL_SETUP = "pending_manual_setup"   # token forbidden -> customer adds the IP System Bypass
STATUS_PENDING_FIREWALL_SETUP = "pending_firewall_setup"  # firewall config not initialized (404 GET+PUT)
STATUS_PENDING_RULE_SETUP = "pending_rule_setup"       # Vercel may block; needs the bypass rule
STATUS_ACTIVE = "active"                               # rule created AND verified
STATUS_BLOCKED_NON_BYPASSABLE = "blocked_non_bypassable"  # Attack Challenge Mode — rule can't override
STATUS_BLOCKED_BY_OTHER = "blocked_by_other_provider"  # Vercel connected; another layer blocks
STATUS_FAILED = "failed"                              # rule setup attempted and failed

_REAUTH_ACTION = "Re-authorize Vercel with firewall (project read-write) permission"
_FIREWALL_INIT_ACTION = ("Enable the Firewall once in Vercel (Project → Firewall), then reconnect "
                         "Vercel. If it persists, grant the integration firewall access.")
_ATTACK_ACTION = ("Turn off Attack Challenge Mode in Vercel → Project → Firewall "
                  "(or scope it to exclude the WebHound scanner), then re-validate.")


def _r(status: str, blocker: str | None, next_action: str | None, message: str) -> dict:
    return {"status": status, "blocker": blocker, "next_action": next_action, "message": message}


def derive_status(
    detection: dict, *, vercel_connected: bool, has_rule: bool, rule_verified: bool,
    has_firewall_write_permission: bool, attack_mode: bool = False,
    rule_setup_failed: bool = False, firewall_initialized: bool = True,
) -> dict:
    """Return {status, blocker, next_action, message}. `detection` is the result of
    scanner_block_detection.classify_scan_blocker (may be empty pre-scan)."""
    blocker = detection.get("blocker")
    active_provider = detection.get("active_blocker_provider")

    if not vercel_connected:
        return _r(STATUS_NOT_NEEDED, None, None, "Connect Vercel to manage scanner access.")

    if vercel_connected and not firewall_initialized and not has_rule:
        return _r(STATUS_PENDING_FIREWALL_SETUP, "vercel", _FIREWALL_INIT_ACTION,
                  "Vercel connected, but the project's Firewall isn't initialized — Vercel's API "
                  "can't create rules until it exists. " + _FIREWALL_INIT_ACTION)

    if rule_setup_failed:
        return _r(STATUS_FAILED, "vercel", "Retry Vercel scanner access setup",
                  "Vercel scanner bypass setup failed. Retry, or set it up manually.")

    # Attack Challenge Mode overrides everything our rule can do — surface it honestly
    # even if the rule exists.
    if attack_mode:
        return _r(STATUS_BLOCKED_NON_BYPASSABLE, "vercel", _ATTACK_ACTION,
                  "Vercel Attack Challenge Mode is on — a custom bypass rule can't override "
                  "a project-wide challenge. " + _ATTACK_ACTION)

    # No challenge at all -> Vercel is not blocking the scanner.
    if blocker == det.BLOCKER_NONE:
        return _r(STATUS_NOT_NEEDED, None, None,
                  "Vercel connected. Vercel is not blocking the scanner.")

    # A different layer (Cloudflare/other) is the FINAL blocker — do NOT fake active.
    if active_provider and active_provider != "vercel":
        return _r(STATUS_BLOCKED_BY_OTHER, active_provider, detection.get("next_action"),
                  f"Vercel connected. Vercel is not blocking the scanner. "
                  f"Current blocker: {active_provider.title()}.")

    # Vercel is (or may be) the blocker.
    if has_rule and rule_verified:
        return _r(STATUS_ACTIVE, "vercel", None,
                  "Vercel scanner access active. Bypass rule created and verified.")
    if not has_firewall_write_permission:
        return _r(STATUS_PENDING_PERMISSIONS, "vercel", _REAUTH_ACTION,
                  "Vercel connected but missing firewall write permission. " + _REAUTH_ACTION + ".")
    return _r(STATUS_PENDING_RULE_SETUP, "vercel", "Set up Vercel scanner access",
              "Vercel connected. Vercel scanner bypass required. Set up scanner access.")


async def scanner_access_view(db: AsyncSession, website: Website) -> dict:
    """DB-backed honest status from stored facts (rule metadata + trusted access). No
    scan-time detection here — that layered tie-in happens in the scan diagnosis."""
    def _c(status, blocker, next_action, message):  # connected view (connected=True)
        return {"status": status, "blocker": blocker, "next_action": next_action,
                "message": message, "connected": True}

    conn = await v.get_connection(db, website.id)
    if conn is None or conn.connection_status != "connected":
        return {**_r(STATUS_NOT_NEEDED, None, "Connect Vercel", "Vercel is not connected."),
                "connected": False}

    meta = (conn.connection_metadata or {}).get(SCANNER_ACCESS_META_KEY) or {}
    has_rule = bool(meta.get("created_by_webhound"))
    attack_mode = bool(meta.get("attack_mode"))
    profile = await ta_service.get_trusted_access(db, website)
    ta_status = profile.access_status if profile else None

    # Guided manual IP allowlist (the marketplace-integration reality): the token can't
    # create the System Bypass, so the customer adds it. Surface the exact IP(s) + steps.
    if meta.get("method") == "manual_ip_bypass" and ta_status != TrustedAccessStatus.ACTIVE.value:
        from apps.api.services.vercel_scanner_access import manual_setup_action
        ips = meta.get("scanner_ips") or []
        out = _c(STATUS_PENDING_MANUAL_SETUP, "vercel", manual_setup_action(ips),
                 "Vercel connected. Add a System Bypass for the WebHound scanner IP(s) to let "
                 "the scanner through — we can't create it for you on this integration.")
        out["scanner_ips"] = ips
        out["ticketable"] = True
        return out

    if meta.get("firewall_status") == "not_initialized" and not has_rule:
        return _c(STATUS_PENDING_FIREWALL_SETUP, "vercel", _FIREWALL_INIT_ACTION,
                  "Vercel connected, but the project's Firewall isn't initialized yet. "
                  + _FIREWALL_INIT_ACTION)

    if attack_mode:
        return _c(STATUS_BLOCKED_NON_BYPASSABLE, "vercel", _ATTACK_ACTION,
                  "Vercel Attack Challenge Mode is on — turn it off (or exclude the scanner) "
                  "for full coverage.")
    if has_rule and ta_status == TrustedAccessStatus.ACTIVE.value:
        return _c(STATUS_ACTIVE, "vercel", None,
                  "Vercel scanner access active. Bypass rule created and verified.")
    if ta_status == TrustedAccessStatus.FAILED.value:
        return _c(STATUS_FAILED, "vercel", "Retry Vercel scanner access setup",
                  "Vercel scanner bypass setup failed. Retry, or set it up manually.")
    if not has_rule:
        return _c(STATUS_PENDING_PERMISSIONS, "vercel", _REAUTH_ACTION,
                  "Vercel connected but the scanner bypass rule isn't in place yet. "
                  "Re-authorize Vercel with firewall write, then re-validate.")
    return _c(STATUS_PENDING_RULE_SETUP, "vercel", "Set up Vercel scanner access",
              "Vercel connected. Setting up the scanner bypass rule.")
