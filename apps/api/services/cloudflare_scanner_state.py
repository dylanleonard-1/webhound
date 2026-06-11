# WebHound — apps/api/services/cloudflare_scanner_state.py
# Phase 3.4 scanner-access — derive the HONEST Cloudflare scanner-access status from
# the block diagnosis + rule/permission facts. Pure + testable. The cardinal rule:
# NEVER report `active` unless Cloudflare is actually the blocker AND our rule was
# created and validated. If Vercel (or another layer) is the real wall, say so.

from __future__ import annotations

from apps.api.services import scanner_block_detection as det

STATUS_NOT_NEEDED = "not_needed"                      # CF connected but not blocking
STATUS_PENDING_PERMISSIONS = "pending_permissions"    # CF may block but token lacks rule-edit
STATUS_PENDING_RULE_SETUP = "pending_rule_setup"      # CF may block; needs the allowlist rule
STATUS_ACTIVE = "active"                              # rule created AND validated
STATUS_BLOCKED_BY_OTHER = "blocked_by_other_provider"  # CF connected; another layer blocks
STATUS_FAILED = "failed"                              # rule setup attempted and failed

_REAUTH_ACTION = "Re-authorize Cloudflare with scanner-access permissions"


def derive_status(
    detection: dict, *, cloudflare_connected: bool, has_rule: bool,
    rule_validated: bool, has_rule_edit_permission: bool, rule_setup_failed: bool = False,
) -> dict:
    """Return {status, blocker, next_action, message}. `detection` is the result of
    scanner_block_detection.classify_scan_blocker."""
    blocker = detection.get("blocker")
    active_provider = detection.get("active_blocker_provider")

    if not cloudflare_connected:
        return _r(STATUS_NOT_NEEDED, None, None,
                  "Connect Cloudflare to manage scanner access.")

    if rule_setup_failed:
        return _r(STATUS_FAILED, "cloudflare", "Retry Cloudflare scanner access setup",
                  "Cloudflare scanner allowlist setup failed. Retry, or set it up manually.")

    # No challenge at all -> Cloudflare is not blocking the scanner.
    if blocker == det.BLOCKER_NONE:
        return _r(STATUS_NOT_NEEDED, None, None,
                  "Cloudflare connected. Cloudflare is not blocking the scanner.")

    # A different layer (Vercel/other) is the FINAL blocker — do NOT fake active.
    if active_provider and active_provider != "cloudflare":
        return _r(STATUS_BLOCKED_BY_OTHER, active_provider,
                  detection.get("next_action"),
                  f"Cloudflare connected. Cloudflare is not blocking the scanner. "
                  f"Current blocker: {active_provider.title()}.")

    # Cloudflare is (or may be) the blocker.
    if has_rule and rule_validated:
        return _r(STATUS_ACTIVE, "cloudflare", None,
                  "Cloudflare scanner access active. Allow rule created and validated.")
    if not has_rule_edit_permission:
        return _r(STATUS_PENDING_PERMISSIONS, "cloudflare", _REAUTH_ACTION,
                  "Cloudflare connected but missing Rulesets/WAF edit permission. "
                  + _REAUTH_ACTION + ".")
    return _r(STATUS_PENDING_RULE_SETUP, "cloudflare", "Set up Cloudflare scanner access",
              "Cloudflare connected. Cloudflare scanner allowlist required. Set up scanner access.")


def _r(status: str, blocker: str | None, next_action: str | None, message: str) -> dict:
    return {"status": status, "blocker": blocker, "next_action": next_action, "message": message}
