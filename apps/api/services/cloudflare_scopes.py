# WebHound — apps/api/services/cloudflare_scopes.py
# Phase 3.4 scanner-access — least-privilege scope helpers + permission detection.
# The scanner-access OAuth requests only what's needed to create the allow rule and
# read it back (zone.read + firewall-services.read/.write + zone-waf.read/.write).
# This module answers: "does the granted token actually have rule-EDIT permission?"
# so the dashboard can ask the user to re-authorize when it doesn't.

from __future__ import annotations

# Write scopes that permit creating/updating the firewall skip rule (resolved from
# Cloudflare's /oauth/scopes catalog). Either grants rule-edit.
RULE_EDIT_SCOPES = ("firewall-services.write", "zone-waf.write")
# Read scopes that permit reading rulesets back (verification).
RULE_READ_SCOPES = ("firewall-services.read", "zone-waf.read", "zone.read")

# Scopes the scanner-access phase is ALLOWED to request — least privilege. Anything
# outside this set (DNS edit, Workers, Account edit, Billing, Email Routing, Load
# Balancers, etc.) must never appear in a scanner-access authorize request.
ALLOWED_SCANNER_SCOPES = frozenset({
    "zone.read",
    "firewall-services.read", "firewall-services.write",
    "zone-waf.read", "zone-waf.write",
    # telemetry reads (deferred but allowed if re-added):
    "zone-security-center-insights.read", "page-shield.read",
    "trust-and-safety.read", "analytics.read",
})


def _normalize(granted_scopes) -> set[str]:
    if isinstance(granted_scopes, str):
        granted_scopes = granted_scopes.split()
    return {s.strip() for s in (granted_scopes or []) if s and s.strip()}


def has_rule_edit_permission(granted_scopes) -> bool:
    """True if the granted scopes include a firewall/WAF WRITE scope (can create the
    allow rule). Accepts a list or a space-separated string."""
    return bool(_normalize(granted_scopes) & set(RULE_EDIT_SCOPES))


def has_rule_read_permission(granted_scopes) -> bool:
    return bool(_normalize(granted_scopes) & set(RULE_READ_SCOPES))


def forbidden_scopes(requested_scopes) -> set[str]:
    """Any requested scope NOT in the least-privilege allowlist (should be empty)."""
    return _normalize(requested_scopes) - ALLOWED_SCANNER_SCOPES
