# WebHound — apps/api/services/cloudflare_rules.py
# Phase 3.4 scanner-access — create/verify/remove the Cloudflare firewall "skip"
# rules that allowlist the WebHound scanner by User-Agent, via the zone Rulesets
# API (http_request_firewall_custom phase). Uses the ELEVATED OAuth token
# (firewall-services.write). Idempotent + reversible: every WebHound rule carries
# a stable ref tag in its description so we never duplicate and can clean up.
#
# Security: the scanner has NO static egress IPs (dynamic cloud), so the match is
# the honest fixed UA (single source of truth = webhound.identity). NEVER log the
# access token.

from __future__ import annotations

import httpx
from webhound.identity import SCANNER_NAME  # "WebHoundScanner" — stable across versions

_CF_API = "https://api.cloudflare.com/client/v4"
_PHASE = "http_request_firewall_custom"

# Stable refs embedded in each rule's description — our idempotency + cleanup key.
REF_ALLOW = "webhound:scanner-access:allow"
REF_BYPASS = "webhound:scanner-access:bypass"

# Match the scanner by its honest UA name (version-independent).
_EXPRESSION = f'(http.user_agent contains "{SCANNER_NAME}")'


class CloudflareRuleError(RuntimeError):
    """A Rulesets API call failed. Carries safe (non-secret) detail."""

    def __init__(self, *args, http_status: int | None = None, api_errors=None) -> None:
        super().__init__(*args)
        self.http_status = http_status
        self.api_errors = api_errors  # whitelisted Cloudflare error objects, never tokens


def _desired_rules() -> list[dict]:
    """The two WebHound scanner rules (both match the scanner UA):
      1) ALLOWLIST — skip the rest of the custom firewall ruleset + legacy security
         products (UA block, browser-integrity, hotlink, security level, rate limit).
      2) BYPASS    — skip the Managed WAF + rate-limiting phases for the scanner.
    Each description ends with its ref tag so we can find/verify/remove it."""
    return [
        {
            "action": "skip",
            "expression": _EXPRESSION,
            "description": f"WebHound scanner allowlist [{REF_ALLOW}]",
            "enabled": True,
            "action_parameters": {
                "ruleset": "current",
                "products": ["uaBlock", "bic", "hot", "securityLevel", "rateLimit", "zoneLockdown"],
            },
        },
        {
            "action": "skip",
            "expression": _EXPRESSION,
            "description": f"WebHound scanner bypass managed [{REF_BYPASS}]",
            "enabled": True,
            "action_parameters": {
                "phases": ["http_request_firewall_managed", "http_ratelimit"],
            },
        },
    ]


def _safe_errors(resp: httpx.Response) -> list:
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        return []
    errs = body.get("errors") if isinstance(body, dict) else None
    # Whitelist code+message only — never echo the request/token.
    return [{"code": e.get("code"), "message": e.get("message")}
            for e in (errs or []) if isinstance(e, dict)]


async def _get_entrypoint(client: httpx.AsyncClient, zone_id: str) -> dict | None:
    """Return the custom-firewall entrypoint ruleset ({id, rules}) or None if the
    zone has no custom ruleset yet (404)."""
    r = await client.get(f"{_CF_API}/zones/{zone_id}/rulesets/phases/{_PHASE}/entrypoint")
    if r.status_code == 404:
        return None
    if r.is_error:
        raise CloudflareRuleError("entrypoint read failed",
                                  http_status=r.status_code, api_errors=_safe_errors(r))
    return (r.json() or {}).get("result") or {}


def _find(rules: list[dict], ref: str) -> dict | None:
    for rule in rules or []:
        if ref in (rule.get("description") or ""):
            return rule
    return None


async def ensure_scanner_rules(access_token: str, zone_id: str) -> dict:
    """Idempotently ensure both scanner rules exist in the zone's custom firewall
    ruleset. Returns {"created": [...refs], "existing": [...refs], "ruleset_id": id}.
    Safe to re-run — never duplicates (matches on the ref tag in the description)."""
    headers = {"Authorization": f"Bearer {access_token}",
               "Content-Type": "application/json", "Accept": "application/json"}
    created: list[str] = []
    existing: list[str] = []
    desired = _desired_rules()
    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        entry = await _get_entrypoint(client, zone_id)

        if entry is None:
            # No custom ruleset yet — create the entrypoint with both rules at once.
            r = await client.put(
                f"{_CF_API}/zones/{zone_id}/rulesets/phases/{_PHASE}/entrypoint",
                json={"rules": desired})
            if r.is_error:
                raise CloudflareRuleError("ruleset create failed",
                                          http_status=r.status_code, api_errors=_safe_errors(r))
            ruleset_id = ((r.json() or {}).get("result") or {}).get("id")
            return {"created": [REF_ALLOW, REF_BYPASS], "existing": [], "ruleset_id": ruleset_id}

        ruleset_id = entry.get("id")
        rules = entry.get("rules") or []
        for desired_rule, ref in ((desired[0], REF_ALLOW), (desired[1], REF_BYPASS)):
            if _find(rules, ref) is not None:
                existing.append(ref)
                continue
            # Append the missing rule to the existing ruleset.
            r = await client.post(
                f"{_CF_API}/zones/{zone_id}/rulesets/{ruleset_id}/rules", json=desired_rule)
            if r.is_error:
                raise CloudflareRuleError("rule append failed",
                                          http_status=r.status_code, api_errors=_safe_errors(r))
            created.append(ref)
    return {"created": created, "existing": existing, "ruleset_id": ruleset_id}


async def verify_scanner_rules(access_token: str, zone_id: str) -> dict:
    """Read the ruleset back and report which WebHound rules are present + enabled.
    Returns {"allow": bool, "bypass": bool, "verified": bool}."""
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        entry = await _get_entrypoint(client, zone_id)
    rules = (entry or {}).get("rules") or []
    allow = _find(rules, REF_ALLOW)
    bypass = _find(rules, REF_BYPASS)
    allow_ok = bool(allow and allow.get("enabled", True))
    bypass_ok = bool(bypass and bypass.get("enabled", True))
    return {"allow": allow_ok, "bypass": bypass_ok, "verified": allow_ok and bypass_ok}


async def remove_scanner_rules(access_token: str, zone_id: str) -> dict:
    """Delete every WebHound scanner rule from the zone (clean disconnect). Returns
    {"removed": [...refs]}. Idempotent — a missing rule is simply not counted."""
    headers = {"Authorization": f"Bearer {access_token}",
               "Content-Type": "application/json", "Accept": "application/json"}
    removed: list[str] = []
    async with httpx.AsyncClient(timeout=20, headers=headers) as client:
        entry = await _get_entrypoint(client, zone_id)
        if not entry:
            return {"removed": removed}
        ruleset_id = entry.get("id")
        rules = entry.get("rules") or []
        for ref in (REF_ALLOW, REF_BYPASS):
            rule = _find(rules, ref)
            if rule is None or not rule.get("id"):
                continue
            r = await client.delete(
                f"{_CF_API}/zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule['id']}")
            if r.is_error:
                raise CloudflareRuleError("rule delete failed",
                                          http_status=r.status_code, api_errors=_safe_errors(r))
            removed.append(ref)
    return {"removed": removed}
