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

# Match the scanner by its honest UA name (version-independent). Tightly scoped to
# the scanner identity only — NEVER a blanket allow for all visitors.
_EXPRESSION = f'(http.user_agent contains "{SCANNER_NAME}")'

# Phases the BYPASS rule skips, in priority order. http_request_sbfm = Super Bot
# Fight Mode (the bot-challenge phase on Pro/Business) — only bypassable via this
# phase skip, not the legacy "products" list. On FREE plans the bot product is Bot
# Fight Mode (no sbfm phase, unskippable): skipping a phase that doesn't run is
# harmless, but if Cloudflare rejects the phase for the plan we degrade to the
# fallback set (still skips managed WAF + rate-limit).
_BYPASS_PHASES = ["http_request_firewall_managed", "http_ratelimit", "http_request_sbfm"]
_BYPASS_PHASES_FALLBACK = ["http_request_firewall_managed", "http_ratelimit"]


class CloudflareRuleError(RuntimeError):
    """A Rulesets API call failed. Carries safe (non-secret) detail."""

    def __init__(self, *args, http_status: int | None = None, api_errors=None) -> None:
        super().__init__(*args)
        self.http_status = http_status
        self.api_errors = api_errors  # whitelisted Cloudflare error objects, never tokens


def _desired_rules(bypass_phases: list[str] | None = None) -> list[dict]:
    """The two WebHound scanner rules (both match ONLY the scanner UA):
      1) ALLOWLIST — skip the rest of the custom firewall ruleset + legacy security
         products (UA block, browser-integrity, hotlink, security level, rate limit).
      2) BYPASS    — skip the Managed WAF + rate-limiting + Super Bot Fight Mode
         phases for the scanner. NEVER disables WAF for other visitors.
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
                "phases": list(bypass_phases or _BYPASS_PHASES),
            },
        },
    ]


def _differs(found: dict, desired: dict) -> bool:
    """True if an existing rule's meaningful fields differ from desired (so it needs
    updating — e.g. an older rule missing the http_request_sbfm phase)."""
    return (found.get("action") != desired["action"]
            or (found.get("expression") or "") != desired["expression"]
            or (found.get("action_parameters") or {}) != desired["action_parameters"]
            or not found.get("enabled", True))


def _phase_unsupported(err: "CloudflareRuleError") -> bool:
    """Did the failure look like the plan doesn't support a skipped phase (e.g. SBFM
    on Free)? Then we degrade to the fallback phase set instead of erroring."""
    text = " ".join(str((e or {}).get("message") or "") for e in (err.api_errors or [])).lower()
    return any(k in text for k in ("sbfm", "super bot", "phase", "not supported",
                                   "not available", "invalid"))


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


async def _apply(access_token: str, zone_id: str, desired: list[dict]) -> dict:
    """Create/update both scanner rules in the zone's custom firewall ruleset.
    Returns {created, updated, existing (refs), ruleset_id, rule_ids (ref->id)}."""
    headers = {"Authorization": f"Bearer {access_token}",
               "Content-Type": "application/json", "Accept": "application/json"}
    created: list[str] = []
    updated: list[str] = []
    existing: list[str] = []
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
            res = (r.json() or {}).get("result") or {}
            ids = {ref: rule.get("id") for ref, rule in
                   ((REF_ALLOW, _find(res.get("rules") or [], REF_ALLOW) or {}),
                    (REF_BYPASS, _find(res.get("rules") or [], REF_BYPASS) or {}))}
            return {"created": [REF_ALLOW, REF_BYPASS], "updated": [], "existing": [],
                    "ruleset_id": res.get("id"), "rule_ids": ids}

        ruleset_id = entry.get("id")
        rules = entry.get("rules") or []
        rule_ids: dict[str, str | None] = {}
        for desired_rule, ref in ((desired[0], REF_ALLOW), (desired[1], REF_BYPASS)):
            found = _find(rules, ref)
            if found is None:
                # Append the missing rule.
                r = await client.post(
                    f"{_CF_API}/zones/{zone_id}/rulesets/{ruleset_id}/rules", json=desired_rule)
                if r.is_error:
                    raise CloudflareRuleError("rule append failed",
                                              http_status=r.status_code, api_errors=_safe_errors(r))
                created.append(ref)
                rule_ids[ref] = ((r.json() or {}).get("result") or {}).get("id")
            elif _differs(found, desired_rule):
                # Update the existing rule (e.g. add the sbfm phase to an old rule).
                r = await client.patch(
                    f"{_CF_API}/zones/{zone_id}/rulesets/{ruleset_id}/rules/{found['id']}",
                    json=desired_rule)
                if r.is_error:
                    raise CloudflareRuleError("rule update failed",
                                              http_status=r.status_code, api_errors=_safe_errors(r))
                updated.append(ref)
                rule_ids[ref] = found.get("id")
            else:
                existing.append(ref)
                rule_ids[ref] = found.get("id")
    return {"created": created, "updated": updated, "existing": existing,
            "ruleset_id": ruleset_id, "rule_ids": rule_ids}


async def ensure_scanner_rules(access_token: str, zone_id: str) -> dict:
    """Idempotently ensure both scanner rules exist + are current in the zone's custom
    firewall ruleset (creates missing, UPDATES drifted — e.g. to add the SBFM phase).
    Degrades to the fallback phase set if the plan rejects a skipped phase (Free/BFM).
    Safe to re-run; never duplicates (matches on the ref tag in the description)."""
    try:
        return await _apply(access_token, zone_id, _desired_rules())
    except CloudflareRuleError as exc:
        if _phase_unsupported(exc):
            # Plan doesn't support a skipped phase (e.g. SBFM on Free) — apply the
            # fallback set so the rest of the allowlist still works.
            result = await _apply(access_token, zone_id, _desired_rules(_BYPASS_PHASES_FALLBACK))
            result["degraded"] = True
            return result
        raise


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
