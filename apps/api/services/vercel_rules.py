# WebHound — apps/api/services/vercel_rules.py
# Phase 4.3 scanner-access — create/verify/remove the Vercel WAF custom rule that
# allowlists the WebHound scanner by User-Agent, via the project Firewall config API
# (PATCH /v1/security/firewall/config). Uses the read-write:project integration
# token. Idempotent + reversible: the rule carries a stable WebHound ref tag in its
# name/description so we never duplicate and can clean up on disconnect.
#
# Security: the scanner has NO static egress IPs (dynamic cloud), so the match is the
# honest fixed UA (single source of truth = webhound.identity). The rule is tightly
# scoped to the scanner identity ONLY — never a blanket allow. NEVER log the token.
#
# Ref: vercel.com/docs/rest-api/security/update-firewall-configuration (rules.insert/
# update/remove + firewallEnabled) and .../vercel-waf/custom-rules (bypass action
# skips the managed bot/WAF protection for matching traffic only).

from __future__ import annotations

import httpx
from webhound.identity import SCANNER_NAME  # "WebHoundScanner" — stable across versions

_V_API = "https://api.vercel.com"
_CONFIG_PATH = "/v1/security/firewall/config"

# Stable ref embedded in the rule name/description — our idempotency + cleanup key.
REF = "webhound:scanner-access:bypass"
RULE_NAME = "WebHound Scanner Bypass"

# Match the scanner by its honest UA (op 'sub' = contains, case-insensitive on
# Vercel). Tightly scoped to the scanner identity — NEVER a blanket allow.
_CONDITION = {"type": "user_agent", "op": "sub", "value": SCANNER_NAME}
_BYPASS_ACTION = {"action": "bypass", "rateLimit": None, "redirect": None, "actionDuration": None}


class VercelRuleError(RuntimeError):
    """A Firewall config API call failed. Carries safe (non-secret) detail."""

    def __init__(self, *args, http_status: int | None = None, api_errors=None) -> None:
        super().__init__(*args)
        self.http_status = http_status
        self.api_errors = api_errors  # whitelisted Vercel error objects, never tokens


def _desired_rule() -> dict:
    """The single WebHound scanner bypass rule (matches ONLY the scanner UA): bypass
    the managed bot/WAF protection for the scanner. NEVER disables protection for
    other visitors. The description ends with the ref tag for find/verify/remove."""
    return {
        "name": RULE_NAME,
        "description": f"Allow the WebHound scanner (UA contains {SCANNER_NAME}) past bot protection [{REF}]",
        "active": True,
        "conditionGroup": [{"conditions": [dict(_CONDITION)]}],
        "action": {"mitigate": dict(_BYPASS_ACTION)},
    }


def _params(project_id: str, team_id: str | None) -> dict:
    p = {"projectId": project_id}
    if team_id:
        p["teamId"] = team_id
    return p


def _safe_errors(resp: httpx.Response) -> list:
    """Whitelist Vercel's {error:{code,message}} only — never echo request/token."""
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        return []
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        return [{"code": err.get("code"), "message": err.get("message")}]
    return []


def _find(rules: list[dict], ref: str = REF) -> dict | None:
    for r in rules or []:
        if ref in f"{r.get('name', '')} {r.get('description', '')}":
            return r
    return None


def _differs(found: dict, desired: dict) -> bool:
    """True if an existing rule's meaningful fields differ from desired (disabled,
    or a changed condition / action) so it needs updating."""
    if not found.get("active", True):
        return True
    if (found.get("conditionGroup") or []) != desired["conditionGroup"]:
        return True
    found_action = ((found.get("action") or {}).get("mitigate") or {}).get("action")
    return found_action != desired["action"]["mitigate"]["action"]


def attack_mode_blocking(config: dict | None) -> bool:
    """Best-effort detection of a project-wide challenge a custom bypass rule cannot
    override (Vercel Attack Challenge Mode). Conservative: only True on a clearly
    truthy flag — we never fabricate a non-bypassable block. The authoritative signal
    remains the scan-time block diagnosis."""
    if not config:
        return False
    if config.get("attackModeEnabled") or config.get("attackChallengeMode"):
        return True
    managed = config.get("managedRules")
    if isinstance(managed, dict):
        acm = managed.get("attackChallengeMode") or managed.get("attackMode")
        if isinstance(acm, dict):
            return bool(acm.get("active") or acm.get("enabled"))
        return bool(acm)
    return False


async def _get_config(client: httpx.AsyncClient, params: dict) -> dict | None:
    """Return the project's firewall config, or None if not provisioned yet (404
    'Seawall Config not found' — an authorized read of an absent config)."""
    r = await client.get(f"{_V_API}{_CONFIG_PATH}", params=params)
    if r.status_code == 404:
        return None
    if r.is_error:
        raise VercelRuleError("firewall config read failed",
                              http_status=r.status_code, api_errors=_safe_errors(r))
    return r.json() or {}


async def _patch(client: httpx.AsyncClient, params: dict, body: dict) -> dict:
    r = await client.patch(f"{_V_API}{_CONFIG_PATH}", params=params, json=body)
    if r.is_error:
        raise VercelRuleError("firewall config patch failed",
                              http_status=r.status_code, api_errors=_safe_errors(r))
    return (r.json() if r.content else {}) or {}


async def ensure_bypass_rule(access_token: str, project_id: str, team_id: str | None = None) -> dict:
    """Idempotently ensure the scanner bypass rule exists + is active on the project's
    firewall config (creates missing, updates drifted). Provisions the firewall config
    first (firewallEnabled=true) when the project has none yet. Safe to re-run; never
    duplicates (matches on the ref tag). Returns {created, updated, existing,
    firewall_provisioned, attack_mode}."""
    headers = {"Authorization": f"Bearer {access_token}",
               "Content-Type": "application/json", "Accept": "application/json"}
    params = _params(project_id, team_id)
    desired = _desired_rule()
    provisioned = False
    async with httpx.AsyncClient(timeout=25, headers=headers) as client:
        config = await _get_config(client, params)
        if config is None:
            # No firewall config yet — enable it (provision), then re-read.
            await _patch(client, params, {"action": "firewallEnabled", "value": True})
            config = await _get_config(client, params) or {}
            provisioned = True
        attack_mode = attack_mode_blocking(config)
        rules = config.get("rules") or []
        found = _find(rules)
        if found is None:
            await _patch(client, params, {"action": "rules.insert", "value": desired})
            result = {"created": [REF], "updated": [], "existing": []}
        elif _differs(found, desired):
            await _patch(client, params,
                         {"action": "rules.update", "id": found.get("id"), "value": desired})
            result = {"created": [], "updated": [REF], "existing": []}
        else:
            result = {"created": [], "updated": [], "existing": [REF]}
    result["firewall_provisioned"] = provisioned
    result["attack_mode"] = attack_mode
    return result


async def verify_bypass_rule(access_token: str, project_id: str, team_id: str | None = None) -> dict:
    """Read the firewall config back and report whether the WebHound bypass rule is
    present + active + actually a bypass. Returns {"bypass", "verified", "attack_mode"}."""
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    params = _params(project_id, team_id)
    async with httpx.AsyncClient(timeout=25, headers=headers) as client:
        config = await _get_config(client, params)
    rules = (config or {}).get("rules") or []
    found = _find(rules)
    ok = bool(
        found and found.get("active", True)
        and ((found.get("action") or {}).get("mitigate") or {}).get("action") == "bypass"
    )
    return {"bypass": ok, "verified": ok, "attack_mode": attack_mode_blocking(config)}


async def remove_bypass_rule(access_token: str, project_id: str, team_id: str | None = None) -> dict:
    """Delete the WebHound scanner bypass rule from the project firewall (clean
    disconnect). Returns {"removed": [...refs]}. Idempotent — a missing rule/config is
    simply not counted."""
    headers = {"Authorization": f"Bearer {access_token}",
               "Content-Type": "application/json", "Accept": "application/json"}
    params = _params(project_id, team_id)
    removed: list[str] = []
    async with httpx.AsyncClient(timeout=25, headers=headers) as client:
        config = await _get_config(client, params)
        if not config:
            return {"removed": removed}
        found = _find(config.get("rules") or [])
        if found and found.get("id"):
            await _patch(client, params, {"action": "rules.remove", "id": found["id"]})
            removed.append(REF)
    return {"removed": removed}
