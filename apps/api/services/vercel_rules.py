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
# IP-scoped System Bypass (DDoS Mitigations & System Bypasses). Matches by sourceIp +
# projectScope — NOT user-agent. Ref: vercel.com/docs/rest-api/reference/endpoints/
# security/create-system-bypass-rule (POST), list (GET), remove (DELETE).
_BYPASS_PATH = "/v1/security/firewall/bypass"

# Stable ref embedded in the rule name/description — our idempotency + cleanup key.
REF = "webhound:scanner-access:bypass"
RULE_NAME = "WebHound Scanner Bypass"
# Note tag stamped on the IP system-bypass entries for idempotency + cleanup.
IP_BYPASS_NOTE = "WebHound scanner egress [webhound:scanner-access]"
IP_BYPASS_REF = "webhound:scanner-access"

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


class VercelFirewallUnavailableError(VercelRuleError):
    """The project's firewall config can't be read OR created via this token: Vercel
    returns 404 'Seawall Config not found' for GET and PUT alike. The firewall must be
    initialized once in the Vercel dashboard (Project → Firewall), or the integration
    token lacks firewall access. Honest pending state — NOT a failure, NOT active."""


class VercelBypassForbiddenError(VercelRuleError):
    """The token is not permitted to manage IP System Bypass rules (Vercel returns
    403 'You don't have permission to create the ip blocking', or 404 'IP Blocking not
    found'). EMPIRICAL: the marketplace integration token's read-write:project does NOT
    grant firewall/ipBlocking write — that's gated to native integrations / user-level
    access. Honest -> customer guided manual setup; NEVER fake active."""


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


def _config_body(config: dict | None) -> dict:
    """Normalize the firewall config shape: GET returns the config at top level; PUT
    returns it wrapped under `active`. Always work against the inner config."""
    if isinstance(config, dict) and isinstance(config.get("active"), dict):
        return config["active"]
    return config or {}


def _rules_of(config: dict | None) -> list[dict]:
    return _config_body(config).get("rules") or []


def attack_mode_blocking(config: dict | None) -> bool:
    """Best-effort detection of a project-wide challenge a custom bypass rule cannot
    override (Vercel Attack Challenge Mode). Conservative: only True on a clearly
    truthy flag — we never fabricate a non-bypassable block. The authoritative signal
    remains the scan-time block diagnosis."""
    body = _config_body(config)
    if not body:
        return False
    if body.get("attackModeEnabled") or body.get("attackChallengeMode"):
        return True
    managed = body.get("managedRules")
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


async def _put(client: httpx.AsyncClient, params: dict, body: dict) -> dict:
    r = await client.put(f"{_V_API}{_CONFIG_PATH}", params=params, json=body)
    if r.is_error:
        raise VercelRuleError("firewall config create failed",
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
            # No firewall config exists yet for this project. PATCH actions (incl.
            # firewallEnabled) 404 with "Seawall Config not found" — only PUT can
            # CREATE one. Since none exists, a fresh create can't overwrite anyone
            # else's rules: PUT firewallEnabled=true with our single bypass rule.
            try:
                created_cfg = await _put(client, params, {"firewallEnabled": True, "rules": [desired]})
            except VercelRuleError as exc:
                # Observed on a Pro project whose firewall was never initialized: PUT
                # also 404s "Seawall Config not found". The config must be bootstrapped
                # in the dashboard (or the token lacks firewall access) — honest pending.
                if exc.http_status == 404:
                    raise VercelFirewallUnavailableError(
                        "firewall config not initialized", http_status=404,
                        api_errors=exc.api_errors) from exc
                raise
            return {"created": [REF], "updated": [], "existing": [],
                    "firewall_provisioned": True,
                    "attack_mode": attack_mode_blocking(created_cfg)}
        attack_mode = attack_mode_blocking(config)
        rules = _rules_of(config)
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
    found = _find(_rules_of(config))
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
        found = _find(_rules_of(config))
        if found and found.get("id"):
            await _patch(client, params, {"action": "rules.remove", "id": found["id"]})
            removed.append(REF)
    return {"removed": removed}


# ── IP-scoped System Bypass (DDoS Mitigations & System Bypasses) ───────────────
# Scoped ONLY to the WebHound scanner egress IP(s) + projectScope — never UA, never a
# broad/global bypass (we never send allSources). The marketplace integration token is
# currently FORBIDDEN here (403), so callers fall back to guided manual setup; these
# functions are correct + future-proof if a token ever has firewall write.

def _bypass_ip_of(entry: dict) -> str:
    """Extract the source IP from a bypass-list entry (Vercel uses 'Ip' or 'sourceIp')."""
    return str(entry.get("Ip") or entry.get("ip") or entry.get("sourceIp") or "").strip()


async def _bypass_request(client, method: str, params: dict, json=None) -> httpx.Response:
    r = await client.request(method, f"{_V_API}{_BYPASS_PATH}", params=params, json=json)
    if r.status_code in (401, 403):
        raise VercelBypassForbiddenError("ip system bypass forbidden",
                                         http_status=r.status_code, api_errors=_safe_errors(r))
    return r


def _bypass_list_from(resp: httpx.Response) -> list[dict]:
    if resp.status_code == 404:  # 'IP Blocking not found' — nothing configured yet
        return []
    if resp.is_error:
        raise VercelRuleError("bypass list failed", http_status=resp.status_code,
                              api_errors=_safe_errors(resp))
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001
        return []
    res = body.get("result") if isinstance(body, dict) else body
    return [e for e in (res or []) if isinstance(e, dict)]


async def ensure_ip_system_bypass(
    access_token: str, project_id: str, team_id: str | None, ips: list[str],
) -> dict:
    """Idempotently ensure a project-scoped System Bypass exists for EACH scanner egress
    IP. Never sends allSources/global. Raises VercelBypassForbiddenError if the token
    can't manage IP blocking (the marketplace integration case). Returns
    {"created": [...ips], "existing": [...ips]}."""
    headers = {"Authorization": f"Bearer {access_token}",
               "Content-Type": "application/json", "Accept": "application/json"}
    params = _params(project_id, team_id)
    created: list[str] = []
    existing: list[str] = []
    async with httpx.AsyncClient(timeout=25, headers=headers) as client:
        lst = _bypass_list_from(await _bypass_request(client, "GET", params))
        present = {_bypass_ip_of(e) for e in lst}
        for ip in ips:
            ip = (ip or "").strip()
            if not ip:
                continue
            if ip in present:
                existing.append(ip)
                continue
            # projectScope=true + sourceIp -> bypass this exact IP across the project's
            # domains. NEVER allSources (that would be a global bypass).
            await _bypass_request(client, "POST", params,
                                  json={"projectScope": True, "sourceIp": ip, "note": IP_BYPASS_NOTE})
            created.append(ip)
    return {"created": created, "existing": existing}


async def verify_ip_system_bypass(
    access_token: str, project_id: str, team_id: str | None, ips: list[str],
) -> dict:
    """Read the bypass list back and confirm every scanner IP is present. Returns
    {"present": [...], "missing": [...], "verified": bool}."""
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    params = _params(project_id, team_id)
    async with httpx.AsyncClient(timeout=25, headers=headers) as client:
        lst = _bypass_list_from(await _bypass_request(client, "GET", params))
    present_ips = {_bypass_ip_of(e) for e in lst}
    want = [(ip or "").strip() for ip in ips if (ip or "").strip()]
    present = [ip for ip in want if ip in present_ips]
    missing = [ip for ip in want if ip not in present_ips]
    return {"present": present, "missing": missing, "verified": bool(want) and not missing}


async def remove_ip_system_bypass(
    access_token: str, project_id: str, team_id: str | None, ips: list[str],
) -> dict:
    """Remove the WebHound scanner System Bypass entries (clean disconnect). Idempotent.
    Returns {"removed": [...ips]}."""
    headers = {"Authorization": f"Bearer {access_token}",
               "Content-Type": "application/json", "Accept": "application/json"}
    params = _params(project_id, team_id)
    want = {(ip or "").strip() for ip in ips if (ip or "").strip()}
    removed: list[str] = []
    async with httpx.AsyncClient(timeout=25, headers=headers) as client:
        lst = _bypass_list_from(await _bypass_request(client, "GET", params))
        for entry in lst:
            ip = _bypass_ip_of(entry)
            if ip not in want:
                continue
            bid = entry.get("Id") or entry.get("id")
            body = {"id": bid} if bid else {"sourceIp": ip, "projectScope": True}
            await _bypass_request(client, "DELETE", params, json=body)
            removed.append(ip)
    return {"removed": removed}
