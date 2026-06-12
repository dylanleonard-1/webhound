"""Phase 3.4 scanner-access — scope least-privilege, firewall skip-rule
create/verify/remove (idempotent + reversible), and telemetry parsing.

Self-contained (no DB / conftest): the Cloudflare HTTP layer is mocked, and the
scope check monkeypatches settings. Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from apps.api.services import cloudflare as cf
from apps.api.services import cloudflare_rules as cf_rules
from apps.api.services import cloudflare_scanner_access as cf_scanner
from apps.api.services import cloudflare_telemetry as cf_telemetry

pytestmark = pytest.mark.anyio


_COMBINED_SCOPES = ("zone.read firewall-services.read firewall-services.write "
                    "zone-waf.read zone-waf.write")


def test_single_connect_requests_combined_scopes(monkeypatch):
    # ONE button: the main Connect Cloudflare authorize now requests the combined
    # least-privilege set (incl. firewall WRITE) so one consent does verify + rules.
    monkeypatch.setattr(cf, "get_settings", lambda: SimpleNamespace(
        cloudflare_client_id="cid", cloudflare_client_secret="s",
        api_base_url="https://api.webhoundsecurity.com",
        cloudflare_scanner_oauth_scopes=_COMBINED_SCOPES))
    url = cf.build_authorize_url("st")
    assert "firewall-services.write" in url   # write requested up front (one consent)
    assert "zone.read" in url
    assert "account" not in url.split("scope=", 1)[1].split("&", 1)[0]  # still least-privilege


async def test_apply_scanner_rules_no_zone():
    res = await cf_scanner.apply_scanner_rules(
        db=None, website=SimpleNamespace(id="w", hostname="x"), access_token="t",
        refresh_token=None, scope="firewall-services.write", zone_id=None,
        user_id=None, org_id=None)
    assert res == {"applied": False, "reason": "no_zone"}


async def test_apply_scanner_rules_skips_when_no_write_scope(monkeypatch):
    # Read-only connect token (zone.read) -> NO rule created -> pending_permissions.
    calls = {"ensure": 0}
    monkeypatch.setattr(cf_scanner.cf, "_audit", lambda *a, **k: None)
    async def _ensure(*a, **k):
        calls["ensure"] += 1
        return {}
    monkeypatch.setattr(cf_scanner.cf_rules, "ensure_scanner_rules", _ensure)
    res = await cf_scanner.apply_scanner_rules(
        db=None, website=SimpleNamespace(id="w", hostname="x"), access_token="t",
        refresh_token=None, scope="zone.read", zone_id="z1", user_id=None, org_id=None)
    assert res == {"applied": False, "reason": "no_permission"}
    assert calls["ensure"] == 0   # never created a rule without write scope

# The committed default scanner scope set.
_SCANNER_SCOPES = (
    "zone.read firewall-services.read firewall-services.write "
    "zone-waf.read zone-waf.write zone-security-center-insights.read "
    "page-shield.read trust-and-safety.read analytics.read"
)
# Scopes that must NEVER be requested (the user's forbidden list).
_FORBIDDEN = [
    "dns.edit", "dns_records", "dns-records.write", "workers", "workers-scripts.write",
    "billing", "account-billing", "account.write", "email", "email-routing", "zone.write",
]


def test_scanner_scope_request_is_least_privilege(monkeypatch):
    monkeypatch.setattr(cf, "get_settings", lambda: SimpleNamespace(
        cloudflare_client_id="cid", cloudflare_client_secret="sec",
        api_base_url="https://api.webhoundsecurity.com",
        cloudflare_scanner_oauth_scopes=_SCANNER_SCOPES))
    url = cf.build_scanner_access_authorize_url("st")
    # Requested scope param (URL-encoded space = +/%20). Check the raw scope list.
    scope_param = url.split("scope=", 1)[1].split("&", 1)[0]
    for needed in ("zone.read", "firewall-services.write", "zone-waf.write",
                   "page-shield.read", "zone-security-center-insights.read",
                   "trust-and-safety.read", "analytics.read"):
        assert needed in scope_param, f"missing required scope {needed}"
    # Forbidden admin/DNS/workers/billing/email scopes must be ABSENT.
    for bad in _FORBIDDEN:
        assert bad not in scope_param, f"forbidden scope present: {bad}"


# ── Fake Cloudflare Rulesets API ──────────────────────────────────────────────

class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.is_error = status >= 400
    def json(self):
        return self._payload


class _FakeRulesAPI:
    """Stateful fake of the zone custom-firewall entrypoint ruleset."""
    def __init__(self, *, entry_exists=True):
        self._next = 1
        self.calls = []
        self.state = {"id": "rs1", "rules": []} if entry_exists else None

    def __call__(self, *a, **k):  # used as httpx.AsyncClient(...)
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        self.calls.append(("GET", url))
        if self.state is None:
            return _Resp(404, {"success": False, "errors": [{"code": 1, "message": "no ruleset"}]})
        return _Resp(200, {"result": self.state})

    async def put(self, url, json=None):
        self.calls.append(("PUT", url))
        rules = []
        for r in (json or {}).get("rules", []):
            rules.append({**r, "id": f"r{self._next}"})
            self._next += 1
        self.state = {"id": "rs1", "rules": rules}
        return _Resp(200, {"result": self.state})

    async def post(self, url, json=None):
        self.calls.append(("POST", url))
        rule = {**(json or {}), "id": f"r{self._next}"}
        self._next += 1
        self.state["rules"].append(rule)
        return _Resp(200, {"result": rule})

    async def patch(self, url, json=None):
        self.calls.append(("PATCH", url))
        rid = url.rsplit("/", 1)[-1]
        for i, r in enumerate(self.state["rules"]):
            if r.get("id") == rid:
                self.state["rules"][i] = {**(json or {}), "id": rid}
        return _Resp(200, {"result": {"id": rid}})

    async def delete(self, url):
        self.calls.append(("DELETE", url))
        rid = url.rsplit("/", 1)[-1]
        self.state["rules"] = [r for r in self.state["rules"] if r.get("id") != rid]
        return _Resp(200, {"result": {"id": rid}})


class _FakeFreePlanAPI(_FakeRulesAPI):
    """Free plan: rejects any rule carrying the http_request_sbfm skip phase (SBFM
    doesn't exist) — forces the graceful fallback path."""
    def _rejects(self, json):
        phases = ((json or {}).get("action_parameters") or {}).get("phases") or []
        return "http_request_sbfm" in phases

    async def put(self, url, json=None):
        for r in (json or {}).get("rules", []):
            if self._rejects(r):
                return _Resp(400, {"success": False,
                                   "errors": [{"code": 1, "message": "phase http_request_sbfm not supported on plan"}]})
        return await super().put(url, json=json)

    async def post(self, url, json=None):
        if self._rejects(json):
            return _Resp(400, {"success": False,
                               "errors": [{"code": 1, "message": "phase http_request_sbfm not supported"}]})
        return await super().post(url, json=json)


async def test_rules_create_verify_remove_on_existing_ruleset(monkeypatch):
    api = _FakeRulesAPI(entry_exists=True)
    monkeypatch.setattr(cf_rules.httpx, "AsyncClient", api)

    created = await cf_rules.ensure_scanner_rules("tok", "zone1")
    assert set(created["created"]) == {cf_rules.REF_ALLOW, cf_rules.REF_BYPASS}
    assert created["existing"] == []
    assert sum(1 for m, _ in api.calls if m == "POST") == 2  # appended both

    verify = await cf_rules.verify_scanner_rules("tok", "zone1")
    assert verify == {"allow": True, "bypass": True, "ip_allow": False, "verified": True}

    removed = await cf_rules.remove_scanner_rules("tok", "zone1")
    assert set(removed["removed"]) == {cf_rules.REF_ALLOW, cf_rules.REF_BYPASS}
    after = await cf_rules.verify_scanner_rules("tok", "zone1")
    assert after["verified"] is False


async def test_rules_create_when_no_ruleset_uses_put(monkeypatch):
    api = _FakeRulesAPI(entry_exists=False)
    monkeypatch.setattr(cf_rules.httpx, "AsyncClient", api)
    created = await cf_rules.ensure_scanner_rules("tok", "zone1")
    assert set(created["created"]) == {cf_rules.REF_ALLOW, cf_rules.REF_BYPASS}
    assert any(m == "PUT" for m, _ in api.calls)        # created the ruleset
    assert not any(m == "POST" for m, _ in api.calls)   # not appended
    assert (await cf_rules.verify_scanner_rules("tok", "zone1"))["verified"] is True


async def test_rules_idempotent_no_duplicate_on_rerun(monkeypatch):
    api = _FakeRulesAPI(entry_exists=True)
    monkeypatch.setattr(cf_rules.httpx, "AsyncClient", api)
    await cf_rules.ensure_scanner_rules("tok", "zone1")
    second = await cf_rules.ensure_scanner_rules("tok", "zone1")
    assert second["created"] == []                       # nothing new
    assert set(second["existing"]) == {cf_rules.REF_ALLOW, cf_rules.REF_BYPASS}
    # exactly 2 rules remain (no duplicates)
    verify = await cf_rules.verify_scanner_rules("tok", "zone1")
    assert verify["verified"] is True
    assert len(api.state["rules"]) == 2


async def test_rule_match_targets_scanner_user_agent():
    # The rule expression must match the honest scanner UA name (single source of
    # truth), not IPs (there are none).
    assert 'http.user_agent contains "WebHoundScanner"' in cf_rules._EXPRESSION


def test_desired_bypass_rule_skips_sbfm_phase():
    # The bypass rule MUST skip Super Bot Fight Mode (the bot challenge layer).
    bypass = cf_rules._desired_rules()[1]
    assert "http_request_sbfm" in bypass["action_parameters"]["phases"]
    assert "http_request_firewall_managed" in bypass["action_parameters"]["phases"]


async def test_rules_update_existing_to_add_sbfm(monkeypatch):
    # An already-deployed bypass rule WITHOUT sbfm must be UPDATED (not duplicated).
    api = _FakeRulesAPI(entry_exists=True)
    api.state["rules"] = [
        {"id": "r-allow", "description": f"allow [{cf_rules.REF_ALLOW}]", "action": "skip",
         "expression": cf_rules._EXPRESSION, "enabled": True,
         "action_parameters": {"ruleset": "current",
                               "products": ["uaBlock", "bic", "hot", "securityLevel", "rateLimit", "zoneLockdown"]}},
        {"id": "r-bypass", "description": f"bypass [{cf_rules.REF_BYPASS}]", "action": "skip",
         "expression": cf_rules._EXPRESSION, "enabled": True,
         "action_parameters": {"phases": ["http_request_firewall_managed", "http_ratelimit"]}},  # no sbfm
    ]
    monkeypatch.setattr(cf_rules.httpx, "AsyncClient", api)
    res = await cf_rules.ensure_scanner_rules("tok", "zone1")
    assert cf_rules.REF_BYPASS in res["updated"]          # bypass got updated
    assert cf_rules.REF_ALLOW in res["existing"]          # allow unchanged
    assert any(m == "PATCH" for m, _ in api.calls)
    bypass = next(r for r in api.state["rules"] if cf_rules.REF_BYPASS in r["description"])
    assert "http_request_sbfm" in bypass["action_parameters"]["phases"]   # live rule now has it
    assert len(api.state["rules"]) == 2                    # no duplicate


async def test_rules_degrade_gracefully_on_free_plan(monkeypatch):
    # Free plan rejects sbfm -> ensure must fall back (no error) and still create the
    # rules with the fallback phase set.
    api = _FakeFreePlanAPI(entry_exists=True)
    monkeypatch.setattr(cf_rules.httpx, "AsyncClient", api)
    res = await cf_rules.ensure_scanner_rules("tok", "zone1")
    assert res.get("degraded") is True
    bypass = next(r for r in api.state["rules"] if cf_rules.REF_BYPASS in r["description"])
    assert "http_request_sbfm" not in bypass["action_parameters"]["phases"]
    assert "http_request_firewall_managed" in bypass["action_parameters"]["phases"]


async def test_ensure_returns_rule_ids(monkeypatch):
    api = _FakeRulesAPI(entry_exists=True)
    monkeypatch.setattr(cf_rules.httpx, "AsyncClient", api)
    res = await cf_rules.ensure_scanner_rules("tok", "zone1")
    assert set(res["rule_ids"].keys()) == {cf_rules.REF_ALLOW, cf_rules.REF_BYPASS}
    assert all(res["rule_ids"].values())   # captured ids for storage/rollback


# ── Telemetry parsing ─────────────────────────────────────────────────────────

class _TelemetryClient:
    def __init__(self, *a, **k):
        pass
    async def __aenter__(self):
        return self
    async def __aexit__(self, *a):
        return False
    async def get(self, url):
        if "page_shield" in url:
            return _Resp(200, {"result": [{"id": "s1"}], "result_info": {"total_count": 7}})
        if "security-center" in url:
            return _Resp(403, {"success": False, "errors": [{"code": 1, "message": "off"}]})
        return _Resp(404, {})


async def test_telemetry_parsing(monkeypatch):
    monkeypatch.setattr(cf_telemetry.httpx, "AsyncClient", lambda *a, **k: _TelemetryClient())
    out = await cf_telemetry.read_security_telemetry("tok", "zone1")
    # Page Shield available with the API's total_count; security center reports off.
    assert out["page_shield_scripts"] == {"available": True, "count": 7}
    assert out["security_center_insights"] == {"available": False, "count": None}
