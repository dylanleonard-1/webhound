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
from apps.api.services import cloudflare_telemetry as cf_telemetry

pytestmark = pytest.mark.anyio

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

    async def delete(self, url):
        self.calls.append(("DELETE", url))
        rid = url.rsplit("/", 1)[-1]
        self.state["rules"] = [r for r in self.state["rules"] if r.get("id") != rid]
        return _Resp(200, {"result": {"id": rid}})


async def test_rules_create_verify_remove_on_existing_ruleset(monkeypatch):
    api = _FakeRulesAPI(entry_exists=True)
    monkeypatch.setattr(cf_rules.httpx, "AsyncClient", api)

    created = await cf_rules.ensure_scanner_rules("tok", "zone1")
    assert set(created["created"]) == {cf_rules.REF_ALLOW, cf_rules.REF_BYPASS}
    assert created["existing"] == []
    assert sum(1 for m, _ in api.calls if m == "POST") == 2  # appended both

    verify = await cf_rules.verify_scanner_rules("tok", "zone1")
    assert verify == {"allow": True, "bypass": True, "verified": True}

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
