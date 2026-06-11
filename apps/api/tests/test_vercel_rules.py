"""Phase 4.3 scanner-access — Vercel WAF bypass-rule module (pure HTTP, mocked).
Run with --noconftest -p no:cacheprovider.

Covers: provision+create -> verify -> remove; UA-scoped + bypass action; idempotent
re-run; drift update (inactive rule); attack-mode (non-bypassable) detection; and
that the firewall config is provisioned (firewallEnabled) when absent.
"""
from __future__ import annotations

import pytest

from apps.api.services import vercel_rules as vr
from webhound.identity import SCANNER_NAME

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


class _Resp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.is_error = status >= 400
        self.content = b"{}" if payload is not None else b""

    def json(self):
        return self._payload


class _FakeFirewallAPI:
    """Stateful fake of one project's Vercel firewall config."""

    def __init__(self, *, exists=False, attack_mode=False, seed_rules=None):
        self._next = 1
        self.calls = []
        self.enabled = exists
        self.attack_mode = attack_mode
        self.config = None
        if exists:
            self.config = {"projectId": "prj", "firewallEnabled": True,
                           "rules": list(seed_rules or [])}
            if attack_mode:
                self.config["attackModeEnabled"] = True

    def __call__(self, *a, **k):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, params=None):
        self.calls.append(("GET", url, params))
        if self.config is None:
            return _Resp(404, {"error": {"code": "not_found", "message": "Seawall Config not found."}})
        return _Resp(200, self.config)

    async def put(self, url, params=None, json=None):
        # Create/overwrite the whole config (PUT). Assign ids to provided rules.
        self.calls.append(("PUT", "create", params))
        rules = []
        for r in (json or {}).get("rules", []):
            rules.append({**r, "id": f"rule_{self._next}"})
            self._next += 1
        self.config = {"projectId": "prj", "firewallEnabled": bool((json or {}).get("firewallEnabled")),
                       "rules": rules}
        if self.attack_mode:
            self.config["attackModeEnabled"] = True
        return _Resp(200, {"active": self.config})

    async def patch(self, url, params=None, json=None):
        action = (json or {}).get("action")
        self.calls.append(("PATCH", action, params))
        if action == "firewallEnabled":
            self.config = {"projectId": "prj", "firewallEnabled": bool(json.get("value")), "rules": []}
            if self.attack_mode:
                self.config["attackModeEnabled"] = True
            return _Resp(200, self.config)
        if self.config is None:
            return _Resp(404, {"error": {"code": "not_found", "message": "Seawall Config not found."}})
        if action == "rules.insert":
            rule = {**json["value"], "id": f"rule_{self._next}"}
            self._next += 1
            self.config["rules"].append(rule)
            return _Resp(200, {"id": rule["id"]})
        if action == "rules.update":
            for i, r in enumerate(self.config["rules"]):
                if r.get("id") == json.get("id"):
                    self.config["rules"][i] = {**json["value"], "id": json["id"]}
            return _Resp(200, {"id": json.get("id")})
        if action == "rules.remove":
            self.config["rules"] = [r for r in self.config["rules"] if r.get("id") != json.get("id")]
            return _Resp(200, {"id": json.get("id")})
        return _Resp(400, {"error": {"code": "bad_request", "message": "unknown action"}})


async def test_provision_create_verify_remove(monkeypatch):
    api = _FakeFirewallAPI(exists=False)  # no config yet -> must provision
    monkeypatch.setattr(vr.httpx, "AsyncClient", api)

    created = await vr.ensure_bypass_rule("tok", "prj", "team")
    assert created["created"] == [vr.REF]
    assert created["firewall_provisioned"] is True  # config created via PUT
    # No config existed -> must CREATE via PUT (PATCH can't create one).
    assert any(m == "PUT" for m, _a, _ in api.calls)

    verify = await vr.verify_bypass_rule("tok", "prj", "team")
    assert verify["bypass"] is True and verify["verified"] is True

    removed = await vr.remove_bypass_rule("tok", "prj", "team")
    assert removed["removed"] == [vr.REF]
    after = await vr.verify_bypass_rule("tok", "prj", "team")
    assert after["verified"] is False


async def test_rule_is_ua_scoped_bypass(monkeypatch):
    api = _FakeFirewallAPI(exists=True)
    monkeypatch.setattr(vr.httpx, "AsyncClient", api)
    await vr.ensure_bypass_rule("tok", "prj", "team")
    rule = api.config["rules"][0]
    cond = rule["conditionGroup"][0]["conditions"][0]
    assert cond == {"type": "user_agent", "op": "sub", "value": SCANNER_NAME}
    assert rule["action"]["mitigate"]["action"] == "bypass"
    assert rule["active"] is True
    # Scoped to the scanner only — never a blanket/global allow.
    assert SCANNER_NAME in rule["description"]


async def test_idempotent_no_duplicate(monkeypatch):
    api = _FakeFirewallAPI(exists=True)
    monkeypatch.setattr(vr.httpx, "AsyncClient", api)
    first = await vr.ensure_bypass_rule("tok", "prj")
    second = await vr.ensure_bypass_rule("tok", "prj")
    assert first["created"] == [vr.REF]
    assert second["existing"] == [vr.REF] and second["created"] == []
    assert len(api.config["rules"]) == 1  # exactly one — no duplicate


async def test_drift_update_reactivates(monkeypatch):
    # Seed a stale, DISABLED WebHound rule -> ensure must update (re-activate) it.
    stale = {"id": "rule_old", "name": vr.RULE_NAME,
             "description": f"old [{vr.REF}]", "active": False,
             "conditionGroup": [{"conditions": [{"type": "user_agent", "op": "sub", "value": SCANNER_NAME}]}],
             "action": {"mitigate": {"action": "bypass"}}}
    api = _FakeFirewallAPI(exists=True, seed_rules=[stale])
    monkeypatch.setattr(vr.httpx, "AsyncClient", api)
    res = await vr.ensure_bypass_rule("tok", "prj")
    assert res["updated"] == [vr.REF]
    assert api.config["rules"][0]["active"] is True


async def test_attack_mode_detected(monkeypatch):
    api = _FakeFirewallAPI(exists=True, attack_mode=True)
    monkeypatch.setattr(vr.httpx, "AsyncClient", api)
    res = await vr.ensure_bypass_rule("tok", "prj")
    assert res["attack_mode"] is True
    assert vr.attack_mode_blocking(api.config) is True


def test_attack_mode_blocking_conservative():
    assert vr.attack_mode_blocking(None) is False
    assert vr.attack_mode_blocking({"rules": []}) is False
    assert vr.attack_mode_blocking({"attackModeEnabled": True}) is True
    assert vr.attack_mode_blocking({"managedRules": {"attackChallengeMode": {"active": True}}}) is True


# ── IP-scoped System Bypass ────────────────────────────────────────────────────

class _FakeBypassAPI:
    """Stateful fake of the /v1/security/firewall/bypass endpoint."""

    def __init__(self, *, forbidden=False, exists404=False, seed=None):
        self.forbidden = forbidden
        self.exists404 = exists404  # GET returns 404 'IP Blocking not found'
        self.entries = list(seed or [])
        self._next = 1
        self.posts = []

    def __call__(self, *a, **k):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def request(self, method, url, params=None, json=None):
        if self.forbidden:
            return _Resp(403, {"error": {"code": "forbidden",
                                         "message": "You don't have permission to create the ip blocking",
                                         "resource": "ipBlocking"}})
        if method == "GET":
            if self.exists404 and not self.entries:
                return _Resp(404, {"error": {"code": "not_found", "message": "IP Blocking not found."}})
            return _Resp(200, {"result": list(self.entries)})
        if method == "POST":
            self.posts.append(json or {})
            entry = {"Id": f"byp_{self._next}", "Ip": json.get("sourceIp"),
                     "Note": json.get("note"), "IsProjectRule": bool(json.get("projectScope"))}
            self._next += 1
            self.entries.append(entry)
            return _Resp(200, {"ok": True, "result": [entry]})
        if method == "DELETE":
            bid = (json or {}).get("id")
            ip = (json or {}).get("sourceIp")
            self.entries = [e for e in self.entries
                            if e.get("Id") != bid and e.get("Ip") != ip]
            return _Resp(200, {"ok": True})
        return _Resp(400, {"error": {"code": "bad_request"}})


async def test_ip_bypass_create_verify_remove(monkeypatch):
    api = _FakeBypassAPI(exists404=True)
    monkeypatch.setattr(vr.httpx, "AsyncClient", api)
    ips = ["152.55.180.27"]

    created = await vr.ensure_ip_system_bypass("tok", "prj", "team", ips)
    assert created["created"] == ips and created["existing"] == []
    # SCOPED: exactly sourceIp + projectScope; NEVER allSources / global.
    assert api.posts == [{"projectScope": True, "sourceIp": "152.55.180.27", "note": vr.IP_BYPASS_NOTE}]
    assert all("allSources" not in p for p in api.posts)

    verify = await vr.verify_ip_system_bypass("tok", "prj", "team", ips)
    assert verify["verified"] is True and verify["present"] == ips and verify["missing"] == []

    removed = await vr.remove_ip_system_bypass("tok", "prj", "team", ips)
    assert removed["removed"] == ips
    after = await vr.verify_ip_system_bypass("tok", "prj", "team", ips)
    assert after["verified"] is False and after["missing"] == ips


async def test_ip_bypass_idempotent(monkeypatch):
    api = _FakeBypassAPI(seed=[{"Id": "byp_x", "Ip": "152.55.180.27", "Note": vr.IP_BYPASS_NOTE}])
    monkeypatch.setattr(vr.httpx, "AsyncClient", api)
    res = await vr.ensure_ip_system_bypass("tok", "prj", "team", ["152.55.180.27"])
    assert res["existing"] == ["152.55.180.27"] and res["created"] == []
    assert api.posts == []  # already present -> no duplicate


async def test_ip_bypass_forbidden_raises(monkeypatch):
    api = _FakeBypassAPI(forbidden=True)
    monkeypatch.setattr(vr.httpx, "AsyncClient", api)
    with pytest.raises(vr.VercelBypassForbiddenError):
        await vr.ensure_ip_system_bypass("tok", "prj", "team", ["152.55.180.27"])


async def test_ip_bypass_never_global(monkeypatch):
    # Multiple IPs -> each scoped to its own sourceIp; never a single global rule.
    api = _FakeBypassAPI(exists404=True)
    monkeypatch.setattr(vr.httpx, "AsyncClient", api)
    await vr.ensure_ip_system_bypass("tok", "prj", "team", ["1.2.3.4", "5.6.7.8"])
    assert {p["sourceIp"] for p in api.posts} == {"1.2.3.4", "5.6.7.8"}
    assert all(p.get("projectScope") is True and "allSources" not in p for p in api.posts)
