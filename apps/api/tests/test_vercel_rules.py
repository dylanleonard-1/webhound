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
