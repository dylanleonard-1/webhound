"""Phase-2 Platform Access — Cloudflare IP-allow rule: create/verify/update
(auto-update on IP change)/remove. Reuses the fake Rulesets API from
test_cloudflare_scanner_access. Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

import pytest

import apps.api.services.cloudflare_rules as cf_rules
from apps.api.tests.test_cloudflare_scanner_access import _FakeRulesAPI

pytestmark = pytest.mark.anyio

IPS = ["162.220.234.240", "152.55.180.240", "152.55.180.241"]


def test_ip_allow_expression_is_scoped_to_ips():
    expr = cf_rules._ip_allow_expression(IPS)
    assert expr == "(ip.src in {162.220.234.240 152.55.180.240 152.55.180.241})"
    # Never a blanket allow.
    assert "ip.src in {" in expr and "true" not in expr.lower()


def test_no_arg_desired_rules_unchanged_two_rules():
    rules = cf_rules._desired_rules()
    assert len(rules) == 2
    assert cf_rules.REF_ALLOW in rules[0]["description"]
    assert cf_rules.REF_BYPASS in rules[1]["description"]


def test_desired_rules_with_ips_adds_ip_allow():
    rules = cf_rules._desired_rules(scanner_ips=IPS)
    assert len(rules) == 3
    ip_rule = rules[2]
    assert cf_rules.REF_IP_ALLOW in ip_rule["description"]
    assert cf_rules.IP_ALLOW_DESCRIPTION in ip_rule["description"]
    assert ip_rule["expression"] == cf_rules._ip_allow_expression(IPS)
    assert ip_rule["action"] == "skip"


async def test_create_verify_remove_ip_allow(monkeypatch):
    api = _FakeRulesAPI(entry_exists=True)
    monkeypatch.setattr(cf_rules.httpx, "AsyncClient", api)

    created = await cf_rules.ensure_scanner_rules("tok", "zone1", scanner_ips=IPS)
    assert set(created["created"]) == {
        cf_rules.REF_ALLOW, cf_rules.REF_BYPASS, cf_rules.REF_IP_ALLOW}

    verify = await cf_rules.verify_scanner_rules("tok", "zone1", scanner_ips=IPS)
    assert verify["ip_allow"] is True and verify["verified"] is True

    # Remove cleans the IP-allow rule too.
    removed = await cf_rules.remove_scanner_rules("tok", "zone1")
    assert cf_rules.REF_IP_ALLOW in removed["removed"]
    after = await cf_rules.verify_scanner_rules("tok", "zone1", scanner_ips=IPS)
    assert after["ip_allow"] is False and after["verified"] is False


async def test_ip_allow_auto_updates_when_ip_list_changes(monkeypatch):
    api = _FakeRulesAPI(entry_exists=True)
    monkeypatch.setattr(cf_rules.httpx, "AsyncClient", api)

    await cf_rules.ensure_scanner_rules("tok", "zone1", scanner_ips=IPS)
    # New IP set → the expression differs → re-running PATCHes (auto-update).
    new_ips = IPS + ["203.0.113.7"]
    res = await cf_rules.ensure_scanner_rules("tok", "zone1", scanner_ips=new_ips)
    assert cf_rules.REF_IP_ALLOW in res["updated"]
    rule = next(r for r in api.state["rules"]
                if cf_rules.REF_IP_ALLOW in r["description"])
    assert rule["expression"] == cf_rules._ip_allow_expression(new_ips)
    # And verify against the new list passes.
    v = await cf_rules.verify_scanner_rules("tok", "zone1", scanner_ips=new_ips)
    assert v["verified"] is True


async def test_idempotent_no_change_when_ips_same(monkeypatch):
    api = _FakeRulesAPI(entry_exists=True)
    monkeypatch.setattr(cf_rules.httpx, "AsyncClient", api)
    await cf_rules.ensure_scanner_rules("tok", "zone1", scanner_ips=IPS)
    second = await cf_rules.ensure_scanner_rules("tok", "zone1", scanner_ips=IPS)
    assert second["created"] == [] and second["updated"] == []
    assert cf_rules.REF_IP_ALLOW in second["existing"]
