"""Phase 3.4 — least-privilege scope + permission detection (pure, no DB).
Run with --noconftest -p no:cacheprovider."""
from __future__ import annotations

from apps.api.services import cloudflare_scopes as sc


def test_rule_edit_permission_detected_from_write_scope():
    assert sc.has_rule_edit_permission(["zone.read", "firewall-services.write"]) is True
    assert sc.has_rule_edit_permission("zone.read zone-waf.write") is True


def test_read_only_token_lacks_rule_edit():
    # The read-only CONNECT token (zone.read only) cannot create rules.
    assert sc.has_rule_edit_permission(["zone.read"]) is False
    assert sc.has_rule_edit_permission([]) is False
    assert sc.has_rule_edit_permission(None) is False


def test_rule_read_permission():
    assert sc.has_rule_read_permission(["firewall-services.read"]) is True
    assert sc.has_rule_read_permission(["zone.read"]) is True


def test_least_privilege_no_forbidden_scopes_in_core_set():
    core = ["zone.read", "firewall-services.read", "firewall-services.write",
            "zone-waf.read", "zone-waf.write"]
    assert sc.forbidden_scopes(core) == set()


def test_forbidden_admin_scopes_flagged():
    bad = ["zone.read", "dns_records.write", "workers-scripts.write", "account.write",
           "billing.read", "email-routing.write", "load-balancers.write"]
    flagged = sc.forbidden_scopes(bad)
    assert "dns_records.write" in flagged
    assert "workers-scripts.write" in flagged
    assert "account.write" in flagged
    assert "billing.read" in flagged
    assert "email-routing.write" in flagged
    assert "load-balancers.write" in flagged
    assert "zone.read" not in flagged
