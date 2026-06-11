"""Phase 4.3 scanner-access — Vercel honest-state derivation (pure).
Run with --noconftest -p no:cacheprovider. Never report 'active' unless Vercel is the
blocker AND our rule is verified; surface attack-mode + other-provider blocks honestly.
"""
from __future__ import annotations

from apps.api.services import scanner_block_detection as det
from apps.api.services import vercel_scanner_state as vs


def _d(blocker, provider=None, next_action=None):
    return {"blocker": blocker, "active_blocker_provider": provider, "next_action": next_action}


def test_not_connected():
    out = vs.derive_status(_d(det.BLOCKER_NONE), vercel_connected=False, has_rule=False,
                           rule_verified=False, has_firewall_write_permission=False)
    assert out["status"] == vs.STATUS_NOT_NEEDED


def test_active_only_when_rule_verified_and_vercel_blocks():
    out = vs.derive_status(_d(det.BLOCKER_VERCEL, provider="vercel"),
                           vercel_connected=True, has_rule=True, rule_verified=True,
                           has_firewall_write_permission=True)
    assert out["status"] == vs.STATUS_ACTIVE and out["blocker"] == "vercel"


def test_pending_permissions_when_no_write_scope():
    out = vs.derive_status(_d(det.BLOCKER_VERCEL, provider="vercel"),
                           vercel_connected=True, has_rule=False, rule_verified=False,
                           has_firewall_write_permission=False)
    assert out["status"] == vs.STATUS_PENDING_PERMISSIONS
    assert "Re-authorize" in out["next_action"]


def test_attack_mode_is_non_bypassable_never_active():
    out = vs.derive_status(_d(det.BLOCKER_VERCEL, provider="vercel"),
                           vercel_connected=True, has_rule=True, rule_verified=True,
                           has_firewall_write_permission=True, attack_mode=True)
    assert out["status"] == vs.STATUS_BLOCKED_NON_BYPASSABLE
    assert "Attack Challenge Mode" in out["message"]


def test_blocked_by_other_provider_not_faked_active():
    out = vs.derive_status(_d(det.BLOCKER_CLOUDFLARE, provider="cloudflare"),
                           vercel_connected=True, has_rule=True, rule_verified=True,
                           has_firewall_write_permission=True)
    assert out["status"] == vs.STATUS_BLOCKED_BY_OTHER and out["blocker"] == "cloudflare"


def test_not_needed_when_no_challenge():
    out = vs.derive_status(_d(det.BLOCKER_NONE), vercel_connected=True, has_rule=False,
                           rule_verified=False, has_firewall_write_permission=True)
    assert out["status"] == vs.STATUS_NOT_NEEDED


def test_failed_state():
    out = vs.derive_status(_d(det.BLOCKER_VERCEL, provider="vercel"),
                           vercel_connected=True, has_rule=False, rule_verified=False,
                           has_firewall_write_permission=True, rule_setup_failed=True)
    assert out["status"] == vs.STATUS_FAILED
