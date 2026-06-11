"""Phase 3.4 — layered scanner-access diagnosis assembly (pure, no DB).
Run with --noconftest -p no:cacheprovider."""
from __future__ import annotations

from apps.api.services import scanner_access_diagnosis as diag
from apps.api.services import scanner_block_detection as det

VERCEL = det.classify_scan_blocker(
    {"challenge_detected": True, "challenge_provider": "vercel",
     "evidence": ["vercel security checkpoint"]}, cloudflare_connected=True)   # diagnosis=both
CF = det.classify_scan_blocker(
    {"challenge_detected": True, "challenge_provider": "cloudflare",
     "evidence": ["cf-ray"]}, cloudflare_connected=True)
NONE = det.classify_scan_blocker({"challenge_detected": False}, cloudflare_connected=True)


def test_webhoundsecurity_expected_outcome():
    # The headline case: verified + CF connected, but Vercel is the real blocker.
    d = diag.assemble_diagnosis(
        VERCEL, verified=True, cloudflare_connected=True, has_rule=True,
        rule_validated=True, has_rule_edit_permission=True)
    assert d["verified"] is True
    assert d["cloudflare_connected"] is True
    assert d["cloudflare_scanner_access"] == "blocked_by_other_provider"   # NOT faked active
    assert d["blocker"] == "vercel"          # actionable provider
    assert d["diagnosis"] == "both"          # CF in front, Vercel final blocker
    assert d["next_action"] == "Set up Vercel scanner access"


def test_cf_blocker_missing_permission_view():
    d = diag.assemble_diagnosis(
        CF, verified=True, cloudflare_connected=True, has_rule=False,
        rule_validated=False, has_rule_edit_permission=False)
    assert d["cloudflare_scanner_access"] == "pending_permissions"
    assert "Re-authorize" in d["next_action"]


def test_cf_blocker_active_view():
    d = diag.assemble_diagnosis(
        CF, verified=True, cloudflare_connected=True, has_rule=True,
        rule_validated=True, has_rule_edit_permission=True,
        rule_meta={"rule_type": "skip", "created_by_webhound": True,
                   "last_validated_at": "2026-06-11T08:00:00+00:00"})
    assert d["cloudflare_scanner_access"] == "active"
    assert d["rule"]["rule_type"] == "skip"
    assert d["rule"]["last_validated_at"]


def test_not_needed_view():
    d = diag.assemble_diagnosis(
        NONE, verified=True, cloudflare_connected=True, has_rule=False,
        rule_validated=False, has_rule_edit_permission=True)
    assert d["cloudflare_scanner_access"] == "not_needed"
    assert "not blocking" in d["message"].lower()


def test_customer_safe_rule_omits_ids():
    # The customer-safe rule view must not leak rule/ruleset/zone ids.
    safe = diag._customer_safe_rule(
        {"rule_ids": {"a": "secret"}, "ruleset_id": "rs", "zone_id": "z",
         "rule_type": "skip", "created_by_webhound": True, "created_at": "t",
         "last_validated_at": "t2"})
    assert "rule_ids" not in safe and "ruleset_id" not in safe and "zone_id" not in safe
    assert safe["rule_type"] == "skip"
