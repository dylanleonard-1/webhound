"""Phase 3.4 — Cloudflare scanner-access status derivation (pure, no DB).
Run with --noconftest -p no:cacheprovider."""
from __future__ import annotations

from apps.api.services import cloudflare_scanner_state as st
from apps.api.services import scanner_block_detection as det

VERCEL = det.classify_scan_blocker(
    {"challenge_detected": True, "challenge_provider": "vercel",
     "evidence": ["vercel security checkpoint"]}, cloudflare_connected=True)  # -> both
CF = det.classify_scan_blocker(
    {"challenge_detected": True, "challenge_provider": "cloudflare",
     "evidence": ["cf-ray"]}, cloudflare_connected=True)
NONE = det.classify_scan_blocker(
    {"challenge_detected": False}, cloudflare_connected=True)


def test_vercel_blocker_does_not_fake_active():
    r = st.derive_status(VERCEL, cloudflare_connected=True, has_rule=True, rule_validated=True,
                         has_rule_edit_permission=True)
    assert r["status"] == st.STATUS_BLOCKED_BY_OTHER
    assert r["blocker"] == "vercel"
    assert "Vercel" in r["next_action"]
    assert "not blocking" in r["message"].lower()


def test_no_challenge_is_not_needed():
    r = st.derive_status(NONE, cloudflare_connected=True, has_rule=False, rule_validated=False,
                         has_rule_edit_permission=True)
    assert r["status"] == st.STATUS_NOT_NEEDED


def test_cf_blocker_missing_permission():
    r = st.derive_status(CF, cloudflare_connected=True, has_rule=False, rule_validated=False,
                         has_rule_edit_permission=False)
    assert r["status"] == st.STATUS_PENDING_PERMISSIONS
    assert "Re-authorize" in r["next_action"]


def test_cf_blocker_needs_rule_setup():
    r = st.derive_status(CF, cloudflare_connected=True, has_rule=False, rule_validated=False,
                         has_rule_edit_permission=True)
    assert r["status"] == st.STATUS_PENDING_RULE_SETUP
    assert "Cloudflare" in r["next_action"]


def test_cf_blocker_rule_created_and_validated_is_active():
    r = st.derive_status(CF, cloudflare_connected=True, has_rule=True, rule_validated=True,
                         has_rule_edit_permission=True)
    assert r["status"] == st.STATUS_ACTIVE


def test_cf_rule_created_but_not_validated_stays_pending():
    r = st.derive_status(CF, cloudflare_connected=True, has_rule=True, rule_validated=False,
                         has_rule_edit_permission=True)
    assert r["status"] == st.STATUS_PENDING_RULE_SETUP   # not active until validated


def test_rule_setup_failed():
    r = st.derive_status(CF, cloudflare_connected=True, has_rule=False, rule_validated=False,
                         has_rule_edit_permission=True, rule_setup_failed=True)
    assert r["status"] == st.STATUS_FAILED


def test_not_connected():
    r = st.derive_status(NONE, cloudflare_connected=False, has_rule=False, rule_validated=False,
                         has_rule_edit_permission=False)
    assert r["status"] == st.STATUS_NOT_NEEDED
