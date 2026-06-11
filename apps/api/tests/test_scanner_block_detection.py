"""Phase 3.4 scanner-access — provider block classification (pure, no DB).
Run with --noconftest -p no:cacheprovider."""
from __future__ import annotations

from apps.api.services import scanner_block_detection as det

# Real-shaped Vercel challenge assessment (from the live webhoundsecurity.com scan).
VERCEL_YA = {
    "rendered_real_app": False, "challenge_detected": True, "challenge_provider": "vercel",
    "reason": "vercel bot/security challenge or block page was served instead of the site",
    "evidence": ["vercel: challenge endpoint '.well-known/vercel/security'",
                 "vercel: challenge marker 'vercel security checkpoint'",
                 "blocking HTTP status: [403]"],
}
CLOUDFLARE_YA = {
    "rendered_real_app": False, "challenge_detected": True, "challenge_provider": "cloudflare",
    "reason": "cloudflare managed challenge served",
    "evidence": ["cf-ray header present", "challenge-platform script", "blocking HTTP status: [403]"],
}
CLEAN_YA = {"rendered_real_app": True, "challenge_detected": False, "challenge_provider": None,
            "evidence": []}
GENERIC_YA = {"rendered_real_app": False, "challenge_detected": True, "challenge_provider": None,
              "reason": "a captcha/bot wall was served", "evidence": ["blocking HTTP status: [403]"]}


def test_vercel_challenge_no_cloudflare():
    r = det.classify_scan_blocker(VERCEL_YA, cloudflare_connected=False)
    assert r["blocker"] == det.BLOCKER_VERCEL
    assert r["diagnosis"] == "vercel"
    assert r["active_blocker_provider"] == "vercel"
    assert "Vercel" in r["next_action"]


def test_both_cloudflare_in_front_vercel_blocks():
    # The real webhoundsecurity.com case: CF connected/proxy + Vercel challenge.
    r = det.classify_scan_blocker(VERCEL_YA, cloudflare_connected=True)
    assert r["blocker"] == det.BLOCKER_BOTH
    assert r["diagnosis"] == "both"
    assert r["active_blocker_provider"] == "vercel"   # CF is NOT the blocker
    assert "Vercel" in r["next_action"]


def test_cloudflare_challenge():
    r = det.classify_scan_blocker(CLOUDFLARE_YA, cloudflare_connected=True)
    assert r["blocker"] == det.BLOCKER_CLOUDFLARE
    assert r["diagnosis"] == "cloudflare"
    assert r["active_blocker_provider"] == "cloudflare"
    assert "Cloudflare" in r["next_action"]


def test_no_challenge():
    r = det.classify_scan_blocker(CLEAN_YA, cloudflare_connected=True)
    assert r["blocker"] == det.BLOCKER_NONE
    assert r["active_blocker_provider"] is None
    assert r["next_action"] is None


def test_generic_unattributed_challenge():
    r = det.classify_scan_blocker(GENERIC_YA, cloudflare_connected=False)
    assert r["blocker"] == det.BLOCKER_GENERIC
    assert r["diagnosis"] == "unknown"


def test_cf_cache_status_alone_is_not_a_challenge_signal():
    # cf-cache-status present but no challenge + no challenge markers -> none.
    ya = {"challenge_detected": False, "challenge_provider": None,
          "evidence": ["cf-cache-status: HIT"]}
    r = det.classify_scan_blocker(ya, cloudflare_connected=True)
    assert r["blocker"] == det.BLOCKER_NONE


def test_none_input_is_safe():
    r = det.classify_scan_blocker(None, cloudflare_connected=False)
    assert r["blocker"] == det.BLOCKER_NONE
    assert r["diagnosis"] == "unknown"


def test_confidence_extracted_when_present():
    ya = {"challenge_detected": True, "challenge_provider": "vercel", "confidence": 97,
          "evidence": ["vercel security checkpoint"]}
    assert det.classify_scan_blocker(ya, cloudflare_connected=True)["confidence"] == 97


def test_confidence_none_when_absent():
    ya = {"challenge_detected": True, "challenge_provider": "vercel"}
    assert det.classify_scan_blocker(ya, cloudflare_connected=False)["confidence"] is None
