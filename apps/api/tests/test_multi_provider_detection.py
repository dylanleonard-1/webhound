"""Phase-2 Platform Access — multi-provider blocker detection.
Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

from apps.api.services.scanner_block_detection import (
    BLOCKER_BOTH,
    BLOCKER_CLOUDFLARE,
    BLOCKER_NONE,
    BLOCKER_VERCEL,
    classify_scan_blocker,
    detect_blocking_provider,
)


# --- legacy behavior preserved ---


def test_legacy_cloudflare_unchanged():
    res = classify_scan_blocker({"challenge_detected": True, "challenge_provider": "cloudflare"})
    assert res["blocker"] == BLOCKER_CLOUDFLARE and res["diagnosis"] == "cloudflare"


def test_legacy_vercel_with_cf_in_front_is_both():
    res = classify_scan_blocker(
        {"challenge_detected": True, "challenge_provider": "vercel"},
        cloudflare_connected=True)
    assert res["blocker"] == BLOCKER_BOTH and res["active_blocker_provider"] == "vercel"


def test_legacy_no_challenge():
    assert classify_scan_blocker({"challenge_detected": False})["blocker"] == BLOCKER_NONE


# --- new multi-provider attribution ---


def test_detect_cloudflare_keeps_legacy_and_adds_provider():
    res = detect_blocking_provider(
        {"challenge_detected": True, "challenge_provider": "cloudflare", "confidence": 90})
    assert res["provider"] == "cloudflare"
    assert res["automation_capable"] is True
    assert res["allowlist_method"] == "api"
    assert res["challenge_detected"] is True and res["access_required"] is True
    assert res["blocker"] == BLOCKER_CLOUDFLARE  # legacy preserved


def test_detect_vercel_manual():
    res = detect_blocking_provider(
        {"challenge_detected": True, "challenge_provider": "vercel"})
    assert res["provider"] == "vercel"
    assert res["automation_capable"] is False
    assert res["allowlist_method"] == "manual"


def test_detect_akamai_from_scan_provider():
    res = detect_blocking_provider(
        {"challenge_detected": True, "challenge_provider": "akamai"})
    assert res["provider"] == "akamai"
    assert res["access_required"] is True
    # legacy classifier can't attribute akamai → generic, but registry does.
    assert res["blocker"] == "generic_bot_challenge"


def test_detect_provider_from_headers_when_scan_silent():
    res = detect_blocking_provider(
        {"challenge_detected": True},
        headers={"x-sucuri-id": "12", "server": "Sucuri/Cloudproxy"})
    assert res["provider"] == "sucuri"
    assert res["access_required"] is True


def test_detect_no_challenge_no_access_required():
    res = detect_blocking_provider({"challenge_detected": False})
    assert res["challenge_detected"] is False
    assert res["access_required"] is False


def test_detect_unknown_challenge_still_access_required():
    res = detect_blocking_provider(
        {"challenge_detected": True, "challenge_provider": "netlify"})
    # netlify is future-expansion (not in the 10-provider registry yet) → no
    # attribution, but a challenge still means access is required.
    assert res["provider"] is None
    assert res["access_required"] is True
