"""Phase-2 Platform Access — wizard state machine + view builder + remediation.
Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

from apps.api.services.platform_access import (
    STATE_ACCESS_REQUIRED,
    STATE_COMPLETE,
    STATE_CONFIGURING,
    STATE_DETECTED,
    STATE_FAILED,
    STATE_NOT_REQUIRED,
    STATE_SUPPORT_REQUIRED,
    STATE_VERIFICATION_RUNNING,
    STATE_VERIFIED,
    WIZARD_STATES,
    build_platform_access_view,
    compute_state,
)

IPS = ["162.220.234.240", "152.55.180.240", "152.55.180.241"]


def test_nine_wizard_states():
    assert len(WIZARD_STATES) == 9


# --- state machine (every state reachable) ---


def test_state_not_required():
    assert compute_state(challenge_detected=False, provider=None,
                         trusted_status=None) == STATE_NOT_REQUIRED


def test_state_detected_provider_not_blocking():
    assert compute_state(challenge_detected=False, provider="cloudflare",
                         trusted_status=None) == STATE_DETECTED


def test_state_access_required():
    assert compute_state(challenge_detected=True, provider="vercel",
                         trusted_status="pending") == STATE_ACCESS_REQUIRED


def test_state_configuring():
    assert compute_state(challenge_detected=True, provider="cloudflare",
                         trusted_status="pending", configuring=True) == STATE_CONFIGURING


def test_state_verification_running():
    assert compute_state(challenge_detected=True, provider="vercel",
                         trusted_status="pending", verifying=True) == STATE_VERIFICATION_RUNNING


def test_state_verified():
    assert compute_state(challenge_detected=False, provider="cloudflare",
                         trusted_status="pending", verification_result="success") == STATE_VERIFIED


def test_state_complete_when_active():
    assert compute_state(challenge_detected=False, provider="cloudflare",
                         trusted_status="active") == STATE_COMPLETE


def test_state_failed():
    assert compute_state(challenge_detected=True, provider="vercel",
                         trusted_status="failed") == STATE_FAILED
    assert compute_state(challenge_detected=True, provider="vercel",
                         trusted_status="pending", verification_result="failed") == STATE_FAILED


def test_state_support_required_wins():
    assert compute_state(challenge_detected=True, provider="akamai",
                         trusted_status="failed", support_required=True) == STATE_SUPPORT_REQUIRED


# --- view builder (registry-driven remediation, dynamic IPs) ---


def _detection(provider="vercel", challenge=True, automation=False):
    return {
        "provider": provider, "name": provider.title(),
        "challenge_detected": challenge, "access_required": challenge,
        "automation_capable": automation, "allowlist_method":
            "api" if automation else "manual", "confidence": 85,
    }


def test_view_access_required_with_remediation():
    view = build_platform_access_view(
        detection=_detection("vercel"), trusted_status="pending", scanner_ips=IPS)
    assert view["state"] == STATE_ACCESS_REQUIRED
    assert view["provider"] == "vercel"
    assert view["can_automate"] is False
    assert view["scanner_ips"] == IPS
    rem = view["remediation"]
    assert rem["provider"] == "vercel"
    assert rem["copy_all"] == ", ".join(IPS)
    # exactly one copyable step carries the IPs
    assert sum(1 for s in rem["steps"] if s["copyable"]) == 1


def test_view_cloudflare_can_automate():
    view = build_platform_access_view(
        detection=_detection("cloudflare", automation=True),
        trusted_status="pending", scanner_ips=IPS)
    assert view["can_automate"] is True
    assert view["allowlist_method"] == "api"


def test_view_not_required_no_remediation():
    view = build_platform_access_view(
        detection={"provider": None, "challenge_detected": False},
        trusted_status=None, scanner_ips=IPS)
    assert view["state"] == STATE_NOT_REQUIRED
    assert view["remediation"] is None


def test_vercel_service_returns_structured_remediation():
    # The Vercel guided path now returns a registry remediation payload.
    from apps.api.services.provider_access_registry import render_remediation
    rem = render_remediation("vercel", IPS)
    assert rem and rem["provider"] == "vercel"
    assert any("System Bypass" in s["text"] for s in rem["steps"])
    assert rem["copy_all"] == ", ".join(IPS)
