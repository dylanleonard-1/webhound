"""Phase-2 Platform Access — support escalation payload (safe context, no secrets).
Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

from apps.api.services.platform_access import build_support_payload

VIEW = {
    "state": "failed", "provider": "vercel", "provider_name": "Vercel",
    "challenge_detected": True, "access_required": True, "verification": "blocked",
    "allowlist_method": "manual", "automation_capable": False,
    "scanner_ips": ["1.2.3.4", "5.6.7.8"],
}


def test_payload_attaches_safe_context():
    p = build_support_payload(VIEW, hostname="example.com", website_id="w-1",
                              scan_id="s-9")
    assert p["category"] == "question" and p["priority"] == "medium"
    assert "Vercel" in p["subject"] and "example.com" in p["subject"]
    body = p["description"]
    for needle in ("provider: vercel", "wizard_state: failed",
                   "challenge_detected: True", "website_id: w-1",
                   "hostname: example.com", "scan_id: s-9",
                   "scanner_ips: 1.2.3.4, 5.6.7.8"):
        assert needle in body, needle


def test_payload_never_contains_secret_keys():
    p = build_support_payload(VIEW, hostname="example.com", website_id="w-1")
    blob = (p["subject"] + p["description"]).lower()
    for forbidden in ("token", "secret", "authorization", "bearer", "password",
                      "access_token", "refresh_token", "api_key"):
        assert forbidden not in blob, forbidden


def test_payload_without_scan_id_uses_latest_reference():
    p = build_support_payload(VIEW, hostname="example.com", website_id="w-1")
    assert "latest scan for this website" in p["description"]
    assert "scan_id:" not in p["description"]


def test_payload_unknown_provider():
    v = {**VIEW, "provider": None, "provider_name": None}
    p = build_support_payload(v, hostname="x.com", website_id="w-2")
    assert "unknown provider" in p["subject"]
    assert "provider: unknown" in p["description"]
