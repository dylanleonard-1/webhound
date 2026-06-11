"""Onboarding redesign — completion derives from PROVIDER CONNECTIONS, not a scan.
Pure helpers (no DB). Run with --noconftest -p no:cacheprovider."""
from __future__ import annotations

from types import SimpleNamespace

from apps.api.models.enums import ReadinessCheck
from apps.api.services import onboarding_readiness as ob

_PASS, _WARN, _FAIL = ReadinessCheck.PASS, ReadinessCheck.WARNING, ReadinessCheck.FAIL


def _pp(**kw):
    base = dict(cdn_provider=None, waf_provider=None, dns_provider=None, hosting_provider=None)
    base.update(kw)
    return SimpleNamespace(**base)


def test_detect_cloudflare_and_vercel():
    pp = _pp(cdn_provider="Cloudflare", waf_provider="Cloudflare", hosting_provider="Vercel")
    assert ob.detected_supported_providers(pp) == {"cloudflare", "vercel"}


def test_detect_cloudflare_only():
    assert ob.detected_supported_providers(_pp(dns_provider="Cloudflare")) == {"cloudflare"}


def test_detect_none_when_unsupported():
    assert ob.detected_supported_providers(_pp(hosting_provider="Netlify", dns_provider="GoDaddy")) == set()
    assert ob.detected_supported_providers(None) == set()


def test_both_detected_completes_only_when_both_connected():
    det = {"cloudflare", "vercel"}
    assert ob.provider_connected_check(det, {"cloudflare", "vercel"}, verified=True) is _PASS
    # Partial connect is a HARD FAIL now (must NOT complete onboarding), not WARN.
    assert ob.provider_connected_check(det, {"cloudflare"}, verified=True) is _FAIL   # partial
    assert ob.provider_connected_check(det, set(), verified=True) is _FAIL


def test_cf_only_completes_on_cf():
    assert ob.provider_connected_check({"cloudflare"}, {"cloudflare"}, verified=True) is _PASS
    assert ob.provider_connected_check({"cloudflare"}, set(), verified=True) is _FAIL


def test_no_supported_provider_falls_back_to_verified():
    # Manual DNS path: 'connected' == ownership verified when nothing to OAuth-connect.
    assert ob.provider_connected_check(set(), set(), verified=True) is _PASS
    assert ob.provider_connected_check(set(), set(), verified=False) is _FAIL


def test_access_validation_not_in_hard_checks():
    # The scan-based coverage check is no longer a completion gate.
    assert "access_validation" not in ob._HARD_CHECKS
    assert "provider_connected" in ob._HARD_CHECKS


def test_webhoundsecurity_layout_detects_both():
    # The real layout: Cloudflare in DNS, Vercel in HOSTING (the bug scenario).
    pp = _pp(dns_provider="Cloudflare", hosting_provider="Vercel")
    assert ob.detected_supported_providers(pp) == {"cloudflare", "vercel"}
    # Only Cloudflare connected -> hard FAIL (onboarding NOT complete; Vercel missing).
    assert ob.provider_connected_check({"cloudflare", "vercel"}, {"cloudflare"}, verified=True) is _FAIL


def test_map_providers_partial_is_not_done():
    from apps.api.services import onboarding_wizard as wz
    # partial -> provider_connected FAIL -> step 'pending' (NOT a done status).
    assert wz._map_providers({"checks": {"provider_connected": "fail"}}) == "pending"
    assert wz._map_providers({"checks": {"provider_connected": "warning"}}) == "pending"
    # all connected -> PASS -> 'completed'.
    assert wz._map_providers({"checks": {"provider_connected": "pass"}}) == "completed"
    # 'pending' is NOT in the wizard's DONE set.
    assert "pending" not in wz._DONE


def test_wizard_reads_100_when_providers_connected_and_bypass_active():
    # Deliverable D: once BOTH providers are connected AND scanner-access made trusted
    # access ACTIVE (bypass rules created+verified), the wizard must read completed/100%
    # — not stuck at 83% with trusted_access pending.
    from apps.api.models.enums import WizardStatus
    from apps.api.services import onboarding_wizard as wz
    # trusted_access ACTIVE is a DONE step (the prior 83% bug was it stuck 'pending').
    assert wz._map_trusted("active") == "completed"
    assert wz._map_trusted("pending") == "pending"  # honest: no bypass yet -> not done
    statuses = {
        "provider_discovery": "completed",
        "verification": "completed",
        "trusted_access": "completed",      # bypass active
        "providers_connected": "completed",  # both providers connected
        "readiness": "completed",
        "monitoring": "active",
    }
    assert wz._overall(statuses) is WizardStatus.COMPLETED
    # ...and a still-pending bypass keeps it IN_PROGRESS (never fake-complete).
    statuses["trusted_access"] = "pending"
    assert wz._overall(statuses) is WizardStatus.IN_PROGRESS
