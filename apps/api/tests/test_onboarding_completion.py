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
    assert ob.provider_connected_check(det, {"cloudflare"}, verified=True) is _WARN   # partial
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
