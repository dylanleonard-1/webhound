"""Phase-2 Platform Access — provider registry: loading, detection, remediation.
Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

import pytest

from apps.api.services.provider_access_registry import (
    PROVIDERS,
    all_providers,
    detect_provider,
    get_provider,
    render_remediation,
)

_EXPECTED = {
    "cloudflare", "vercel", "cloudfront", "akamai", "fastly",
    "azure_front_door", "imperva", "sucuri", "aws_waf", "google_cloud_armor",
}


def test_registry_has_all_ten_providers():
    assert set(PROVIDERS) == _EXPECTED
    assert len(all_providers()) == 10


def test_only_cloudflare_is_automation_capable():
    auto = {p.key for p in all_providers() if p.automation_capable}
    assert auto == {"cloudflare"}
    assert get_provider("cloudflare").allowlist_method == "api"
    for k in _EXPECTED - {"cloudflare"}:
        assert get_provider(k).allowlist_method == "manual"


def test_every_provider_has_complete_remediation():
    for p in all_providers():
        assert p.name and p.support_url.startswith("https://")
        assert p.remediation_title and p.remediation_problem and p.remediation_impact
        assert len(p.remediation_steps) >= 2
        # Exactly one step carries the scanner IPs.
        ip_steps = [s for s in p.remediation_steps if s.ips]
        assert len(ip_steps) == 1, p.key


# --- detection (per provider, from real signals) ---


@pytest.mark.parametrize("provider,headers,body", [
    ("cloudflare", {"cf-ray": "abc", "server": "cloudflare"}, ""),
    ("vercel", {"x-vercel-id": "iad1::xyz"}, "Vercel Security Checkpoint"),
    ("cloudfront", {"x-amz-cf-id": "xyz", "via": "1.1 abc.cloudfront.net"}, ""),
    ("akamai", {"x-akamai-transformed": "9", "server": "AkamaiGHost"}, ""),
    ("fastly", {"x-fastly-request-id": "abc", "x-served-by": "cache-fastly"}, ""),
    ("azure_front_door", {"x-azure-ref": "abc", "x-azure-fdid": "xyz"}, ""),
    ("imperva", {"x-iinfo": "1-2-3", "x-cdn": "Incapsula"}, ""),
    ("sucuri", {"x-sucuri-id": "12", "server": "Sucuri/Cloudproxy"}, ""),
    ("aws_waf", {"x-amzn-requestid": "abc"}, "AWS WAF request blocked"),
    ("google_cloud_armor", {"via": "1.1 google", "server": "Google Frontend"},
     "Google Cloud Armor: the request was blocked"),
])
def test_detect_each_provider(provider, headers, body):
    res = detect_provider(headers=headers, body=body)
    assert res is not None, provider
    assert res["provider"] == provider, (provider, res)
    assert res["confidence"] > 0


def test_detect_none_for_clean_response():
    assert detect_provider(headers={"server": "nginx"}, body="<html>ok</html>") is None


def test_detect_cookie_signal_imperva():
    res = detect_provider(headers={"set-cookie": "visid_incap_123=abc; path=/"})
    assert res and res["provider"] == "imperva"


def test_detect_challenge_url_cloudflare():
    res = detect_provider(url_chain="https://x.com/cdn-cgi/challenge-platform/h/g")
    assert res and res["provider"] == "cloudflare"


# --- remediation rendering (dynamic IPs, no hardcoding) ---


def test_render_remediation_injects_ips():
    ips = ["1.2.3.4", "5.6.7.8", "9.9.9.9"]
    pay = render_remediation("vercel", ips)
    assert pay["provider"] == "vercel"
    assert pay["scanner_ips"] == ips
    assert pay["copy_all"] == "1.2.3.4, 5.6.7.8, 9.9.9.9"
    ip_steps = [s for s in pay["steps"] if s["copyable"]]
    assert len(ip_steps) == 1
    assert "1.2.3.4, 5.6.7.8, 9.9.9.9" in ip_steps[0]["text"]
    assert ip_steps[0]["copy_value"] == "1.2.3.4, 5.6.7.8, 9.9.9.9"
    # steps numbered sequentially
    assert [s["n"] for s in pay["steps"]] == list(range(1, len(pay["steps"]) + 1))


def test_render_remediation_unknown_provider():
    assert render_remediation("nope", ["1.2.3.4"]) is None
