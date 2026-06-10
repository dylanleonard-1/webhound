# WebHound — tests/test_provider_discovery.py
# Phase 3.1 Provider Discovery Foundation. Fully offline: assess_provider_profile
# runs the REAL TechnologyEngine over constructed PageArtifacts, so any Finding
# drift in technology.py breaks these tests rather than silently breaking
# discovery. The discover() test monkeypatches network I/O only.

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from webhound.core.extractor import PageArtifacts
from webhound.providers import discovery as pd
from webhound.providers.discovery import (
    EVENT_COMPLETED,
    EVENT_DETECTED,
    EVENT_STARTED,
    ProviderDiscoveryService,
    ProviderProfile,
    assess_provider_profile,
)

_NOW = datetime(2026, 6, 9, tzinfo=timezone.utc)


def _script(src: str | None = None, content: str | None = None):
    from webhound.core.extractor import ExtractedScript as _ES
    return _ES(
        src=src, content=content,
        is_inline=src is None, is_external=src is not None,
        is_external_domain=False,
    )


def _artifacts(
    *,
    url: str = "https://example.com/",
    response_headers: dict[str, str] | None = None,
    meta_tags: dict[str, str] | None = None,
    scripts=None,
    all_links: list[str] | None = None,
) -> PageArtifacts:
    _scripts = scripts or []
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title="Test",
        all_links=all_links or [],
        internal_links=[],
        external_links=[],
        scripts=_scripts,
        inline_scripts=[s.content for s in _scripts if s.is_inline and s.content],
        external_script_urls=[s.src for s in _scripts if s.is_external and s.src],
        forms=[],
        cookies=[],
        response_headers=response_headers or {},
        meta_tags=meta_tags or {},
        extracted_at=_NOW,
    )


# --- pure aggregation (real TechnologyEngine) --------------------------------

def test_cloudflare_via_cf_ray_sets_cdn_and_waf():
    h = {"cf-ray": "7d-LAX", "server": "cloudflare"}
    arts = _artifacts(response_headers=h)
    p = assess_provider_profile("example.com", artifacts=arts, response_headers=h, nameservers=[])
    assert p.cdn_provider == "Cloudflare"
    assert p.waf_provider == "Cloudflare"
    assert p.confidence > 0
    assert any("Cloudflare" in e for e in p.evidence)


def test_wordpress_via_meta_generator():
    arts = _artifacts(meta_tags={"generator": "WordPress 6.4.2"})
    p = assess_provider_profile("blog.test", artifacts=arts, response_headers={}, nameservers=[])
    assert p.cms == "WordPress"


def test_nextjs_framework_from_structured_evidence():
    # Next.js is attributed from the Finding's structured extra, not its title.
    arts = _artifacts(scripts=[_script(src="https://example.com/_next/static/app.js")])
    p = assess_provider_profile("example.com", artifacts=arts, response_headers={}, nameservers=[])
    assert p.framework == "Next.js"
    assert any("framework: Next.js" in e for e in p.evidence)


def test_shopify_cms_via_header():
    h = {"x-shopify-stage": "production"}
    arts = _artifacts(response_headers=h)
    p = assess_provider_profile("shop.test", artifacts=arts, response_headers=h, nameservers=[])
    assert p.cms == "Shopify"


def test_dns_provider_from_nameservers():
    p = assess_provider_profile(
        "example.com", artifacts=None, response_headers={},
        nameservers=["ns1.cloudflare.com", "ns2.cloudflare.com"],
    )
    assert p.dns_provider == "Cloudflare"


def test_hosting_provider_from_vercel_header():
    h = {"x-vercel-id": "iad1::abc"}
    p = assess_provider_profile("app.test", artifacts=None, response_headers=h, nameservers=[])
    assert p.hosting_provider == "Vercel"


def test_vercel_via_challenge_signature_reuse():
    # Reuses challenge_detection._PROVIDER_SIGNATURES URL signatures.
    arts = _artifacts(all_links=["https://app.test/_vercel/security/challenge"])
    p = assess_provider_profile(
        "app.test", artifacts=arts,
        response_headers={}, nameservers=[],
    )
    assert p.cdn_provider == "Vercel"


def test_non_html_header_fallback_detects_cloudflare():
    # artifacts is None (non-HTML / hard block) — CDN/WAF still come from headers.
    h = {"cf-ray": "7d-DFW"}
    p = assess_provider_profile("blocked.test", artifacts=None, response_headers=h, nameservers=[])
    assert p.cdn_provider == "Cloudflare"
    assert p.waf_provider == "Cloudflare"


def test_unknown_domain_is_all_none_zero_confidence():
    p = assess_provider_profile("nothing.test", artifacts=None, response_headers={}, nameservers=[])
    assert p.cdn_provider is None and p.cms is None and p.dns_provider is None
    assert p.confidence == 0
    assert p.evidence == []
    assert p.registrar is None  # deferred in the foundation


def test_to_dict_has_all_success_criteria_fields():
    p = assess_provider_profile("x.test", artifacts=None, response_headers={}, nameservers=[])
    d = p.to_dict()
    for key in ("domain", "registrar", "dns_provider", "hosting_provider",
                "cdn_provider", "waf_provider", "cms", "framework",
                "confidence", "evidence"):
        assert key in d


def test_full_stack_confidence_and_evidence():
    h = {"cf-ray": "7d-LAX"}
    arts = _artifacts(
        response_headers=h,
        meta_tags={"generator": "WordPress 6.4"},
        scripts=[_script(src="https://x.test/_next/static/app.js")],
    )
    p = assess_provider_profile(
        "x.test", artifacts=arts, response_headers=h,
        nameservers=["ns1.cloudflare.com"],
    )
    assert p.cdn_provider == "Cloudflare" and p.waf_provider == "Cloudflare"
    assert p.cms == "WordPress"
    assert p.framework == "Next.js"
    assert p.dns_provider == "Cloudflare"
    assert p.confidence >= 70
    assert len(p.evidence) >= 4


# --- discover() IO orchestration (network monkeypatched) ---------------------

class _FakeResp:
    def __init__(self, headers, body="", content_type="text/html"):
        self.headers = headers
        self.body = body
        self.content_type = content_type
        self.status_code = 200
        self.url = "https://example.com/"


def test_discover_emits_events_and_degrades_on_fetch_failure(monkeypatch):
    events: list[tuple[str, dict]] = []

    # Fetch fails entirely → discovery must degrade to DNS-only, not crash.
    class _BoomClient:
        def __init__(self, *a, **k): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, url): raise RuntimeError("network down")

    monkeypatch.setattr(pd, "SafeHttpClient", _BoomClient)
    monkeypatch.setattr(pd, "resolve_dns", lambda *a, **k: type("R", (), {"ns": ["ns1.cloudflare.com"]})())

    svc = ProviderDiscoveryService(timeout_seconds=5)
    profile = asyncio.run(svc.discover("https://example.com/", on_event=lambda n, p: events.append((n, p))))

    assert isinstance(profile, ProviderProfile)
    assert profile.dns_provider == "Cloudflare"  # DNS-only still works
    names = [n for n, _ in events]
    assert names[0] == EVENT_STARTED
    assert EVENT_COMPLETED == names[-1]
    assert EVENT_DETECTED in names
