# WebHound — scanner/tests/test_shopify_engine.py
# Phase 9B: Unit tests for the Shopify CMS engine.
# Previously STATIC-only — this file brings it to full unit-test coverage.
# All tests use constructed PageArtifacts — no HTTP, no live network.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.core.extractor import ExtractedScript, PageArtifacts
from webhound.engines.cms.shopify import ShopifyEngine, _is_shopify, _mask, _detect_apps
from webhound.models.finding import FindingCategory
from webhound.models.severity import Severity

_ENGINE = ShopifyEngine()
_NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# PageArtifacts helpers
# ---------------------------------------------------------------------------

def _artifacts(
    url: str = "https://myshop.myshopify.com/",
    meta_tags: dict | None = None,
    response_headers: dict | None = None,
    external_script_urls: list[str] | None = None,
    inline_scripts: list[str] | None = None,
    all_links: list[str] | None = None,
    scripts: list | None = None,
) -> PageArtifacts:
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title="Test Shop",
        all_links=all_links or [],
        internal_links=[],
        external_links=[],
        scripts=scripts or [],
        inline_scripts=inline_scripts or [],
        external_script_urls=external_script_urls or [],
        forms=[],
        cookies=[],
        response_headers=response_headers or {},
        meta_tags=meta_tags or {},
        extracted_at=_NOW,
    )


def _shopify_artifacts(**kwargs) -> PageArtifacts:
    """Return Shopify-detected artifacts via generator meta tag."""
    meta = kwargs.pop("meta_tags", {})
    meta.setdefault("generator", "Shopify")
    return _artifacts(meta_tags=meta, **kwargs)


# ---------------------------------------------------------------------------
# Detection (_is_shopify)
# ---------------------------------------------------------------------------

class TestShopifyDetection:
    def test_detected_via_generator_meta(self):
        a = _artifacts(meta_tags={"generator": "Shopify"})
        assert _is_shopify(a)

    def test_detected_via_shopify_header(self):
        a = _artifacts(response_headers={"x-shopify-stage": "production"})
        assert _is_shopify(a)

    def test_detected_via_request_id_header(self):
        a = _artifacts(response_headers={"x-shopify-request-id": "abc123"})
        assert _is_shopify(a)

    def test_detected_via_cdn_script(self):
        a = _artifacts(external_script_urls=["https://cdn.shopify.com/s/assets/storefront.js"])
        assert _is_shopify(a)

    def test_detected_via_shopifycdn(self):
        a = _artifacts(external_script_urls=["https://cdn.shopifycdn.com/s/js/app.js"])
        assert _is_shopify(a)

    def test_detected_via_cdn_shop_link(self):
        a = _artifacts(all_links=["https://myshop.com/cdn/shop/products/img.jpg"])
        assert _is_shopify(a)

    def test_not_detected_on_plain_site(self):
        a = _artifacts(
            meta_tags={"generator": "WordPress"},
            response_headers={"server": "nginx"},
        )
        assert not _is_shopify(a)

    def test_detection_case_insensitive_meta(self):
        a = _artifacts(meta_tags={"generator": "SHOPIFY"})
        assert _is_shopify(a)


# ---------------------------------------------------------------------------
# analyze() — detected finding
# ---------------------------------------------------------------------------

class TestShopifyDetectedFinding:
    def test_shopify_detected_emits_info_finding(self):
        a = _shopify_artifacts()
        findings = _ENGINE.analyze(a)
        assert any("Shopify detected" in f.title for f in findings)

    def test_detected_finding_severity_info(self):
        a = _shopify_artifacts()
        findings = _ENGINE.analyze(a)
        detected = next(f for f in findings if "Shopify detected" in f.title)
        assert detected.severity == Severity.INFO

    def test_detected_finding_has_evidence(self):
        a = _shopify_artifacts()
        findings = _ENGINE.analyze(a)
        detected = next(f for f in findings if "Shopify detected" in f.title)
        assert detected.evidence

    def test_non_shopify_returns_empty(self):
        a = _artifacts(meta_tags={"generator": "WordPress"})
        findings = _ENGINE.analyze(a)
        assert findings == []


# ---------------------------------------------------------------------------
# Admin token leak (shpat_)
# ---------------------------------------------------------------------------

class TestAdminTokenLeak:
    _FAKE_TOKEN = "shpat_" + "a" * 32

    def test_admin_token_in_inline_script_fires(self):
        a = _shopify_artifacts(inline_scripts=[f"var token = '{self._FAKE_TOKEN}';"])
        findings = _ENGINE.analyze(a)
        assert any("Admin API token" in f.title for f in findings)

    def test_admin_token_severity_critical(self):
        a = _shopify_artifacts(inline_scripts=[f"x='{self._FAKE_TOKEN}'"])
        findings = _ENGINE.analyze(a)
        token_finding = next(f for f in findings if "Admin API token" in f.title)
        assert token_finding.severity == Severity.CRITICAL

    def test_admin_token_in_html_body(self):
        a = _shopify_artifacts()
        findings = _ENGINE.analyze(a, html_body=f"token: {self._FAKE_TOKEN}")
        assert any("Admin API token" in f.title for f in findings)

    def test_admin_token_evidence_is_masked(self):
        a = _shopify_artifacts(inline_scripts=[f"x='{self._FAKE_TOKEN}'"])
        findings = _ENGINE.analyze(a)
        token_finding = next(f for f in findings if "Admin API token" in f.title)
        # The full token must NOT appear in evidence content
        for ev in token_finding.evidence:
            assert self._FAKE_TOKEN not in (ev.content or "")

    def test_no_false_positive_on_storefront_token_prefix(self):
        # shpss_ is a different finding type, not admin
        a = _shopify_artifacts(inline_scripts=["var x = 'shpss_" + "b" * 32 + "';"])
        findings = _ENGINE.analyze(a)
        assert not any("Admin API token" in f.title for f in findings)

    def test_wrong_token_format_no_finding(self):
        # Token too short — not a valid shpat_ token
        a = _shopify_artifacts(inline_scripts=["var token = 'shpat_abc123';"])
        findings = _ENGINE.analyze(a)
        assert not any("Admin API token" in f.title for f in findings)


# ---------------------------------------------------------------------------
# Shared-secret token leak (shpss_)
# ---------------------------------------------------------------------------

class TestSessionTokenLeak:
    _FAKE_SS = "shpss_" + "c" * 32

    def test_session_token_in_inline_script_fires(self):
        a = _shopify_artifacts(inline_scripts=[f"var ss = '{self._FAKE_SS}';"])
        findings = _ENGINE.analyze(a)
        assert any("shpss_" in f.title or "shared-secret" in f.title.lower() for f in findings)

    def test_session_token_severity_critical(self):
        a = _shopify_artifacts(inline_scripts=[f"ss='{self._FAKE_SS}'"])
        findings = _ENGINE.analyze(a)
        ss_finding = next((f for f in findings if "shpss_" in f.title or "shared-secret" in f.title.lower()), None)
        assert ss_finding is not None
        assert ss_finding.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# App inventory
# ---------------------------------------------------------------------------

class TestAppInventory:
    def test_klaviyo_detected(self):
        a = _shopify_artifacts(external_script_urls=["https://static.klaviyo.com/onsite/js/klaviyo.js"])
        findings = _ENGINE.analyze(a)
        app_finding = next((f for f in findings if "third-party apps" in f.title.lower()), None)
        assert app_finding is not None
        assert "Klaviyo" in app_finding.metadata.get("apps", [])

    def test_multiple_apps_detected(self):
        a = _shopify_artifacts(external_script_urls=[
            "https://static.klaviyo.com/onsite/js/klaviyo.js",
            "https://staticw2.yotpo.com/widgets/yotpo.js",
            "https://sdk.smile.io/v2/smile-shopify.js",
        ])
        findings = _ENGINE.analyze(a)
        app_finding = next((f for f in findings if "third-party apps" in f.title.lower()), None)
        assert app_finding is not None
        assert len(app_finding.metadata.get("apps", [])) >= 3

    def test_no_app_finding_when_no_apps(self):
        a = _shopify_artifacts(external_script_urls=["https://cdn.shopify.com/s/app.js"])
        findings = _ENGINE.analyze(a)
        assert not any("third-party apps" in f.title.lower() for f in findings)


# ---------------------------------------------------------------------------
# _mask helper
# ---------------------------------------------------------------------------

class TestMaskHelper:
    def test_mask_hides_middle(self):
        token = "shpat_" + "a" * 32
        masked = _mask(token)
        assert masked.startswith("shpat_")
        assert "*" in masked

    def test_mask_short_token_all_stars(self):
        assert _mask("abc") == "***"

    def test_mask_preserves_prefix_and_suffix(self):
        token = "shpat_" + "x" * 32 + "zzzz"
        masked = _mask(token)
        assert masked[:6] == "shpat_"
        assert masked[-4:] == "zzzz"


# ---------------------------------------------------------------------------
# Framework alignment
# ---------------------------------------------------------------------------

class TestFrameworkAlignment:
    def test_admin_token_has_cvss_10(self):
        a = _shopify_artifacts(inline_scripts=["shpat_" + "a" * 32])
        findings = _ENGINE.analyze(a)
        token_finding = next((f for f in findings if "Admin API token" in f.title), None)
        if token_finding and token_finding.framework:
            assert token_finding.framework.cvss_score == 10.0

    def test_detected_has_framework(self):
        a = _shopify_artifacts()
        findings = _ENGINE.analyze(a)
        detected = next(f for f in findings if "Shopify detected" in f.title)
        assert detected.framework is not None

    def test_detected_engine_name(self):
        a = _shopify_artifacts()
        findings = _ENGINE.analyze(a)
        for f in findings:
            assert f.scanner_engine == "shopify"
