# WebHound — scanner/tests/test_third_party_domains.py
# Tests for the ThirdPartyDomainEngine covering trusted CDN filtering,
# unknown-domain detection, risky-TLD escalation, and form-action checks.
# All tests use constructed PageArtifacts — no network activity.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.core.extractor import (
    ExtractedForm,
    ExtractedIframe,
    ExtractedScript,
    FormInput,
    PageArtifacts,
)
from webhound.engines.javascript.third_party_domains import ThirdPartyDomainEngine
from webhound.models.severity import Severity

_ENGINE = ThirdPartyDomainEngine()
_NOW = datetime.now(timezone.utc)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _script(
    src: str,
    is_external_domain: bool = True,
) -> ExtractedScript:
    return ExtractedScript(
        src=src,
        content=None,
        is_inline=False,
        is_external=True,
        is_external_domain=is_external_domain,
    )


def _form(
    action_url: str | None,
    has_password: bool = False,
) -> ExtractedForm:
    return ExtractedForm(
        action=action_url,
        action_url=action_url,
        method="POST",
        inputs=(),
        has_password_field=has_password,
        has_csrf_token=False,
    )


def _iframe(
    src_url: str,
    page_url: str = "https://example.com/",
    is_hidden: bool = False,
    sandbox: str | None = None,
) -> ExtractedIframe:
    from urllib.parse import urlparse
    page_host = urlparse(page_url).hostname or ""
    src_host = urlparse(src_url).hostname or ""
    return ExtractedIframe(
        src_url=src_url,
        is_external_domain=(src_host != page_host),
        is_hidden=is_hidden,
        sandbox=sandbox,
    )


def _artifacts(
    url: str = "https://example.com/",
    scripts: list[ExtractedScript] | None = None,
    forms: list[ExtractedForm] | None = None,
    external_links: list[str] | None = None,
    iframes: list[ExtractedIframe] | None = None,
    external_stylesheet_urls: list[str] | None = None,
    inline_css_import_urls: list[str] | None = None,
    inline_js_request_urls: list[str] | None = None,
) -> PageArtifacts:
    _scripts = scripts or []
    ext_urls = [s.src for s in _scripts if s.is_external and s.src]
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title="Test Page",
        all_links=[],
        internal_links=[],
        external_links=external_links or [],
        scripts=_scripts,
        inline_scripts=[],
        external_script_urls=ext_urls,
        forms=forms or [],
        cookies=[],
        response_headers={},
        meta_tags={},
        extracted_at=_NOW,
        iframes=iframes or [],
        external_stylesheet_urls=external_stylesheet_urls or [],
        inline_css_import_urls=inline_css_import_urls or [],
        inline_js_request_urls=inline_js_request_urls or [],
    )


# ===========================================================================
# Trusted CDN domains — must never generate findings
# ===========================================================================


def _domain_findings(findings):
    """Domain-trust findings only. The engine also emits an orthogonal
    missing-Subresource-Integrity finding for any external script without an
    integrity hash; these tests are about domain classification, not SRI."""
    return [f for f in findings if "subresource integrity" not in f.title.lower()]


class TestTrustedCdnDomains:

    def test_google_analytics_no_finding(self):
        arts = _artifacts(scripts=[
            _script("https://www.google-analytics.com/analytics.js"),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_googleapis_no_finding(self):
        arts = _artifacts(scripts=[
            _script("https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_cloudflare_cdn_no_finding(self):
        arts = _artifacts(scripts=[
            _script("https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.4/moment.min.js"),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_jsdelivr_no_finding(self):
        arts = _artifacts(scripts=[
            _script("https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.min.js"),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_stripe_no_finding(self):
        arts = _artifacts(scripts=[
            _script("https://js.stripe.com/v3/"),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_facebook_no_finding(self):
        arts = _artifacts(scripts=[
            _script("https://connect.facebook.net/en_US/fbevents.js"),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_multiple_trusted_cdns_no_findings(self):
        arts = _artifacts(scripts=[
            _script("https://www.googletagmanager.com/gtag/js"),
            _script("https://cdn.jsdelivr.net/npm/bootstrap@5/dist/js/bootstrap.min.js"),
            _script("https://unpkg.com/react@18/umd/react.production.min.js"),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_external_script_without_sri_is_flagged(self):
        # Orthogonal to domain trust: any external <script> lacking an
        # integrity hash earns a single missing-SRI finding.
        arts = _artifacts(scripts=[
            _script("https://cdn.jsdelivr.net/npm/bootstrap@5/dist/js/bootstrap.min.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert any("subresource integrity" in f.title.lower() for f in findings)


# ===========================================================================
# Unknown external domains — must produce LOW findings
# ===========================================================================


class TestUnknownExternalDomains:

    def test_unknown_domain_produces_finding(self):
        arts = _artifacts(scripts=[
            _script("https://analytics.unknown-startup.com/track.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert len(_domain_findings(findings)) == 1

    def test_unknown_domain_severity_is_low(self):
        arts = _artifacts(scripts=[
            _script("https://cdn.somevendor.com/widget.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert findings[0].severity == Severity.LOW

    def test_unknown_domain_finding_title_contains_host(self):
        arts = _artifacts(scripts=[
            _script("https://cdn.somevendor.com/widget.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert "cdn.somevendor.com" in findings[0].title

    def test_unknown_domain_finding_has_evidence(self):
        arts = _artifacts(scripts=[
            _script("https://cdn.somevendor.com/widget.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert findings[0].evidence

    def test_unknown_domain_category_is_javascript(self):
        from webhound.models.finding import FindingCategory
        arts = _artifacts(scripts=[
            _script("https://cdn.somevendor.com/widget.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert findings[0].category == FindingCategory.JAVASCRIPT

    def test_two_different_unknown_domains_two_findings(self):
        arts = _artifacts(scripts=[
            _script("https://cdn.vendorA.com/a.js"),
            _script("https://cdn.vendorB.com/b.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert len(_domain_findings(findings)) == 2

    def test_same_domain_different_paths_one_finding(self):
        arts = _artifacts(scripts=[
            _script("https://cdn.vendorA.com/a.js"),
            _script("https://cdn.vendorA.com/b.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert len(_domain_findings(findings)) == 1

    def test_subdomains_of_same_registered_domain_one_finding(self):
        arts = _artifacts(scripts=[
            _script("https://static.vendorA.com/a.js"),
            _script("https://cdn.vendorA.com/b.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert len(_domain_findings(findings)) == 1


# ===========================================================================
# Risky TLDs — must produce MEDIUM findings
# ===========================================================================


class TestRiskyTldDomains:

    def test_tk_tld_is_medium(self):
        arts = _artifacts(scripts=[
            _script("https://analytics.free.tk/track.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert findings[0].severity == Severity.MEDIUM

    def test_xyz_tld_is_medium(self):
        arts = _artifacts(scripts=[
            _script("https://cdn.cheap.xyz/lib.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert findings[0].severity == Severity.MEDIUM

    def test_cc_tld_is_medium(self):
        arts = _artifacts(scripts=[
            _script("https://script.abuse.cc/track.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert findings[0].severity == Severity.MEDIUM


# ===========================================================================
# Same-domain scripts — must never produce findings
# ===========================================================================


class TestSameDomainScripts:

    def test_same_domain_external_path_no_finding(self):
        arts = _artifacts(scripts=[
            _script("https://example.com/js/app.js", is_external_domain=False),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_inline_scripts_ignored(self):
        from webhound.core.extractor import ExtractedScript as ES
        inline = ES(
            src=None,
            content="var x = 1;",
            is_inline=True,
            is_external=False,
            is_external_domain=False,
        )
        arts = _artifacts(scripts=[inline])
        assert _domain_findings(_ENGINE.analyze(arts)) == []


# ===========================================================================
# Mixed trusted + unknown
# ===========================================================================


class TestMixedDomains:

    def test_trusted_plus_unknown_one_finding(self):
        arts = _artifacts(scripts=[
            _script("https://www.google-analytics.com/analytics.js"),  # trusted
            _script("https://cdn.unknown-tracker.com/pixel.js"),        # unknown
        ])
        findings = _ENGINE.analyze(arts)
        assert len(_domain_findings(findings)) == 1
        assert "unknown-tracker.com" in findings[0].title

    def test_two_unknown_one_trusted_two_findings(self):
        arts = _artifacts(scripts=[
            _script("https://www.googletagmanager.com/gtag/js"),  # trusted
            _script("https://cdn.vendorA.com/a.js"),               # unknown
            _script("https://cdn.vendorB.com/b.js"),               # unknown
        ])
        findings = _ENGINE.analyze(arts)
        assert len(_domain_findings(findings)) == 2


# ===========================================================================
# External form actions
# ===========================================================================


class TestExternalFormActions:

    def test_form_action_external_domain_produces_finding(self):
        arts = _artifacts(forms=[
            _form("https://external-processor.com/submit"),
        ])
        findings = _ENGINE.analyze(arts)
        assert len(_domain_findings(findings)) == 1

    def test_form_action_external_finding_is_medium(self):
        arts = _artifacts(forms=[
            _form("https://external-processor.com/submit"),
        ])
        findings = _ENGINE.analyze(arts)
        assert findings[0].severity == Severity.MEDIUM

    def test_form_action_same_domain_no_finding(self):
        arts = _artifacts(
            url="https://example.com/",
            forms=[_form("https://example.com/submit")],
        )
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_form_action_none_no_finding(self):
        arts = _artifacts(forms=[_form(None)])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_form_action_deduplication(self):
        arts = _artifacts(forms=[
            _form("https://external-processor.com/submit"),
            _form("https://external-processor.com/other"),
        ])
        findings = _ENGINE.analyze(arts)
        assert len(_domain_findings(findings)) == 1


# ===========================================================================
# Empty / no-op cases
# ===========================================================================


class TestEdgeCases:

    def test_empty_artifacts_no_findings(self):
        arts = _artifacts()
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_no_external_scripts_no_findings(self):
        arts = _artifacts(scripts=[
            _script("https://example.com/app.js", is_external_domain=False),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_engine_name_is_third_party_domains(self):
        assert _ENGINE.NAME == "third_party_domains"

    def test_finding_scanner_engine_field(self):
        arts = _artifacts(scripts=[
            _script("https://cdn.unknownvendor.io/lib.js"),
        ])
        findings = _ENGINE.analyze(arts)
        assert findings[0].scanner_engine == "third_party_domains"

    def test_finding_has_framework_mappings(self):
        arts = _artifacts(scripts=[
            _script("https://cdn.unknownvendor.io/lib.js"),
        ])
        findings = _ENGINE.analyze(arts)
        f = findings[0]
        assert f.framework.owasp_top10
        assert "A08:2021" in f.framework.owasp_top10
        assert "CWE-829" in f.framework.cwe_ids


# ===========================================================================
# External iframes (visible)
# ===========================================================================


class TestExternalIframes:

    def test_visible_external_iframe_produces_finding(self):
        arts = _artifacts(iframes=[
            _iframe("https://widget.external-service.com/embed"),
        ])
        findings = _ENGINE.analyze(arts)
        assert len(_domain_findings(findings)) == 1

    def test_visible_external_iframe_severity_is_low(self):
        arts = _artifacts(iframes=[
            _iframe("https://widget.external-service.com/embed"),
        ])
        assert _ENGINE.analyze(arts)[0].severity == Severity.LOW

    def test_hidden_external_iframe_is_skipped(self):
        # Hidden iframes are handled by the compromise/hidden_iframes engine
        arts = _artifacts(iframes=[
            _iframe("https://tracker.evil.com/px", is_hidden=True),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_same_domain_iframe_produces_no_finding(self):
        arts = _artifacts(iframes=[
            ExtractedIframe(
                src_url="https://example.com/embed",
                is_external_domain=False,
                is_hidden=False,
                sandbox=None,
            ),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_trusted_iframe_domain_no_finding(self):
        arts = _artifacts(iframes=[
            _iframe("https://www.youtube.com/embed/abc123"),
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_iframe_finding_title_contains_host(self):
        arts = _artifacts(iframes=[
            _iframe("https://widget.vendorx.com/embed"),
        ])
        findings = _ENGINE.analyze(arts)
        assert "widget.vendorx.com" in findings[0].title

    def test_iframe_finding_contains_category(self):
        arts = _artifacts(iframes=[
            _iframe("https://widget.vendorx.com/embed"),
        ])
        findings = _ENGINE.analyze(arts)
        assert "Unknown" in findings[0].title

    def test_iframe_deduplication_same_registered_domain(self):
        arts = _artifacts(iframes=[
            _iframe("https://a.vendorx.com/embed"),
            _iframe("https://b.vendorx.com/embed"),
        ])
        assert len(_ENGINE.analyze(arts)) == 1


# ===========================================================================
# External stylesheets
# ===========================================================================


class TestExternalStylesheets:

    def test_external_stylesheet_produces_finding(self):
        arts = _artifacts(external_stylesheet_urls=[
            "https://fonts.unknown-font-cdn.com/css?family=Roboto",
        ])
        assert len(_ENGINE.analyze(arts)) == 1

    def test_external_stylesheet_severity_is_low(self):
        arts = _artifacts(external_stylesheet_urls=[
            "https://fonts.unknown-font-cdn.com/css?family=Roboto",
        ])
        assert _ENGINE.analyze(arts)[0].severity == Severity.LOW

    def test_trusted_stylesheet_no_finding(self):
        arts = _artifacts(external_stylesheet_urls=[
            "https://fonts.googleapis.com/css2?family=Roboto",
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_css_import_url_produces_finding(self):
        arts = _artifacts(inline_css_import_urls=[
            "https://static.unknown-cdn.net/styles/base.css",
        ])
        assert len(_ENGINE.analyze(arts)) == 1

    def test_stylesheet_and_css_import_same_domain_deduped(self):
        arts = _artifacts(
            external_stylesheet_urls=["https://fonts.unknowncdn.com/a.css"],
            inline_css_import_urls=["https://fonts.unknowncdn.com/b.css"],
        )
        assert len(_ENGINE.analyze(arts)) == 1


# ===========================================================================
# Inline JS request destinations (fetch / XHR / WebSocket)
# ===========================================================================


class TestJsRequestDomains:

    def test_fetch_to_external_domain_produces_finding(self):
        arts = _artifacts(inline_js_request_urls=[
            "https://api.unknown-tracker.com/v1/events",
        ])
        assert len(_ENGINE.analyze(arts)) == 1

    def test_websocket_to_external_domain_produces_finding(self):
        arts = _artifacts(inline_js_request_urls=[
            "wss://realtime.external-service.io/ws",
        ])
        assert len(_ENGINE.analyze(arts)) == 1

    def test_fetch_to_same_domain_no_finding(self):
        arts = _artifacts(
            url="https://example.com/",
            inline_js_request_urls=["https://example.com/api/data"],
        )
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_trusted_api_domain_no_finding(self):
        arts = _artifacts(inline_js_request_urls=[
            "https://api.stripe.com/v1/charges",
        ])
        assert _domain_findings(_ENGINE.analyze(arts)) == []

    def test_js_request_finding_title_contains_domain(self):
        arts = _artifacts(inline_js_request_urls=[
            "https://collect.unknown-analytics.com/event",
        ])
        findings = _ENGINE.analyze(arts)
        assert "collect.unknown-analytics.com" in findings[0].title

    def test_js_request_deduplication_same_domain(self):
        arts = _artifacts(inline_js_request_urls=[
            "https://api.vendorx.com/track",
            "https://api.vendorx.com/identify",
        ])
        assert len(_ENGINE.analyze(arts)) == 1


# ===========================================================================
# Domain categorization labels
# ===========================================================================


class TestDomainCategorization:
    from webhound.engines.javascript.third_party_domains import _get_category

    def test_google_analytics_categorized_as_analytics(self):
        from webhound.engines.javascript.third_party_domains import _get_category
        assert _get_category("google-analytics.com") == "Analytics"

    def test_stripe_categorized_as_payments(self):
        from webhound.engines.javascript.third_party_domains import _get_category
        assert _get_category("stripe.com") == "Payments"

    def test_facebook_net_categorized_as_tracking(self):
        from webhound.engines.javascript.third_party_domains import _get_category
        assert _get_category("facebook.net") == "Tracking"

    def test_hubspot_categorized_as_marketing(self):
        from webhound.engines.javascript.third_party_domains import _get_category
        assert _get_category("hubspot.com") == "Marketing"

    def test_sentry_categorized_as_monitoring(self):
        from webhound.engines.javascript.third_party_domains import _get_category
        assert _get_category("sentry.io") == "Monitoring"

    def test_cloudflare_categorized_as_cdn(self):
        from webhound.engines.javascript.third_party_domains import _get_category
        assert _get_category("cloudflare.com") == "CDN"

    def test_unknown_domain_categorized_as_unknown(self):
        from webhound.engines.javascript.third_party_domains import _get_category
        assert _get_category("some-random-domain.com") == "Unknown"
