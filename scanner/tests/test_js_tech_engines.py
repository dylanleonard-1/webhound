# WebHound — scanner/tests/test_js_tech_engines.py
# Tests for Phase 5: JavaScript and technology detection engines.
#
# All tests use constructed PageArtifacts — no HTTP, no DNS, no live network.

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webhound.core.extractor import ExtractedForm, ExtractedScript, PageArtifacts
from webhound.engines.javascript.js_analyzer import JsAnalyzerEngine
from webhound.engines.javascript.js_collector import JsCollectorEngine
from webhound.engines.javascript.obfuscation_detector import ObfuscationDetectorEngine
from webhound.engines.javascript.third_party_domains import ThirdPartyDomainEngine
from webhound.engines.recon.technology import TechnologyEngine
from webhound.models.evidence import EvidenceType
from webhound.models.finding import FindingCategory
from webhound.models.severity import Severity

_COLLECTOR = JsCollectorEngine()
_ANALYZER = JsAnalyzerEngine()
_OBFUSCATION = ObfuscationDetectorEngine()
_THIRD_PARTY = ThirdPartyDomainEngine()
_TECH = TechnologyEngine()

_NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _script(
    *,
    src: str | None = None,
    content: str | None = None,
    is_inline: bool = False,
    is_external: bool = False,
    is_external_domain: bool = False,
) -> ExtractedScript:
    return ExtractedScript(
        src=src,
        content=content,
        is_inline=is_inline,
        is_external=is_external,
        is_external_domain=is_external_domain,
    )


def _artifacts(
    url: str = "https://example.com/",
    scripts: list[ExtractedScript] | None = None,
    forms: list[ExtractedForm] | None = None,
    response_headers: dict[str, str] | None = None,
    meta_tags: dict[str, str] | None = None,
    external_links: list[str] | None = None,
    all_links: list[str] | None = None,
) -> PageArtifacts:
    _scripts = scripts or []
    inline = [s.content for s in _scripts if s.is_inline and s.content]
    ext_urls = [s.src for s in _scripts if s.is_external and s.src]
    return PageArtifacts(
        url=url,
        status_code=200,
        content_type="text/html",
        title="Test Page",
        all_links=all_links or [],
        internal_links=[],
        external_links=external_links or [],
        scripts=_scripts,
        inline_scripts=inline,
        external_script_urls=ext_urls,
        forms=forms or [],
        cookies=[],
        response_headers=response_headers or {},
        meta_tags=meta_tags or {},
        extracted_at=_NOW,
    )


def _inline(content: str, page_url: str = "https://example.com/") -> ExtractedScript:
    return _script(content=content, is_inline=True)


def _external(
    src: str,
    page_url: str = "https://example.com/",
    same_domain: bool = False,
) -> ExtractedScript:
    return _script(src=src, is_external=True, is_external_domain=not same_domain)


# ===========================================================================
# TestJsCollectorEngine
# ===========================================================================

class TestJsCollectorEngine:

    def test_collects_inline_scripts(self):
        arts = _artifacts(scripts=[_inline("var x = 1;")])
        col = _COLLECTOR.collect(arts)
        assert len(col.inline_scripts) == 1

    def test_collects_external_scripts(self):
        arts = _artifacts(scripts=[_external("https://cdn.example.com/lib.js")])
        col = _COLLECTOR.collect(arts)
        assert len(col.external_scripts) == 1

    def test_inline_script_has_hash(self):
        arts = _artifacts(scripts=[_inline("var x = 1;")])
        col = _COLLECTOR.collect(arts)
        h = col.inline_scripts[0].content_hash
        assert len(h) == 64  # SHA-256 hex

    def test_external_script_has_hash(self):
        src = "https://cdn.example.com/lib.js"
        arts = _artifacts(scripts=[_external(src)])
        col = _COLLECTOR.collect(arts)
        h = col.external_scripts[0].content_hash
        assert len(h) == 64

    def test_deduplicates_identical_inline_scripts(self):
        arts = _artifacts(scripts=[
            _inline("var x = 1;"),
            _inline("var x = 1;"),
        ])
        col = _COLLECTOR.collect(arts)
        assert len(col.inline_scripts) == 1

    def test_deduplicates_identical_external_urls(self):
        src = "https://cdn.example.com/lib.js"
        arts = _artifacts(scripts=[_external(src), _external(src)])
        col = _COLLECTOR.collect(arts)
        assert len(col.external_scripts) == 1

    def test_different_inline_scripts_both_collected(self):
        arts = _artifacts(scripts=[
            _inline("var x = 1;"),
            _inline("var y = 2;"),
        ])
        col = _COLLECTOR.collect(arts)
        assert len(col.inline_scripts) == 2

    def test_identifies_third_party_script(self):
        arts = _artifacts(scripts=[_external("https://evil.xyz/track.js", same_domain=False)])
        col = _COLLECTOR.collect(arts)
        assert col.third_party_scripts

    def test_identifies_first_party_script(self):
        arts = _artifacts(scripts=[_external("https://example.com/app.js", same_domain=True)])
        col = _COLLECTOR.collect(arts)
        assert not col.third_party_scripts

    def test_external_script_has_domain(self):
        arts = _artifacts(scripts=[_external("https://cdn.third.com/lib.js")])
        col = _COLLECTOR.collect(arts)
        assert col.external_scripts[0].domain == "cdn.third.com"

    def test_empty_page_no_scripts(self):
        arts = _artifacts()
        col = _COLLECTOR.collect(arts)
        assert col.scripts == []

    def test_inline_scripts_are_inline(self):
        arts = _artifacts(scripts=[_inline("alert(1)")])
        col = _COLLECTOR.collect(arts)
        assert col.inline_scripts[0].is_inline is True
        assert col.inline_scripts[0].is_external is False

    def test_third_party_domains_property(self):
        arts = _artifacts(scripts=[
            _external("https://cdn.evil.tk/a.js", same_domain=False),
            _external("https://analytics.foo.com/b.js", same_domain=False),
        ])
        col = _COLLECTOR.collect(arts)
        domains = col.third_party_domains
        assert "cdn.evil.tk" in domains
        assert "analytics.foo.com" in domains


# ===========================================================================
# TestJsAnalyzerEngine
# ===========================================================================

class TestJsAnalyzerEngine:

    def test_detects_eval_call(self):
        arts = _artifacts(scripts=[_inline("eval(userInput)")])
        findings = _ANALYZER.analyze(arts)
        assert any("eval" in f.title.lower() for f in findings)

    def test_eval_finding_is_low(self):
        arts = _artifacts(scripts=[_inline("eval('test')")])
        findings = _ANALYZER.analyze(arts)
        ev = [f for f in findings if "eval" in f.title.lower()]
        assert ev[0].severity == Severity.LOW

    def test_detects_new_function(self):
        arts = _artifacts(scripts=[_inline("var f = new Function('return 1')")])
        findings = _ANALYZER.analyze(arts)
        assert any("builds functions from strings" in f.title.lower() for f in findings)

    def test_new_function_is_medium(self):
        arts = _artifacts(scripts=[_inline("new Function(code)()")])
        findings = _ANALYZER.analyze(arts)
        nf = [f for f in findings if "builds functions from strings" in f.title.lower()]
        assert nf[0].severity == Severity.MEDIUM

    def test_detects_document_write(self):
        arts = _artifacts(scripts=[_inline("document.write('<b>hi</b>')")])
        findings = _ANALYZER.analyze(arts)
        assert any("document.write" in f.title.lower() for f in findings)

    def test_detects_innerhtml_assignment(self):
        arts = _artifacts(scripts=[_inline("el.innerHTML = userInput")])
        findings = _ANALYZER.analyze(arts)
        assert any("innerhtml" in f.title.lower() for f in findings)

    def test_detects_atob_call(self):
        arts = _artifacts(scripts=[_inline("var data = atob(encoded)")])
        findings = _ANALYZER.analyze(arts)
        assert any("atob" in f.title.lower() for f in findings)

    def test_detects_cookie_access(self):
        arts = _artifacts(scripts=[_inline("var c = document.cookie")])
        findings = _ANALYZER.analyze(arts)
        assert any("cookie" in f.title.lower() for f in findings)

    def test_detects_local_storage(self):
        arts = _artifacts(scripts=[_inline("localStorage.setItem('token', val)")])
        findings = _ANALYZER.analyze(arts)
        assert any("localstorage" in f.title.lower() for f in findings)

    def test_local_storage_is_info(self):
        arts = _artifacts(scripts=[_inline("localStorage.getItem('x')")])
        findings = _ANALYZER.analyze(arts)
        ls = [f for f in findings if "localstorage" in f.title.lower()]
        assert ls[0].severity == Severity.INFO

    def test_detects_location_redirect(self):
        arts = _artifacts(scripts=[_inline("window.location.href = url")])
        findings = _ANALYZER.analyze(arts)
        assert any("redirect" in f.title.lower() for f in findings)

    def test_detects_form_action_manipulation(self):
        arts = _artifacts(scripts=[_inline("form.action = attackerUrl")])
        findings = _ANALYZER.analyze(arts)
        assert any("submit destination" in f.title.lower() for f in findings)

    def test_form_action_is_medium(self):
        arts = _artifacts(scripts=[_inline("document.forms[0].action = x")])
        findings = _ANALYZER.analyze(arts)
        fa = [f for f in findings if "submit destination" in f.title.lower()]
        assert fa[0].severity == Severity.MEDIUM

    def test_clean_script_no_risky_findings(self):
        arts = _artifacts(scripts=[_inline("var x = 1 + 2; console.log(x);")])
        findings = _ANALYZER.analyze(arts)
        assert findings == []

    def test_no_inline_scripts_no_findings(self):
        arts = _artifacts(scripts=[_external("https://cdn.example.com/lib.js")])
        findings = _ANALYZER.analyze(arts)
        assert findings == []

    def test_finding_category_is_javascript(self):
        arts = _artifacts(scripts=[_inline("eval(x)")])
        findings = _ANALYZER.analyze(arts)
        assert all(f.category == FindingCategory.JAVASCRIPT for f in findings)

    def test_finding_has_evidence(self):
        arts = _artifacts(scripts=[_inline("eval(x)")])
        findings = _ANALYZER.analyze(arts)
        assert findings[0].evidence
        assert findings[0].evidence[0].evidence_type == EvidenceType.JAVASCRIPT

    def test_finding_has_remediation(self):
        arts = _artifacts(scripts=[_inline("eval(x)")])
        findings = _ANALYZER.analyze(arts)
        assert findings[0].remediation

    def test_deduplication_same_pattern_same_script(self):
        arts = _artifacts(scripts=[_inline("eval(a); eval(b); eval(c);")])
        findings = _ANALYZER.analyze(arts)
        eval_findings = [f for f in findings if "eval" in f.title.lower() and "multiple" not in f.title.lower()]
        assert len(eval_findings) == 1


# ===========================================================================
# TestObfuscationDetectorEngine
# ===========================================================================

class TestObfuscationDetectorEngine:

    def test_detects_large_base64_blob(self):
        # 90 valid base64 characters
        blob = "A" * 80 + "BCDEF===="
        script = f"var data = '{blob}';"
        arts = _artifacts(scripts=[_inline(script)])
        findings = _OBFUSCATION.analyze(arts)
        assert any("base64" in f.title.lower() for f in findings)

    def test_large_base64_finding_is_medium(self):
        blob = "Z" * 85
        arts = _artifacts(scripts=[_inline(f"atob('{blob}')")])
        findings = _OBFUSCATION.analyze(arts)
        b64 = [f for f in findings if "base64" in f.title.lower()]
        assert b64[0].severity == Severity.MEDIUM

    def test_short_base64_no_finding(self):
        arts = _artifacts(scripts=[_inline("var id = 'dGVzdA==';")])  # only 8 base64 chars
        findings = _OBFUSCATION.analyze(arts)
        assert not any("base64" in f.title.lower() for f in findings)

    def test_detects_hex_escape_run(self):
        hex_run = "".join(f"\\x{i:02x}" for i in range(10))  # 10 consecutive escapes
        arts = _artifacts(scripts=[_inline(f"var s = '{hex_run}';")])
        findings = _OBFUSCATION.analyze(arts)
        assert any("hex" in f.title.lower() for f in findings)

    def test_hex_escape_finding_is_medium(self):
        hex_run = "".join(f"\\x{i:02x}" for i in range(12))
        arts = _artifacts(scripts=[_inline(f"var s = '{hex_run}';")])
        findings = _OBFUSCATION.analyze(arts)
        hx = [f for f in findings if "hex" in f.title.lower()]
        assert hx[0].severity == Severity.MEDIUM

    def test_few_hex_escapes_no_finding(self):
        arts = _artifacts(scripts=[_inline("var nl = '\\x0a';")])  # only 1 escape
        findings = _OBFUSCATION.analyze(arts)
        assert not any("hex" in f.title.lower() for f in findings)

    def test_detects_packer_pattern(self):
        packed = "eval(function(p,a,c,k,e,d){return 'test'})"
        arts = _artifacts(scripts=[_inline(packed)])
        findings = _OBFUSCATION.analyze(arts)
        assert any("packer" in f.title.lower() for f in findings)

    def test_packer_finding_is_high(self):
        packed = "eval(function(p,a,c,k,e,d){return p})"
        arts = _artifacts(scripts=[_inline(packed)])
        findings = _OBFUSCATION.analyze(arts)
        pk = [f for f in findings if "packer" in f.title.lower()]
        assert pk[0].severity == Severity.HIGH

    def test_detects_multiple_evals(self):
        script = "eval(a); eval(b); eval(c); eval(d); eval(e);"  # 5+ (threshold)
        arts = _artifacts(scripts=[_inline(script)])
        findings = _OBFUSCATION.analyze(arts)
        assert any("calls eval" in f.title.lower() for f in findings)

    def test_multiple_evals_finding_is_high(self):
        script = "eval(v); eval(w); eval(x); eval(y); eval(z);"  # 5+ (threshold)
        arts = _artifacts(scripts=[_inline(script)])
        findings = _OBFUSCATION.analyze(arts)
        multi = [f for f in findings if "calls eval" in f.title.lower()]
        assert multi[0].severity == Severity.HIGH

    def test_high_entropy_script_flagged(self):
        # Construct a high-entropy script (mixed random-looking chars)
        import random, string
        rng = random.Random(42)
        chars = string.printable
        high_entropy_content = "".join(rng.choice(chars) for _ in range(600))
        arts = _artifacts(scripts=[_inline(high_entropy_content)])
        findings = _OBFUSCATION.analyze(arts)
        assert any("random-looking" in f.title.lower() for f in findings)

    def test_normal_script_no_obfuscation_finding(self):
        arts = _artifacts(scripts=[_inline(
            "function greet(name) { return 'Hello, ' + name; }"
        )])
        findings = _OBFUSCATION.analyze(arts)
        assert findings == []

    def test_no_inline_scripts_no_findings(self):
        arts = _artifacts()
        findings = _OBFUSCATION.analyze(arts)
        assert findings == []

    def test_finding_category_is_javascript(self):
        blob = "B" * 85
        arts = _artifacts(scripts=[_inline(f"var x='{blob}';")])
        findings = _OBFUSCATION.analyze(arts)
        assert all(f.category == FindingCategory.JAVASCRIPT for f in findings)


# ===========================================================================
# TestThirdPartyDomainEngine
# ===========================================================================

class TestThirdPartyDomainEngine:

    def test_first_party_no_finding(self):
        arts = _artifacts(
            url="https://example.com/",
            scripts=[_external("https://example.com/app.js", same_domain=True)],
        )
        findings = _THIRD_PARTY.analyze(arts)
        assert not any(f.category == FindingCategory.JAVASCRIPT for f in findings
                       if "third-party" in f.title.lower())

    def test_no_external_scripts_no_findings(self):
        arts = _artifacts(scripts=[_inline("var x = 1;")])
        findings = _THIRD_PARTY.analyze(arts)
        assert findings == []

    def test_unknown_third_party_is_low(self):
        arts = _artifacts(scripts=[_external("https://unknown-tracker.com/t.js")])
        findings = _THIRD_PARTY.analyze(arts)
        assert findings
        assert findings[0].severity == Severity.LOW

    def test_risky_tld_is_medium(self):
        arts = _artifacts(scripts=[_external("https://scripts.tk/payload.js")])
        findings = _THIRD_PARTY.analyze(arts)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_another_risky_tld_xyz_is_medium(self):
        arts = _artifacts(scripts=[_external("https://cdn.evil.xyz/lib.js")])
        findings = _THIRD_PARTY.analyze(arts)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_known_cdn_no_finding(self):
        # googleapis.com is in the trusted list
        arts = _artifacts(scripts=[
            _external("https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js")
        ])
        findings = _THIRD_PARTY.analyze(arts)
        # Trusted CDN -> no domain-trust finding (a missing-SRI finding is
        # expected and separate).
        assert not any("loads a script from" in f.title.lower() for f in findings)

    def test_random_looking_domain_is_medium(self):
        # xkq3mpzv has no vowels and length >= 8
        arts = _artifacts(scripts=[_external("https://xkq3mpzv.com/t.js")])
        findings = _THIRD_PARTY.analyze(arts)
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_external_form_action_is_medium(self):
        form = ExtractedForm(
            action="https://evil.example.net/collect",
            action_url="https://evil.example.net/collect",
            method="POST",
            inputs=(),
            has_password_field=True,
            has_csrf_token=False,
        )
        arts = _artifacts(forms=[form])
        findings = _THIRD_PARTY.analyze(arts)
        assert any("form" in f.title.lower() and f.severity == Severity.MEDIUM for f in findings)

    def test_internal_form_action_no_finding(self):
        form = ExtractedForm(
            action="/submit",
            action_url="https://example.com/submit",
            method="POST",
            inputs=(),
            has_password_field=False,
            has_csrf_token=True,
        )
        arts = _artifacts(forms=[form])
        findings = _THIRD_PARTY.analyze(arts)
        assert not any("form" in f.title.lower() for f in findings)

    def test_finding_has_evidence(self):
        arts = _artifacts(scripts=[_external("https://unknown-domain.com/t.js")])
        findings = _THIRD_PARTY.analyze(arts)
        assert findings[0].evidence

    def test_finding_has_owasp_alignment(self):
        arts = _artifacts(scripts=[_external("https://bad.tk/x.js")])
        findings = _THIRD_PARTY.analyze(arts)
        assert findings[0].framework.owasp_top10

    def test_deduplicates_same_domain_multiple_scripts(self):
        arts = _artifacts(scripts=[
            _external("https://tracker.io/a.js"),
            _external("https://tracker.io/b.js"),
        ])
        findings = _THIRD_PARTY.analyze(arts)
        # Should produce one finding per domain, not per script
        domain_findings = [f for f in findings if "tracker.io" in f.title]
        assert len(domain_findings) == 1


# ===========================================================================
# TestTechnologyEngine
# ===========================================================================

class TestTechnologyEngine:

    def test_detects_wordpress_from_meta(self):
        arts = _artifacts(meta_tags={"generator": "WordPress 6.3"})
        findings = _TECH.analyze(arts)
        assert any("wordpress" in f.title.lower() for f in findings)

    def test_detects_wordpress_from_script_path(self):
        arts = _artifacts(scripts=[
            _external("https://example.com/wp-content/themes/my-theme/app.js", same_domain=True)
        ])
        findings = _TECH.analyze(arts)
        assert any("wordpress" in f.title.lower() for f in findings)

    def test_detects_shopify_from_meta(self):
        arts = _artifacts(meta_tags={"generator": "Shopify"})
        findings = _TECH.analyze(arts)
        assert any("shopify" in f.title.lower() for f in findings)

    def test_detects_shopify_from_header(self):
        arts = _artifacts(response_headers={"x-shopify-stage": "production"})
        findings = _TECH.analyze(arts)
        assert any("shopify" in f.title.lower() for f in findings)

    def test_detects_wix_from_meta(self):
        arts = _artifacts(meta_tags={"generator": "Wix.com Website Builder"})
        findings = _TECH.analyze(arts)
        assert any("wix" in f.title.lower() for f in findings)

    def test_detects_drupal_from_header(self):
        arts = _artifacts(response_headers={"x-drupal-cache": "MISS"})
        findings = _TECH.analyze(arts)
        assert any("drupal" in f.title.lower() for f in findings)

    def test_detects_joomla_from_meta(self):
        arts = _artifacts(meta_tags={"generator": "Joomla! 4.2"})
        findings = _TECH.analyze(arts)
        assert any("joomla" in f.title.lower() for f in findings)

    def test_detects_cloudflare_from_cf_ray(self):
        arts = _artifacts(response_headers={"cf-ray": "abc123-LHR"})
        findings = _TECH.analyze(arts)
        assert any("cloudflare" in f.title.lower() for f in findings)

    def test_detects_cloudfront_from_header(self):
        arts = _artifacts(response_headers={"x-amz-cf-id": "EXAMPLE123=="})
        findings = _TECH.analyze(arts)
        assert any("cloudfront" in f.title.lower() for f in findings)

    def test_detects_fastly_from_header(self):
        arts = _artifacts(response_headers={"x-fastly-request-id": "abc123"})
        findings = _TECH.analyze(arts)
        assert any("fastly" in f.title.lower() for f in findings)

    def test_detects_jquery_from_script(self):
        arts = _artifacts(scripts=[
            _external("https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js")
        ])
        findings = _TECH.analyze(arts)
        assert any("jquery" in f.title.lower() for f in findings)

    def test_detects_react_from_script(self):
        arts = _artifacts(scripts=[
            _external("https://unpkg.com/react.min.js")
        ])
        findings = _TECH.analyze(arts)
        assert any("react" in f.title.lower() for f in findings)

    def test_detects_bootstrap_from_script(self):
        arts = _artifacts(scripts=[
            _external("https://cdn.jsdelivr.net/npm/bootstrap.min.js")
        ])
        findings = _TECH.analyze(arts)
        assert any("bootstrap" in f.title.lower() for f in findings)

    def test_detects_server_version_disclosure(self):
        arts = _artifacts(response_headers={"server": "Apache/2.4.48 (Ubuntu)"})
        findings = _TECH.analyze(arts)
        version = [f for f in findings if "exact version" in f.title.lower()]
        assert version
        assert version[0].severity == Severity.LOW

    def test_detects_xpoweredby_version_disclosure(self):
        arts = _artifacts(response_headers={"x-powered-by": "PHP/7.4.3"})
        findings = _TECH.analyze(arts)
        version = [f for f in findings if "exact version" in f.title.lower()]
        assert version
        assert version[0].severity == Severity.LOW

    def test_server_header_without_version_is_info(self):
        arts = _artifacts(response_headers={"server": "nginx"})
        findings = _TECH.analyze(arts)
        info_srv = [f for f in findings if "server" in f.title.lower() or "nginx" in f.title.lower()]
        assert info_srv
        assert all(f.severity == Severity.INFO for f in info_srv)

    def test_no_technology_hints_no_findings(self):
        arts = _artifacts()
        findings = _TECH.analyze(arts)
        assert findings == []

    def test_technology_finding_category(self):
        arts = _artifacts(meta_tags={"generator": "WordPress 6.3"})
        findings = _TECH.analyze(arts)
        assert all(f.category == FindingCategory.TECHNOLOGY for f in findings)

    def test_wordpress_finding_is_info(self):
        arts = _artifacts(meta_tags={"generator": "WordPress"})
        findings = _TECH.analyze(arts)
        wp = [f for f in findings if "wordpress" in f.title.lower()]
        assert wp[0].severity == Severity.INFO

    def test_finding_has_evidence(self):
        arts = _artifacts(meta_tags={"generator": "Shopify"})
        findings = _TECH.analyze(arts)
        assert findings[0].evidence
