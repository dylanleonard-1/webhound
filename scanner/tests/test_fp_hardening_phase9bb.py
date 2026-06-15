# WebHound — scanner/tests/test_fp_hardening_phase9bb.py
# Phase 9B-B detection-hardening tests.
#
# EVERY change in this file has a matching BEFORE comment (what the engine did
# before the fix) and AFTER comment (what it does after).  The test names make
# the before/after contract explicit so a future reader never has to guess which
# behaviour is intentional.
#
# Safe-mode: all tests use synthetic data — no HTTP, no DNS, no network.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import pytest

from uuid import uuid4

from webhound.engines.javascript.obfuscation_detector import ObfuscationDetectorEngine
from webhound.engines.tls_dns.tls_checker import TlsCheckerEngine, TlsCertInfo
from webhound.engines.cookies.cookie_scanner import CookieScannerEngine
from webhound.threat_intel.domain_classifier import DomainClass, DomainClassifier
from webhound.core.extractor import ExtractedScript, PageArtifacts
from webhound.core.http_client import HttpResponse
from webhound.models.severity import Severity

_OBFUSCATION = ObfuscationDetectorEngine()
_TLS = TlsCheckerEngine()
_COOKIES = CookieScannerEngine()
_CLASSIFIER = DomainClassifier()
_NOW = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Helpers — constructors match actual classes
# ---------------------------------------------------------------------------

def _inline(content: str) -> ExtractedScript:
    return ExtractedScript(
        src=None,
        content=content,
        is_inline=True,
        is_external=False,
        is_external_domain=False,
    )


def _artifacts(scripts: list | None = None) -> PageArtifacts:
    _scripts = scripts or []
    return PageArtifacts(
        url="https://example.com/",
        status_code=200,
        content_type="text/html",
        title="Test",
        all_links=[],
        internal_links=[],
        external_links=[],
        scripts=_scripts,
        inline_scripts=[s.content for s in _scripts if s.is_inline and s.content],
        external_script_urls=[s.src for s in _scripts if s.is_external and s.src],
        forms=[],
        cookies=[],
        response_headers={},
        meta_tags={},
        extracted_at=_NOW,
    )


def _cert(
    domain: str = "example.com",
    *,
    issuer_o: str | None = None,
    issuer_cn: str | None = None,
    is_expired: bool = False,
    protocol_version: str | None = None,
    not_after: datetime | None = None,
) -> TlsCertInfo:
    return TlsCertInfo(
        domain=domain,
        issuer_o=issuer_o,
        issuer_cn=issuer_cn,
        is_expired=is_expired,
        protocol_version=protocol_version,
        not_after=not_after,
    )


def _http_response(url: str, headers: dict) -> HttpResponse:
    return HttpResponse(
        request_id=uuid4(),
        original_url=url,
        url=url,
        status_code=200,
        headers=headers,
        body="<html></html>",
        content_type="text/html",
        elapsed_ms=10.0,
        redirect_count=0,
        redirect_chain=[],
        captured_at=_NOW,
    )


# =============================================================================
# FP Fix 1 — obfuscation_detector: packer bare-definition FP
# =============================================================================


class TestPackerFPHardening:
    """Packer FP fix: require pipe-encoded payload string adjacent to signature.

    BEFORE: eval(function(p,a,c,k,e,...){...}) fired regardless of whether
            a packed string argument was present (bare function definition FPs).
    AFTER:  Only fires when a pipe-separated token string (≥5 pipes) exists
            within 2000 chars of the packer signature.
    """

    # -- Before (now prevented) --

    def test_bare_packer_definition_does_not_fire(self):
        """BEFORE: would fire. AFTER: bare packer template → no finding."""
        bare = "eval(function(p,a,c,k,e,r){/* template only, no payload */})"
        arts = _artifacts(scripts=[_inline(bare)])
        findings = _OBFUSCATION.analyze(arts)
        packer_findings = [f for f in findings if "packer" in f.title.lower()]
        assert not packer_findings, (
            "bare packer function definition (no encoded payload) must not fire — "
            "this was the main FP source"
        )

    def test_packer_with_few_pipes_does_not_fire(self):
        """BEFORE: would fire. AFTER: <5 pipe separators → no finding."""
        # Only 2 pipes — looks like packer but not a real token dictionary
        near_miss = (
            "eval(function(p,a,c,k,e,r){return p}"
            "('hello|world|foo',3,3,'',0,{}))"
        )
        arts = _artifacts(scripts=[_inline(near_miss)])
        findings = _OBFUSCATION.analyze(arts)
        packer_findings = [f for f in findings if "packer" in f.title.lower()]
        assert not packer_findings, (
            "2-pipe token list is not enough to confirm a genuine packed payload"
        )

    # -- After (detection preserved for genuine packed code) --

    def test_genuine_packed_payload_fires(self):
        """AFTER: genuine Dean Edwards packed output still fires."""
        genuine = (
            "eval(function(p,a,c,k,e,d){e=function(c){return c};"
            "return p}('0 1 2 3 4 5',6,6,'function|hello|name|return|var|log'.split('|'),0,{}))"
        )
        arts = _artifacts(scripts=[_inline(genuine)])
        findings = _OBFUSCATION.analyze(arts)
        assert any("packer" in f.title.lower() for f in findings), (
            "genuine packed payload (6-token dictionary) must still fire"
        )

    def test_genuine_packer_finding_is_high_severity(self):
        """AFTER: severity is preserved for genuine packed payloads."""
        genuine = (
            "eval(function(p,a,c,k,e,d){return p}"
            "('a|b|c|d|e|f|g',7,7,'a|b|c|d|e|f|g'.split('|'),0,{}))"
        )
        arts = _artifacts(scripts=[_inline(genuine)])
        findings = _OBFUSCATION.analyze(arts)
        packer = [f for f in findings if "packer" in f.title.lower()]
        assert packer, "packer finding must exist"
        assert packer[0].severity == Severity.HIGH

    def test_packer_large_token_dictionary_fires(self):
        """AFTER: large pipe-separated payload (real-world packed bundle) fires."""
        # Simulate a real-world packed script with a large token list
        tokens = "|".join([f"tok{i}" for i in range(20)])  # 19 pipes
        payload = f"eval(function(p,a,c,k,e,d){{return p}}('{tokens}',20,20,'',0,{{}}))"
        arts = _artifacts(scripts=[_inline(payload)])
        findings = _OBFUSCATION.analyze(arts)
        assert any("packer" in f.title.lower() for f in findings)

    def test_packer_no_finding_when_no_inline_scripts(self):
        """Unchanged: no inline scripts → no finding."""
        arts = _artifacts(scripts=[])
        findings = _OBFUSCATION.analyze(arts)
        assert not any("packer" in f.title.lower() for f in findings)


# =============================================================================
# FP Fix 2 — domain_classifier: shared hosting platform FP
# =============================================================================


class TestSharedHostingFPHardening:
    """Shared-hosting FP fix: added major hosting platforms to trusted/benign lists.

    BEFORE: Known hosting platforms not in the allowlists could accumulate
            heuristic signals (suspicious keyword in subdomain, risky TLD)
            and reach RISKY or MALICIOUS_INDICATOR.
    AFTER:  Registerable domains of the hosting platforms are in _TRUSTED_DOMAINS
            so subdomains are fast-pathed to TRUSTED regardless of subdomain content.
    """

    # -- After (FP eliminated for known hosting platforms) --

    def test_wpengine_subdomain_is_trusted(self):
        """AFTER: WP Engine customer subdomains are TRUSTED (was potentially RISKY)."""
        result = _CLASSIFIER.classify("login-portal.wpengine.com")
        assert result.classification in (DomainClass.TRUSTED, DomainClass.COMMON_BENIGN), (
            f"wpengine.com subdomain got {result.classification!r} — expected TRUSTED/BENIGN"
        )

    def test_kinsta_subdomain_is_trusted(self):
        """AFTER: Kinsta customer subdomains are TRUSTED."""
        result = _CLASSIFIER.classify("mysite.kinsta.com")
        assert result.classification in (DomainClass.TRUSTED, DomainClass.COMMON_BENIGN)

    def test_digitalocean_app_is_trusted(self):
        """AFTER: DigitalOcean App Platform is TRUSTED."""
        result = _CLASSIFIER.classify("myapp.digitalocean.app")
        assert result.classification in (DomainClass.TRUSTED, DomainClass.COMMON_BENIGN)

    def test_replit_subdomain_is_trusted(self):
        """AFTER: Replit.com deployments are TRUSTED."""
        result = _CLASSIFIER.classify("project.replit.com")
        assert result.classification in (DomainClass.TRUSTED, DomainClass.COMMON_BENIGN)

    def test_glitch_me_subdomain_is_trusted(self):
        """AFTER: Glitch.me projects are TRUSTED."""
        result = _CLASSIFIER.classify("my-project.glitch.me")
        assert result.classification in (DomainClass.TRUSTED, DomainClass.COMMON_BENIGN)

    def test_hetzner_hosting_is_trusted(self):
        """AFTER: Hetzner Cloud IPs/subdomains are TRUSTED."""
        result = _CLASSIFIER.classify("myserver.hetzner.com")
        assert result.classification in (DomainClass.TRUSTED, DomainClass.COMMON_BENIGN)

    # -- True positives preserved --

    def test_brand_lookalike_on_risky_tld_still_fires(self):
        """AFTER: genuine lookalike + risky TLD still reaches RISKY or MALICIOUS_INDICATOR."""
        result = _CLASSIFIER.classify("paypal-login-secure.tk")
        assert result.classification in (DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR), (
            "brand-lookalike + risky TLD must still be flagged"
        )

    def test_dga_looking_domain_still_risky(self):
        """AFTER: DGA/machine-generated label still reaches SUSPICIOUS+."""
        result = _CLASSIFIER.classify("xk7q2mfbn.xyz")
        assert result.classification in (
            DomainClass.SUSPICIOUS, DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR
        )

    def test_unknown_clean_domain_is_unknown(self):
        """Baseline: a clean, unknown domain stays UNKNOWN (no regression)."""
        result = _CLASSIFIER.classify("mycleansite.com")
        assert result.classification == DomainClass.UNKNOWN

    def test_cloudflare_still_trusted(self):
        """Sanity: cloudflare.com stays TRUSTED (no regression to existing list)."""
        result = _CLASSIFIER.classify("cdn.cloudflare.com")
        assert result.classification == DomainClass.TRUSTED


# =============================================================================
# FP Fix 3 — tls_checker: CDN certificate annotation
# =============================================================================


class TestTlsCDNAnnotation:
    """CDN certificate annotation: findings now note when cert is CDN-issued.

    BEFORE: cert_expired and weak_protocol findings said nothing about whether
            the observed certificate belongs to a CDN edge (not the origin).
    AFTER:  When the cert issuer indicates a CDN provider (Cloudflare, Amazon,
            Fastly, etc.) the finding description includes a note stating that
            only the CDN-layer certificate was observed.
    """

    # -- After (CDN note present for CDN-issued certs) --

    def test_cloudflare_issued_expired_cert_has_cdn_note(self):
        """AFTER: cert_expired finding on Cloudflare-issued cert includes CDN note."""
        cert = _cert(
            "example.com",
            issuer_o="Cloudflare, Inc.",
            is_expired=True,
        )
        findings = _TLS.analyze(cert)
        expired = [f for f in findings if "expired" in f.title.lower()]
        assert expired, "cert_expired finding must exist"
        assert "cdn" in expired[0].description.lower() or "cloudflare" in expired[0].description.lower(), (
            "CDN-issued expired cert should note CDN-termination in description"
        )

    def test_amazon_issued_cert_expired_has_cdn_note(self):
        """AFTER: cert_expired finding on Amazon-issued cert includes CDN note."""
        cert = _cert(
            "example.com",
            issuer_o="Amazon",
            is_expired=True,
        )
        findings = _TLS.analyze(cert)
        expired = [f for f in findings if "expired" in f.title.lower()]
        assert expired
        assert "cdn" in expired[0].description.lower() or "amazon" in expired[0].description.lower()

    def test_cloudflare_weak_protocol_has_cdn_note(self):
        """AFTER: weak_protocol finding on Cloudflare-issued cert includes CDN note."""
        cert = _cert(
            "example.com",
            issuer_o="Cloudflare, Inc.",
            protocol_version="TLSv1.1",
        )
        findings = _TLS.analyze(cert)
        weak = [f for f in findings if "obsolete" in f.title.lower()]
        assert weak, "weak_protocol finding must exist"
        desc = weak[0].description.lower()
        assert "cdn" in desc or "cloudflare" in desc, (
            "Cloudflare-issued weak-protocol finding must note CDN termination"
        )

    def test_fastly_issued_cert_expired_has_cdn_note(self):
        """AFTER: Fastly-issued cert in expired finding includes CDN note."""
        cert = _cert("example.com", issuer_o="Fastly, Inc.", is_expired=True)
        findings = _TLS.analyze(cert)
        expired = [f for f in findings if "expired" in f.title.lower()]
        assert expired
        desc = expired[0].description.lower()
        assert "cdn" in desc or "fastly" in desc

    # -- Before (no note for non-CDN issuers) --

    def test_non_cdn_issuer_no_cdn_note_in_expired(self):
        """BEFORE/AFTER unchanged: non-CDN issuer cert does not add CDN note."""
        cert = _cert("example.com", issuer_o="My Company CA", is_expired=True)
        findings = _TLS.analyze(cert)
        expired = [f for f in findings if "expired" in f.title.lower()]
        assert expired, "cert_expired must still fire"
        assert "cdn-terminated" not in expired[0].description.lower(), (
            "non-CDN issuer must not trigger the CDN annotation"
        )

    def test_cdn_note_not_added_when_cert_ok(self):
        """Sanity: a valid Cloudflare cert produces no expired finding at all."""
        cert = _cert("example.com", issuer_o="Cloudflare, Inc.", is_expired=False)
        findings = _TLS.analyze(cert)
        expired = [f for f in findings if "expired" in f.title.lower()]
        assert not expired


# =============================================================================
# FP Fix 4 — cookie_scanner: passive-analysis disclaimer
# =============================================================================


class TestCookiePassiveAnalysisDisclaimer:
    """Cookie passive-analysis disclaimer.

    BEFORE: missing_httponly and missing_secure findings said nothing about
            the scope of the analysis (Set-Cookie headers only, not JS cookies).
    AFTER:  Both findings include an explicit note stating that WebHound only
            inspects Set-Cookie response headers and does not analyze cookies
            created via document.cookie.
    """

    def test_httponly_finding_has_passive_analysis_note(self):
        """AFTER: missing_httponly description includes passive-analysis note."""
        resp = _http_response(
            "https://example.com/",
            {"Set-Cookie": "session=abc123; SameSite=Lax"},
        )
        findings = _COOKIES.analyze(resp)
        httponly = [f for f in findings if "httponly" in f.title.lower()]
        assert httponly, "missing_httponly finding must fire"
        desc = httponly[0].description.lower()
        assert "set-cookie" in desc or "header" in desc or "passive" in desc, (
            "missing_httponly must mention Set-Cookie / header / passive scope"
        )

    def test_secure_finding_has_passive_analysis_note(self):
        """AFTER: missing_secure description includes passive-analysis note."""
        resp = _http_response(
            "https://example.com/",
            {"Set-Cookie": "session=abc123; HttpOnly; SameSite=Lax"},
        )
        findings = _COOKIES.analyze(resp)
        secure = [f for f in findings if "secure flag" in f.title.lower() or "missing the secure" in f.title.lower()]
        assert secure, "missing_secure finding must fire"
        desc = secure[0].description.lower()
        assert "set-cookie" in desc or "header" in desc or "passive" in desc, (
            "missing_secure must mention Set-Cookie / header / passive scope"
        )

    def test_httponly_note_mentions_javascript(self):
        """AFTER: missing_httponly description mentions document.cookie / JavaScript."""
        resp = _http_response(
            "https://example.com/",
            {"Set-Cookie": "pref=dark; SameSite=Lax"},
        )
        findings = _COOKIES.analyze(resp)
        httponly = [f for f in findings if "httponly" in f.title.lower()]
        assert httponly
        assert "javascript" in httponly[0].description.lower() or "document.cookie" in httponly[0].description.lower()

    def test_httponly_still_fires_for_real_missing_flag(self):
        """Unchanged: missing HttpOnly still produces a finding."""
        resp = _http_response(
            "https://example.com/",
            {"Set-Cookie": "auth_token=xyz; Secure; SameSite=Lax"},
        )
        findings = _COOKIES.analyze(resp)
        assert any("httponly" in f.title.lower() for f in findings)

    def test_secure_still_fires_for_real_missing_flag(self):
        """Unchanged: missing Secure on HTTPS page still produces a finding."""
        resp = _http_response(
            "https://example.com/",
            {"Set-Cookie": "pref=dark; HttpOnly; SameSite=Lax"},
        )
        findings = _COOKIES.analyze(resp)
        assert any("secure flag" in f.title.lower() or "missing the secure" in f.title.lower() for f in findings)

    def test_cookie_with_both_flags_no_httponly_or_secure_finding(self):
        """Unchanged: a fully-attributed cookie produces no httponly/secure finding."""
        resp = _http_response(
            "https://example.com/",
            {"Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax"},
        )
        findings = _COOKIES.analyze(resp)
        assert not any("httponly" in f.title.lower() for f in findings)
        assert not any("secure flag" in f.title.lower() or "missing the secure" in f.title.lower() for f in findings)


# =============================================================================
# Regression suite — ensure no existing TP detections were broken
# =============================================================================


class TestRegressionNoBreakage:
    """Verify no true-positive detection was silently removed."""

    def test_hex_escape_run_still_fires(self):
        hex_run = "\\x65\\x76\\x61\\x6c\\x28\\x22\\x61\\x6c"  # 8 hex escapes
        arts = _artifacts(scripts=[_inline(hex_run)])
        findings = _OBFUSCATION.analyze(arts)
        assert any("hex" in f.title.lower() for f in findings)

    def test_multi_eval_still_fires(self):
        multi = "eval(a); eval(b); eval(c); eval(d); eval(e);"  # 5 calls
        arts = _artifacts(scripts=[_inline(multi)])
        findings = _OBFUSCATION.analyze(arts)
        assert any("calls eval" in f.title.lower() for f in findings)

    def test_malicious_lookalike_still_flagged(self):
        result = _CLASSIFIER.classify("paypal-security-verify.tk")
        assert result.classification in (DomainClass.RISKY, DomainClass.MALICIOUS_INDICATOR)

    def test_cookie_samesite_still_fires(self):
        resp = _http_response(
            "https://example.com/",
            {"Set-Cookie": "pref=dark; Secure; HttpOnly"},
        )
        findings = _COOKIES.analyze(resp)
        assert any("samesite" in f.title.lower() for f in findings)

    def test_cookie_none_without_secure_still_fires(self):
        resp = _http_response(
            "https://example.com/",
            {"Set-Cookie": "sid=abc; SameSite=None"},
        )
        findings = _COOKIES.analyze(resp)
        assert any("samesite=none" in f.title.lower() for f in findings)

    def test_tls_expiry_warning_still_fires(self):
        from datetime import timedelta
        cert = _cert(
            "example.com",
            issuer_o="Let's Encrypt",
            not_after=datetime.now(timezone.utc) + timedelta(days=10),
        )
        findings = _TLS.analyze(cert)
        assert any("expires" in f.title.lower() for f in findings)
