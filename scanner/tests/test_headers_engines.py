# WebHound — scanner/tests/test_headers_engines.py
# Tests for Phase 3: security_headers, cors, and cookie_scanner engines.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from webhound.core.http_client import HttpResponse
from webhound.engines.cookies.cookie_scanner import (
    CookieScannerEngine,
    ParsedCookie,
    parse_set_cookie,
)
from webhound.engines.headers.cors import CorsEngine
from webhound.engines.headers.security_headers import SecurityHeadersEngine
from webhound.models.finding import FindingCategory
from webhound.models.severity import Severity


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

_URL = "https://example.com/"
_URL_HTTP = "http://example.com/"


def _resp(
    url: str = _URL,
    headers: dict[str, str] | None = None,
    status: int = 200,
) -> HttpResponse:
    h = {"content-type": "text/html"}
    if headers:
        h.update({k.lower(): v for k, v in headers.items()})
    return HttpResponse(
        request_id=uuid4(),
        original_url=url,
        url=url,
        status_code=status,
        headers=h,
        body="<html></html>",
        content_type="text/html",
        elapsed_ms=50.0,
        redirect_count=0,
        redirect_chain=[],
        captured_at=datetime.now(timezone.utc),
    )


def _titles(findings) -> list[str]:
    return [f.title for f in findings]


def _by_title(findings, fragment: str):
    return [f for f in findings if fragment.lower() in f.title.lower()]


# ---------------------------------------------------------------------------
# SecurityHeadersEngine — missing headers
# ---------------------------------------------------------------------------


class TestSecurityHeadersMissing:
    E = SecurityHeadersEngine()

    def test_missing_csp_raises_finding(self):
        fs = self.E.analyze(_resp())
        assert any("Content-Security-Policy" in t for t in _titles(fs))

    def test_missing_csp_is_medium(self):
        fs = self.E.analyze(_resp())
        csp_findings = _by_title(fs, "No Content-Security-Policy")
        assert csp_findings
        assert csp_findings[0].severity == Severity.MEDIUM

    def test_missing_hsts_raises_finding_on_https(self):
        fs = self.E.analyze(_resp(_URL))
        assert any("HSTS" in t for t in _titles(fs))

    def test_missing_hsts_no_finding_on_http(self):
        fs = self.E.analyze(_resp(_URL_HTTP))
        assert not any("HSTS" in t for t in _titles(fs))

    def test_missing_hsts_is_medium(self):
        fs = self.E.analyze(_resp())
        hsts = _by_title(fs, "HSTS")
        assert hsts
        assert hsts[0].severity == Severity.MEDIUM

    def test_missing_x_frame_options_raises_finding(self):
        fs = self.E.analyze(_resp())
        assert any("clickjacking" in t for t in _titles(fs))

    def test_missing_x_frame_options_is_medium(self):
        fs = self.E.analyze(_resp())
        xfo = _by_title(fs, "clickjacking")
        assert xfo
        assert xfo[0].severity == Severity.MEDIUM

    def test_missing_xcto_raises_finding(self):
        fs = self.E.analyze(_resp())
        assert any("misinterpret file types" in t for t in _titles(fs))

    def test_missing_xcto_is_medium(self):
        fs = self.E.analyze(_resp())
        xcto = _by_title(fs, "misinterpret file types")
        assert xcto
        assert xcto[0].severity == Severity.MEDIUM

    def test_missing_referrer_policy_raises_finding(self):
        fs = self.E.analyze(_resp())
        assert any("Referrer-Policy" in t for t in _titles(fs))

    def test_fully_compliant_headers_produce_no_critical_findings(self):
        fs = self.E.analyze(_resp(headers={
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Resource-Policy": "same-origin",
        }))
        # All mandatory headers present — no critical or high findings expected
        assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in fs)


# ---------------------------------------------------------------------------
# SecurityHeadersEngine — CSP checks
# ---------------------------------------------------------------------------


class TestCSPChecks:
    E = SecurityHeadersEngine()

    def test_csp_with_unsafe_inline_is_medium(self):
        # audit #6: 'unsafe-inline' in script-src is a config weakness -> MEDIUM (was HIGH).
        fs = self.E.analyze(_resp(headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"
        }))
        unsafe = _by_title(fs, "inline scripts")
        assert unsafe
        assert unsafe[0].severity == Severity.MEDIUM

    def test_csp_unsafe_inline_only_in_style_src_not_flagged(self):
        # audit #6: 'unsafe-inline' in STYLE-src is not a script-XSS risk -> no script finding.
        fs = self.E.analyze(_resp(headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'"
        }))
        assert not _by_title(fs, "inline scripts")

    def test_csp_with_unsafe_eval_is_medium(self):
        fs = self.E.analyze(_resp(headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-eval'"
        }))
        ev = _by_title(fs, "allows eval")
        assert ev
        assert ev[0].severity == Severity.MEDIUM

    def test_csp_with_wildcard_src_is_high(self):
        fs = self.E.analyze(_resp(headers={
            "Content-Security-Policy": "default-src *"
        }))
        wc = _by_title(fs, "wildcard")
        assert wc
        assert wc[0].severity == Severity.HIGH

    def test_csp_without_default_src_is_medium(self):
        fs = self.E.analyze(_resp(headers={
            "Content-Security-Policy": "script-src 'self'"
        }))
        ds = _by_title(fs, "default fallback")
        assert ds
        assert ds[0].severity == Severity.MEDIUM

    def test_strict_csp_no_unsafe_findings(self):
        fs = self.E.analyze(_resp(headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self'"
        }))
        unsafe = [f for f in fs if "unsafe" in f.title.lower() or "wildcard" in f.title.lower()]
        assert not unsafe

    def test_csp_evidence_contains_header_value(self):
        fs = self.E.analyze(_resp(headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"
        }))
        unsafe = _by_title(fs, "inline scripts")
        assert unsafe
        assert any("unsafe-inline" in ev.content for ev in unsafe[0].evidence)


# ---------------------------------------------------------------------------
# SecurityHeadersEngine — HSTS checks
# ---------------------------------------------------------------------------


class TestHSTSChecks:
    E = SecurityHeadersEngine()

    def test_hsts_present_no_missing_finding(self):
        fs = self.E.analyze(_resp(headers={
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains"
        }))
        missing = _by_title(fs, "HSTS header missing")
        assert not missing

    def test_hsts_short_max_age_is_low(self):
        fs = self.E.analyze(_resp(headers={
            "Strict-Transport-Security": "max-age=3600"
        }))
        short = _by_title(fs, "max-age is below")
        assert short
        assert short[0].severity == Severity.LOW

    def test_hsts_missing_include_subdomains_is_info(self):
        fs = self.E.analyze(_resp(headers={
            "Strict-Transport-Security": "max-age=63072000"
        }))
        no_sub = _by_title(fs, "doesn't cover subdomains")
        assert no_sub
        assert no_sub[0].severity == Severity.INFO

    def test_hsts_full_compliance_no_findings(self):
        fs = self.E.analyze(_resp(headers={
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload"
        }))
        hsts_findings = [f for f in fs if "hsts" in f.title.lower() or "transport" in f.title.lower()]
        assert not hsts_findings


# ---------------------------------------------------------------------------
# SecurityHeadersEngine — X-Frame-Options
# ---------------------------------------------------------------------------


class TestXFrameOptions:
    E = SecurityHeadersEngine()

    def test_xfo_present_suppresses_missing_finding(self):
        fs = self.E.analyze(_resp(headers={"X-Frame-Options": "DENY"}))
        missing = _by_title(fs, "clickjacking")
        assert not missing

    def test_csp_frame_ancestors_suppresses_xfo_finding(self):
        fs = self.E.analyze(_resp(headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"
        }))
        missing = _by_title(fs, "clickjacking")
        assert not missing

    def test_allow_from_is_low(self):
        fs = self.E.analyze(_resp(headers={"X-Frame-Options": "ALLOW-FROM https://partner.com"}))
        af = _by_title(fs, "ALLOW-FROM")
        assert af
        assert af[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# CorsEngine tests
# ---------------------------------------------------------------------------


class TestCorsEngine:
    E = CorsEngine()

    def test_no_cors_headers_no_findings(self):
        fs = self.E.analyze(_resp())
        assert fs == []

    def test_wildcard_acao_on_public_resource_is_info(self):
        # audit #4: ACAO:* without credentials on a PUBLIC path is informational, not
        # MEDIUM (a browser won't send credentials cross-origin without ACAC:true).
        fs = self.E.analyze(_resp(url="https://example.com/about",
                                  headers={"Access-Control-Allow-Origin": "*"}))
        wc = _by_title(fs, "any website")
        assert wc and wc[0].severity == Severity.INFO
        assert "public" in wc[0].title.lower()

    def test_wildcard_acao_on_sensitive_path_is_medium(self):
        # A sensitive/API/account path with ACAO:* IS a real leak -> MEDIUM.
        fs = self.E.analyze(_resp(url="https://example.com/api/v1/users",
                                  headers={"Access-Control-Allow-Origin": "*"}))
        wc = _by_title(fs, "any website")
        assert wc and wc[0].severity == Severity.MEDIUM

    def test_wildcard_acao_with_credentials_is_high(self):
        fs = self.E.analyze(_resp(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }))
        dangerous = _by_title(fs, "wildcard origin + credentials")
        assert dangerous
        assert dangerous[0].severity == Severity.HIGH

    def test_specific_origin_with_credentials_no_finding(self):
        # Non-wildcard origin + credentials is the standard cookie-auth CORS
        # pattern; the engine intentionally no longer flags it (noise reduction).
        fs = self.E.analyze(_resp(headers={
            "Access-Control-Allow-Origin": "https://trusted.com",
            "Access-Control-Allow-Credentials": "true",
        }))
        assert fs == []

    def test_specific_origin_no_credentials_no_finding(self):
        fs = self.E.analyze(_resp(headers={
            "Access-Control-Allow-Origin": "https://trusted.com",
        }))
        assert fs == []

    def test_sensitive_methods_in_acam_is_medium(self):
        fs = self.E.analyze(_resp(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, PUT",
        }))
        methods_f = _by_title(fs, "sensitive HTTP methods")
        assert methods_f
        assert methods_f[0].severity == Severity.MEDIUM

    def test_safe_methods_only_no_method_finding(self):
        fs = self.E.analyze(_resp(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST",
        }))
        assert not _by_title(fs, "sensitive HTTP methods")

    def test_wildcard_allow_headers_is_low(self):
        fs = self.E.analyze(_resp(headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*",
        }))
        hdr_f = _by_title(fs, "wildcard request headers")
        assert hdr_f
        assert hdr_f[0].severity == Severity.LOW

    def test_cors_finding_has_evidence(self):
        fs = self.E.analyze(_resp(headers={"Access-Control-Allow-Origin": "*"}))
        assert fs
        assert fs[0].evidence
        assert "*" in fs[0].evidence[0].content

    def test_cors_finding_category_is_cors(self):
        fs = self.E.analyze(_resp(headers={"Access-Control-Allow-Origin": "*"}))
        assert fs
        assert fs[0].category == FindingCategory.CORS

    def test_cors_finding_has_owasp_alignment(self):
        fs = self.E.analyze(_resp(headers={"Access-Control-Allow-Origin": "*"}))
        assert fs
        assert fs[0].framework.owasp_top10


# ---------------------------------------------------------------------------
# parse_set_cookie helper
# ---------------------------------------------------------------------------


class TestParseSetCookie:
    def test_parses_name_value(self):
        c = parse_set_cookie("session=abc123; Path=/; HttpOnly; Secure")
        assert c.name == "session"
        assert c.value == "abc123"

    def test_detects_secure_flag(self):
        c = parse_set_cookie("id=1; Secure")
        assert c.secure is True

    def test_detects_httponly_flag(self):
        c = parse_set_cookie("id=1; HttpOnly")
        assert c.http_only is True

    def test_detects_samesite_strict(self):
        c = parse_set_cookie("id=1; SameSite=Strict")
        assert c.same_site == "Strict"

    def test_detects_samesite_none(self):
        c = parse_set_cookie("id=1; SameSite=None; Secure")
        assert c.same_site == "None"
        assert c.secure is True

    def test_detects_domain(self):
        c = parse_set_cookie("id=1; Domain=.example.com")
        assert c.domain == ".example.com"

    def test_has_broad_domain_true(self):
        c = parse_set_cookie("id=1; Domain=.example.com")
        assert c.has_broad_domain is True

    def test_has_broad_domain_false(self):
        c = parse_set_cookie("id=1; Domain=example.com")
        assert c.has_broad_domain is False

    def test_no_domain_not_broad(self):
        c = parse_set_cookie("id=1; Path=/")
        assert c.has_broad_domain is False

    def test_is_session_cookie_no_expiry(self):
        c = parse_set_cookie("id=1; Path=/")
        assert c.is_session_cookie is True

    def test_persistent_cookie_with_max_age(self):
        c = parse_set_cookie("id=1; Max-Age=3600")
        assert c.is_session_cookie is False
        assert c.max_age == 3600

    def test_persistent_cookie_with_expires(self):
        c = parse_set_cookie("id=1; Expires=Thu, 01 Jan 2099 00:00:00 GMT")
        assert c.is_session_cookie is False


# ---------------------------------------------------------------------------
# CookieScannerEngine tests
# ---------------------------------------------------------------------------


class TestCookieScannerEngine:
    E = CookieScannerEngine()

    def test_no_cookies_no_findings(self):
        assert self.E.analyze(_resp()) == []

    def test_missing_secure_on_https_is_medium(self):
        # Non-sensitive cookie name → MEDIUM baseline (sensitive/session
        # cookies are graded HIGH by the engine).
        r = _resp(headers={"set-cookie": "prefs=abc; HttpOnly; SameSite=Lax"})
        fs = self.E.analyze(r)
        missing_secure = _by_title(fs, "missing the Secure flag")
        assert missing_secure
        assert missing_secure[0].severity == Severity.MEDIUM

    def test_no_missing_secure_finding_on_http(self):
        r = _resp(url=_URL_HTTP, headers={"set-cookie": "session=abc; HttpOnly"})
        fs = self.E.analyze(r)
        assert not _by_title(fs, "missing the Secure flag")

    def test_secure_flag_present_no_secure_finding(self):
        r = _resp(headers={"set-cookie": "session=abc; Secure; HttpOnly; SameSite=Lax"})
        fs = self.E.analyze(r)
        assert not _by_title(fs, "missing the Secure flag")

    def test_missing_httponly_is_medium(self):
        r = _resp(headers={"set-cookie": "prefs=abc; Secure; SameSite=Lax"})
        fs = self.E.analyze(r)
        http_only = _by_title(fs, "missing HttpOnly")
        assert http_only
        assert http_only[0].severity == Severity.MEDIUM

    def test_httponly_present_no_httponly_finding(self):
        r = _resp(headers={"set-cookie": "session=abc; Secure; HttpOnly; SameSite=Lax"})
        fs = self.E.analyze(r)
        assert not _by_title(fs, "missing HttpOnly")

    def test_missing_samesite_is_medium(self):
        r = _resp(headers={"set-cookie": "session=abc; Secure; HttpOnly"})
        fs = self.E.analyze(r)
        ss = _by_title(fs, "no SameSite attribute")
        assert ss
        assert ss[0].severity == Severity.MEDIUM

    def test_samesite_none_without_secure_is_high(self):
        r = _resp(headers={"set-cookie": "tracking=1; SameSite=None"})
        fs = self.E.analyze(r)
        none_f = _by_title(fs, "SameSite=None without Secure")
        assert none_f
        assert none_f[0].severity == Severity.HIGH

    def test_samesite_none_with_secure_is_low(self):
        r = _resp(headers={"set-cookie": "xsid=1; Secure; HttpOnly; SameSite=None"})
        fs = self.E.analyze(r)
        cross_site = _by_title(fs, "cross-site use")
        assert cross_site
        assert cross_site[0].severity == Severity.LOW

    def test_broad_domain_is_low(self):
        r = _resp(headers={
            "set-cookie": "id=1; Secure; HttpOnly; SameSite=Strict; Domain=.example.com"
        })
        fs = self.E.analyze(r)
        broad = _by_title(fs, "every subdomain")
        assert broad
        assert broad[0].severity == Severity.LOW

    def test_narrow_domain_no_broad_finding(self):
        r = _resp(headers={
            "set-cookie": "id=1; Secure; HttpOnly; SameSite=Strict; Domain=example.com"
        })
        fs = self.E.analyze(r)
        assert not _by_title(fs, "every subdomain")

    def test_cookie_finding_category_is_cookie(self):
        r = _resp(headers={"set-cookie": "id=1"})
        fs = self.E.analyze(r)
        assert fs
        assert all(f.category == FindingCategory.COOKIE for f in fs)

    def test_cookie_finding_has_evidence(self):
        r = _resp(headers={"set-cookie": "session=abc; HttpOnly"})
        fs = self.E.analyze(r)
        assert fs
        assert all(len(f.evidence) > 0 for f in fs)

    def test_cookie_finding_has_owasp_alignment(self):
        r = _resp(headers={"set-cookie": "session=abc"})
        fs = self.E.analyze(r)
        assert fs
        assert all(f.framework.owasp_top10 for f in fs)

    def test_cookie_finding_name_in_title(self):
        r = _resp(headers={"set-cookie": "mysession=xyz; SameSite=Lax"})
        fs = self.E.analyze(r)
        assert any("mysession" in f.title for f in fs)

    def test_fully_secure_cookie_produces_no_findings(self):
        r = _resp(headers={
            "set-cookie": "id=1; Secure; HttpOnly; SameSite=Strict; Path=/"
        })
        fs = self.E.analyze(r)
        assert fs == []

    def test_scanner_engine_name_is_set(self):
        r = _resp(headers={"set-cookie": "id=1"})
        fs = self.E.analyze(r)
        assert fs
        assert all(f.scanner_engine == "cookie_scanner" for f in fs)

    def test_finding_has_remediation(self):
        r = _resp(headers={"set-cookie": "session=x"})
        fs = self.E.analyze(r)
        assert fs
        assert all(f.remediation for f in fs)
