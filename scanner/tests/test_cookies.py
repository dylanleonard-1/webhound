# WebHound — scanner/tests/test_cookies.py
# Tests for CookieScannerEngine and parse_set_cookie.
# Focuses on edge cases and scenarios not covered by test_headers_engines.py.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from webhound.core.http_client import HttpResponse
from webhound.engines.cookies.cookie_scanner import (
    CookieScannerEngine,
    ParsedCookie,
    _collect_cookies,
    parse_set_cookie,
)
from webhound.models.finding import FindingCategory
from webhound.models.severity import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_URL_HTTPS = "https://example.com/"
_URL_HTTP = "http://example.com/"


def _resp(
    set_cookie: str | None = None,
    url: str = _URL_HTTPS,
) -> HttpResponse:
    headers: dict[str, str] = {"content-type": "text/html"}
    if set_cookie is not None:
        headers["set-cookie"] = set_cookie
    return HttpResponse(
        request_id=uuid4(),
        original_url=url,
        url=url,
        status_code=200,
        headers=headers,
        body="<html></html>",
        content_type="text/html",
        elapsed_ms=30.0,
        redirect_count=0,
        redirect_chain=[],
        captured_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# parse_set_cookie — edge cases
# ---------------------------------------------------------------------------


class TestParseSetCookie:
    def test_simple_name_value(self):
        c = parse_set_cookie("sid=abc123")
        assert c.name == "sid"
        assert c.value == "abc123"

    def test_value_with_equals_sign(self):
        c = parse_set_cookie("token=base64==; HttpOnly")
        assert c.value == "base64=="
        assert c.http_only is True

    def test_all_flags_parsed(self):
        raw = "id=1; Secure; HttpOnly; SameSite=Strict"
        c = parse_set_cookie(raw)
        assert c.secure is True
        assert c.http_only is True
        assert c.same_site == "Strict"

    def test_domain_parsed(self):
        c = parse_set_cookie("a=b; Domain=.example.com")
        assert c.domain == ".example.com"

    def test_path_parsed(self):
        c = parse_set_cookie("a=b; Path=/admin")
        assert c.path == "/admin"

    def test_max_age_parsed(self):
        c = parse_set_cookie("a=b; Max-Age=3600")
        assert c.max_age == 3600

    def test_max_age_zero(self):
        c = parse_set_cookie("a=b; Max-Age=0")
        assert c.max_age == 0

    def test_expires_parsed(self):
        c = parse_set_cookie("a=b; Expires=Thu, 01 Jan 2026 00:00:00 GMT")
        assert c.expires == "Thu, 01 Jan 2026 00:00:00 GMT"

    def test_invalid_max_age_ignored(self):
        c = parse_set_cookie("a=b; Max-Age=notanumber")
        assert c.max_age is None

    def test_name_only_no_value(self):
        c = parse_set_cookie("tokenonly")
        assert c.name == "tokenonly"
        assert c.value == ""

    def test_samesite_lax(self):
        c = parse_set_cookie("a=b; SameSite=Lax")
        assert c.same_site == "Lax"

    def test_samesite_none_with_secure(self):
        c = parse_set_cookie("a=b; SameSite=None; Secure")
        assert c.same_site == "None"
        assert c.secure is True

    def test_raw_preserved(self):
        raw = "mykey=myval; Secure; HttpOnly"
        c = parse_set_cookie(raw)
        assert c.raw == raw


# ---------------------------------------------------------------------------
# ParsedCookie properties
# ---------------------------------------------------------------------------


class TestParsedCookieProperties:
    def test_is_session_cookie_no_expiry(self):
        c = parse_set_cookie("sid=x")
        assert c.is_session_cookie is True

    def test_persistent_cookie_max_age(self):
        c = parse_set_cookie("sid=x; Max-Age=86400")
        assert c.is_session_cookie is False

    def test_persistent_cookie_expires(self):
        c = parse_set_cookie("sid=x; Expires=Thu, 01 Jan 2026 00:00:00 GMT")
        assert c.is_session_cookie is False

    def test_has_broad_domain_leading_dot(self):
        c = parse_set_cookie("a=b; Domain=.example.com")
        assert c.has_broad_domain is True

    def test_has_broad_domain_no_leading_dot(self):
        c = parse_set_cookie("a=b; Domain=example.com")
        assert c.has_broad_domain is False

    def test_has_broad_domain_no_domain_attribute(self):
        c = parse_set_cookie("a=b; Secure")
        assert c.has_broad_domain is False


# ---------------------------------------------------------------------------
# CookieScannerEngine — broad domain scope
# ---------------------------------------------------------------------------


class TestCookieScannerBroadDomain:
    E = CookieScannerEngine()

    def test_broad_domain_produces_low_finding(self):
        resp = _resp("id=1; Domain=.example.com")
        findings = self.E.analyze(resp)
        broad = [f for f in findings if "every subdomain" in f.title.lower()]
        assert broad, "Expected a broad-domain finding"
        assert broad[0].severity == Severity.LOW

    def test_no_broad_domain_finding_without_leading_dot(self):
        resp = _resp("id=1; Domain=example.com")
        findings = self.E.analyze(resp)
        broad = [f for f in findings if "every subdomain" in f.title.lower()]
        assert not broad

    def test_finding_category_is_cookie(self):
        resp = _resp("id=1; Domain=.example.com")
        findings = self.E.analyze(resp)
        assert all(f.category == FindingCategory.COOKIE for f in findings)

    def test_no_broad_domain_finding_when_no_domain_attribute(self):
        resp = _resp("id=1; Secure; HttpOnly; SameSite=Strict")
        findings = self.E.analyze(resp)
        broad = [f for f in findings if "every subdomain" in f.title.lower()]
        assert not broad


# ---------------------------------------------------------------------------
# CookieScannerEngine — no cookies
# ---------------------------------------------------------------------------


class TestCookieScannerNoCookies:
    E = CookieScannerEngine()

    def test_no_cookies_produces_no_findings(self):
        assert self.E.analyze(_resp()) == []

    def test_empty_set_cookie_header_produces_no_findings(self):
        assert self.E.analyze(_resp(set_cookie="")) == []


# ---------------------------------------------------------------------------
# CookieScannerEngine — Secure flag context
# ---------------------------------------------------------------------------


class TestCookieScannerSecureContext:
    E = CookieScannerEngine()

    def test_missing_secure_on_https_produces_finding(self):
        resp = _resp("sid=x", url=_URL_HTTPS)
        titles = [f.title for f in self.E.analyze(resp)]
        assert any("Secure flag" in t for t in titles)

    def test_no_secure_finding_on_http(self):
        resp = _resp("sid=x", url=_URL_HTTP)
        titles = [f.title for f in self.E.analyze(resp)]
        assert not any("Secure flag" in t for t in titles)

    def test_secure_flag_present_suppresses_secure_finding(self):
        resp = _resp("sid=x; Secure", url=_URL_HTTPS)
        titles = [f.title for f in self.E.analyze(resp)]
        assert not any("missing Secure flag" in t for t in titles)


# ---------------------------------------------------------------------------
# CookieScannerEngine — evidence integrity
# ---------------------------------------------------------------------------


class TestCookieScannerEvidence:
    E = CookieScannerEngine()

    def test_all_findings_have_evidence(self):
        resp = _resp("sid=x")
        findings = self.E.analyze(resp)
        assert all(len(f.evidence) >= 1 for f in findings)

    def test_finding_evidence_contains_cookie_name(self):
        resp = _resp("mysession=abc")
        findings = self.E.analyze(resp)
        for f in findings:
            if "mysession" in f.title:
                assert any("mysession" in ev.content for ev in f.evidence)

    def test_findings_have_owasp_alignment(self):
        resp = _resp("sid=x")
        findings = self.E.analyze(resp)
        assert all(f.framework.owasp_top10 for f in findings)

    def test_findings_have_remediation(self):
        resp = _resp("sid=x")
        findings = self.E.analyze(resp)
        assert all(f.remediation for f in findings)


# ---------------------------------------------------------------------------
# _collect_cookies helper
# ---------------------------------------------------------------------------


class TestCollectCookies:
    def test_collects_single_cookie(self):
        resp = _resp("sid=abc")
        cookies = _collect_cookies(resp)
        assert len(cookies) == 1
        assert cookies[0].name == "sid"

    def test_no_set_cookie_returns_empty(self):
        resp = _resp()
        assert _collect_cookies(resp) == []

    def test_whitespace_only_cookie_ignored(self):
        resp = _resp("   ")
        assert _collect_cookies(resp) == []

    def test_collected_cookie_preserves_raw(self):
        raw = "token=xyz; Secure; HttpOnly"
        resp = _resp(raw)
        cookies = _collect_cookies(resp)
        assert cookies[0].raw == raw
