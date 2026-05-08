# WebHound — scanner/tests/test_extractor.py
# Additional Extractor tests focusing on meta tags, form inputs,
# CSRF heuristics, and edge-case HTML handling.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from webhound.core.extractor import Extractor, PageArtifacts, _is_html
from webhound.core.http_client import HttpResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_URL = "https://example.com/"
_E = Extractor()


def _resp(
    body: str,
    url: str = _URL,
    content_type: str = "text/html; charset=utf-8",
    headers: dict[str, str] | None = None,
    status: int = 200,
) -> HttpResponse:
    h: dict[str, str] = {"content-type": content_type}
    if headers:
        h.update({k.lower(): v for k, v in headers.items()})
    return HttpResponse(
        request_id=uuid4(),
        original_url=url,
        url=url,
        status_code=status,
        headers=h,
        body=body,
        content_type=content_type,
        elapsed_ms=50.0,
        redirect_count=0,
        redirect_chain=[],
        captured_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# _is_html
# ---------------------------------------------------------------------------


class TestIsHtml:
    def test_text_html(self):
        assert _is_html("text/html") is True

    def test_text_html_with_charset(self):
        assert _is_html("text/html; charset=utf-8") is True

    def test_xhtml(self):
        assert _is_html("application/xhtml+xml") is True

    def test_json_not_html(self):
        assert _is_html("application/json") is False

    def test_css_not_html(self):
        assert _is_html("text/css") is False

    def test_none_not_html(self):
        assert _is_html(None) is False


# ---------------------------------------------------------------------------
# Non-HTML / empty responses
# ---------------------------------------------------------------------------


class TestExtractorNonHtml:
    E = Extractor()

    def test_json_response_returns_none(self):
        resp = _resp("{}", content_type="application/json")
        assert self.E.extract(resp) is None

    def test_empty_body_returns_none(self):
        resp = _resp("", content_type="text/html")
        assert self.E.extract(resp) is None

    def test_whitespace_only_body_returns_none(self):
        resp = _resp("   \n  ", content_type="text/html")
        assert self.E.extract(resp) is None

    def test_css_response_returns_none(self):
        resp = _resp("body {}", content_type="text/css")
        assert self.E.extract(resp) is None


# ---------------------------------------------------------------------------
# Basic artifact structure
# ---------------------------------------------------------------------------


class TestExtractorBasicStructure:
    E = Extractor()
    _HTML = "<html><head><title>Test Page</title></head><body></body></html>"

    def test_returns_page_artifacts(self):
        resp = _resp(self._HTML)
        a = self.E.extract(resp)
        assert isinstance(a, PageArtifacts)

    def test_url_is_response_url(self):
        resp = _resp(self._HTML)
        a = self.E.extract(resp)
        assert a.url == _URL

    def test_status_code_captured(self):
        resp = _resp(self._HTML)
        a = self.E.extract(resp)
        assert a.status_code == 200

    def test_title_extracted(self):
        resp = _resp(self._HTML)
        a = self.E.extract(resp)
        assert a.title == "Test Page"

    def test_no_title_returns_none(self):
        resp = _resp("<html><body></body></html>")
        a = self.E.extract(resp)
        assert a.title is None


# ---------------------------------------------------------------------------
# Meta tag extraction
# ---------------------------------------------------------------------------


class TestExtractorMetaTags:
    E = Extractor()

    def test_extracts_meta_name_content(self):
        html = '<html><head><meta name="description" content="A test site"></head><body></body></html>'
        a = self.E.extract(_resp(html))
        assert "description" in a.meta_tags
        assert a.meta_tags["description"] == "A test site"

    def test_extracts_meta_property_content(self):
        html = '<html><head><meta property="og:title" content="OG Title"></head><body></body></html>'
        a = self.E.extract(_resp(html))
        assert "og:title" in a.meta_tags
        assert a.meta_tags["og:title"] == "OG Title"

    def test_no_meta_tags_returns_empty_dict(self):
        resp = _resp("<html><body></body></html>")
        a = self.E.extract(resp)
        assert isinstance(a.meta_tags, dict)

    def test_multiple_meta_tags(self):
        html = (
            "<html><head>"
            '<meta name="author" content="Alice">'
            '<meta name="keywords" content="security,scan">'
            "</head><body></body></html>"
        )
        a = self.E.extract(_resp(html))
        assert "author" in a.meta_tags
        assert "keywords" in a.meta_tags


# ---------------------------------------------------------------------------
# Form extraction — inputs and security attributes
# ---------------------------------------------------------------------------


class TestExtractorFormInputs:
    E = Extractor()

    def test_has_password_field_true(self):
        html = (
            "<html><body><form action='/login' method='post'>"
            "<input type='text' name='user'>"
            "<input type='password' name='pass'>"
            "</form></body></html>"
        )
        a = self.E.extract(_resp(html))
        assert a.forms
        assert a.forms[0].has_password_field is True

    def test_has_password_field_false(self):
        html = (
            "<html><body><form><input type='text' name='q'></form></body></html>"
        )
        a = self.E.extract(_resp(html))
        assert a.forms
        assert a.forms[0].has_password_field is False

    def test_form_input_count(self):
        html = (
            "<html><body><form>"
            "<input type='text' name='a'>"
            "<input type='email' name='b'>"
            "<input type='submit' value='Go'>"
            "</form></body></html>"
        )
        a = self.E.extract(_resp(html))
        assert len(a.forms[0].inputs) == 3

    def test_has_csrf_token_hidden_input_named_csrf(self):
        html = (
            "<html><body><form method='post'>"
            "<input type='hidden' name='csrf_token' value='abc'>"
            "<input type='text' name='data'>"
            "</form></body></html>"
        )
        a = self.E.extract(_resp(html))
        assert a.forms[0].has_csrf_token is True

    def test_has_csrf_token_false_when_missing(self):
        html = (
            "<html><body><form method='post'>"
            "<input type='text' name='data'>"
            "</form></body></html>"
        )
        a = self.E.extract(_resp(html))
        assert a.forms[0].has_csrf_token is False

    def test_form_input_types_captured(self):
        html = (
            "<html><body><form>"
            "<input type='hidden' name='h' value='x'>"
            "</form></body></html>"
        )
        a = self.E.extract(_resp(html))
        inputs = a.forms[0].inputs
        hidden_inputs = [i for i in inputs if i.input_type == "hidden"]
        assert hidden_inputs


# ---------------------------------------------------------------------------
# Cookie extraction from response headers
# ---------------------------------------------------------------------------


class TestExtractorCookies:
    E = Extractor()

    def test_set_cookie_header_captured(self):
        resp = _resp(
            "<html><body></body></html>",
            headers={"Set-Cookie": "sid=abc; Secure; HttpOnly"},
        )
        a = self.E.extract(resp)
        assert a.cookies
        assert any("sid=abc" in c for c in a.cookies)

    def test_no_cookies_when_no_header(self):
        resp = _resp("<html><body></body></html>")
        a = self.E.extract(resp)
        assert a.cookies == []


# ---------------------------------------------------------------------------
# Response headers captured
# ---------------------------------------------------------------------------


class TestExtractorResponseHeaders:
    E = Extractor()

    def test_response_headers_include_content_type(self):
        resp = _resp("<html><body></body></html>")
        a = self.E.extract(resp)
        assert "content-type" in a.response_headers

    def test_custom_header_captured(self):
        resp = _resp(
            "<html><body></body></html>",
            headers={"X-Custom-Header": "test-value"},
        )
        a = self.E.extract(resp)
        assert a.response_headers.get("x-custom-header") == "test-value"


# ---------------------------------------------------------------------------
# extracted_at timestamp
# ---------------------------------------------------------------------------


def test_extracted_at_is_timezone_aware():
    a = _E.extract(_resp("<html><body></body></html>"))
    assert a.extracted_at.tzinfo is not None
