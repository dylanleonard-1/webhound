# WebHound — scanner/tests/test_crawl.py
# Pytest tests for Phase 2B: extractor and crawler.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest

from webhound.core.crawler import CrawlResult, Crawler
from webhound.core.extractor import (
    ExtractedForm,
    ExtractedScript,
    Extractor,
    FormInput,
    PageArtifacts,
    _is_html,
)
from webhound.core.http_client import HttpResponse, SafeHttpClient
from webhound.core.scan_context import ScanContext
from webhound.models.target import ScanOptions, Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_URL = "https://example.com"


def _make_response(
    body: str,
    url: str = "https://example.com/",
    status: int = 200,
    content_type: str = "text/html; charset=utf-8",
    headers: dict[str, str] | None = None,
) -> HttpResponse:
    all_headers = {"content-type": content_type}
    if headers:
        all_headers.update({k.lower(): v for k, v in headers.items()})
    return HttpResponse(
        request_id=uuid4(),
        original_url=url,
        url=url,
        status_code=status,
        headers=all_headers,
        body=body,
        content_type=content_type,
        elapsed_ms=50.0,
        redirect_count=0,
        redirect_chain=[],
        captured_at=datetime.now(timezone.utc),
    )


def _target(max_pages: int = 10, max_depth: int = 3, rate: float = 10.0) -> Target:
    return Target.from_url(
        _BASE_URL,
        scan_options=ScanOptions(
            max_pages=max_pages,
            max_depth=max_depth,
            rate_limit_rps=rate,
        ),
    )


def _transport(pages: dict[str, tuple[int, str, str]]) -> httpx.MockTransport:
    """Multi-page transport: pages dict maps URL → (status, body, content_type)."""
    async def handler(request: httpx.Request) -> httpx.Response:
        key = str(request.url)
        # Try exact match, then strip trailing slash variant
        if key not in pages and key.rstrip("/") in pages:
            key = key.rstrip("/")
        status, body, ct = pages.get(key, (200, "<html><body>generic</body></html>", "text/html"))
        return httpx.Response(status, text=body, headers={"content-type": ct})
    return httpx.MockTransport(handler)


def _html_transport(pages: dict[str, str]) -> httpx.MockTransport:
    """Convenience wrapper: maps URL → HTML body, status always 200."""
    return _transport({k: (200, v, "text/html; charset=utf-8") for k, v in pages.items()})


# ---------------------------------------------------------------------------
# _is_html helper
# ---------------------------------------------------------------------------

class TestIsHtml:
    def test_text_html(self):
        assert _is_html("text/html")

    def test_text_html_with_charset(self):
        assert _is_html("text/html; charset=utf-8")

    def test_xhtml(self):
        assert _is_html("application/xhtml+xml")

    def test_json_not_html(self):
        assert not _is_html("application/json")

    def test_css_not_html(self):
        assert not _is_html("text/css")

    def test_none_not_html(self):
        assert not _is_html(None)

    def test_image_not_html(self):
        assert not _is_html("image/png")


# ---------------------------------------------------------------------------
# Extractor — link extraction
# ---------------------------------------------------------------------------


class TestExtractorLinks:
    E = Extractor()

    def test_extracts_internal_links(self):
        resp = _make_response(
            '<html><body><a href="/about">About</a><a href="/blog">Blog</a></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert "https://example.com/about" in art.internal_links
        assert "https://example.com/blog" in art.internal_links

    def test_extracts_external_links(self):
        resp = _make_response(
            '<html><body><a href="https://other.com/page">Ext</a></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert "https://other.com/page" in art.external_links

    def test_external_links_not_in_internal(self):
        resp = _make_response(
            '<html><body><a href="https://other.com/">X</a></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert not any("other.com" in u for u in art.internal_links)

    def test_all_links_is_union(self):
        resp = _make_response(
            '<html><body><a href="/in">I</a><a href="https://ext.com/">E</a></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert len(art.all_links) == len(art.internal_links) + len(art.external_links)

    def test_deduplicates_links(self):
        resp = _make_response(
            '<html><body>'
            '<a href="/page">One</a>'
            '<a href="/page">Two</a>'
            '<a href="/page#anchor">Three</a>'  # fragment stripped → same as /page
            '</body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert art.all_links.count("https://example.com/page") == 1

    def test_fragment_only_links_ignored(self):
        resp = _make_response('<html><body><a href="#section">Skip</a></body></html>')
        art = self.E.extract(resp)
        assert art is not None
        assert art.all_links == []

    def test_javascript_links_ignored(self):
        resp = _make_response('<html><body><a href="javascript:void(0)">JS</a></body></html>')
        art = self.E.extract(resp)
        assert art is not None
        assert art.all_links == []

    def test_mailto_links_ignored(self):
        resp = _make_response('<html><body><a href="mailto:a@b.com">Mail</a></body></html>')
        art = self.E.extract(resp)
        assert art is not None
        assert art.all_links == []

    def test_relative_link_resolved(self):
        resp = _make_response(
            '<html><body><a href="page2">P2</a></body></html>',
            url="https://example.com/blog/",
        )
        art = self.E.extract(resp)
        assert art is not None
        assert "https://example.com/blog/page2" in art.all_links

    def test_absolute_path_resolved_against_host(self):
        resp = _make_response(
            '<html><body><a href="/contact">C</a></body></html>',
            url="https://example.com/blog/post",
        )
        art = self.E.extract(resp)
        assert art is not None
        assert "https://example.com/contact" in art.all_links

    def test_base_href_used_for_resolution(self):
        resp = _make_response(
            '<html><head><base href="https://example.com/docs/"></head>'
            '<body><a href="intro">Intro</a></body></html>',
            url="https://example.com/",
        )
        art = self.E.extract(resp)
        assert art is not None
        assert "https://example.com/docs/intro" in art.all_links

    def test_url_normalization_strips_default_port(self):
        resp = _make_response(
            '<html><body><a href="https://example.com:443/page">X</a></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert any(":443" not in u for u in art.all_links)

    def test_empty_href_ignored(self):
        resp = _make_response('<html><body><a href="">Blank</a></body></html>')
        art = self.E.extract(resp)
        assert art is not None
        assert art.all_links == []


# ---------------------------------------------------------------------------
# Extractor — script extraction
# ---------------------------------------------------------------------------


class TestExtractorScripts:
    E = Extractor()

    def test_extracts_inline_script(self):
        resp = _make_response(
            '<html><head><script>var x = 1;</script></head></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert len(art.inline_scripts) == 1
        assert "var x = 1;" in art.inline_scripts[0]

    def test_extracts_external_script_src(self):
        resp = _make_response(
            '<html><head><script src="/static/app.js"></script></head></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert "https://example.com/static/app.js" in art.external_script_urls

    def test_external_script_on_different_domain(self):
        resp = _make_response(
            '<html><head><script src="https://cdn.other.com/lib.js"></script></head></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        s = art.scripts[0]
        assert s.is_external_domain is True
        assert s.src == "https://cdn.other.com/lib.js"

    def test_internal_script_src_not_external_domain(self):
        resp = _make_response(
            '<html><head><script src="/app.js"></script></head></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        s = art.scripts[0]
        assert s.is_external_domain is False

    def test_inline_script_not_executed(self):
        # Presence of eval/alert does not cause any exception or side effect.
        resp = _make_response(
            '<html><head><script>eval(atob("bGV0IHg9MSs")); alert(1);</script></head></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert art.inline_scripts  # captured but not run

    def test_multiple_scripts(self):
        resp = _make_response(
            '<html><head>'
            '<script>var a=1;</script>'
            '<script src="/b.js"></script>'
            '<script>var c=3;</script>'
            '</head></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert len(art.scripts) == 3
        assert len(art.inline_scripts) == 2
        assert len(art.external_script_urls) == 1

    def test_empty_script_tag_ignored(self):
        resp = _make_response('<html><head><script></script></head></html>')
        art = self.E.extract(resp)
        assert art is not None
        assert art.scripts == []


# ---------------------------------------------------------------------------
# Extractor — form extraction
# ---------------------------------------------------------------------------


class TestExtractorForms:
    E = Extractor()

    def test_extracts_form_action(self):
        resp = _make_response(
            '<html><body><form action="/login" method="POST"></form></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert len(art.forms) == 1
        assert art.forms[0].action == "/login"
        assert art.forms[0].action_url == "https://example.com/login"

    def test_form_method_uppercased(self):
        resp = _make_response(
            '<html><body><form method="post"></form></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert art.forms[0].method == "POST"

    def test_form_default_method_is_get(self):
        resp = _make_response(
            '<html><body><form action="/search"></form></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert art.forms[0].method == "GET"

    def test_form_inputs_extracted(self):
        resp = _make_response(
            '<html><body>'
            '<form>'
            '<input type="text" name="user">'
            '<input type="password" name="pass">'
            '<input type="hidden" name="csrf_token" value="abc">'
            '</form>'
            '</body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        form = art.forms[0]
        names = [i.name for i in form.inputs]
        assert "user" in names
        assert "pass" in names
        assert "csrf_token" in names

    def test_form_detects_password_field(self):
        resp = _make_response(
            '<html><body><form><input type="password" name="pw"></form></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert art.forms[0].has_password_field is True

    def test_form_no_password_field(self):
        resp = _make_response(
            '<html><body><form><input type="text" name="q"></form></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert art.forms[0].has_password_field is False

    def test_form_detects_csrf_token(self):
        resp = _make_response(
            '<html><body>'
            '<form><input type="hidden" name="csrf_token" value="x"></form>'
            '</body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert art.forms[0].has_csrf_token is True

    def test_form_no_csrf_token(self):
        resp = _make_response(
            '<html><body><form><input type="text" name="q"></form></body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert art.forms[0].has_csrf_token is False

    def test_form_never_submitted(self):
        # Extractor should not perform any network activity.
        # This test confirms extract() is purely synchronous.
        resp = _make_response(
            '<html><body><form action="https://evil.com/capture" method="POST">'
            '<input type="text" name="data"></form></body></html>'
        )
        art = self.E.extract(resp)
        # The form is captured — but action_url points to evil.com.
        # The extractor records it without making any request.
        assert art is not None
        assert art.forms[0].action_url is not None
        assert "evil.com" in (art.forms[0].action_url or "")

    def test_multiple_forms(self):
        resp = _make_response(
            '<html><body>'
            '<form action="/login"></form>'
            '<form action="/register"></form>'
            '</body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert len(art.forms) == 2

    def test_input_value_captured_not_submitted(self):
        resp = _make_response(
            '<html><body>'
            '<form><input type="hidden" name="key" value="secret123"></form>'
            '</body></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        # Value is captured for analysis — never sent anywhere by extractor.
        inp = next(i for i in art.forms[0].inputs if i.name == "key")
        assert inp.value == "secret123"


# ---------------------------------------------------------------------------
# Extractor — cookies and metadata
# ---------------------------------------------------------------------------


class TestExtractorMeta:
    E = Extractor()

    def test_extracts_set_cookie_header(self):
        resp = _make_response(
            "<html></html>",
            headers={"Set-Cookie": "session=abc123; HttpOnly; Secure"},
        )
        art = self.E.extract(resp)
        assert art is not None
        assert any("session=abc123" in c for c in art.cookies)

    def test_no_cookies_when_header_absent(self):
        resp = _make_response("<html></html>")
        art = self.E.extract(resp)
        assert art is not None
        assert art.cookies == []

    def test_extracts_page_title(self):
        resp = _make_response("<html><head><title>My Site</title></head></html>")
        art = self.E.extract(resp)
        assert art is not None
        assert art.title == "My Site"

    def test_no_title_returns_none(self):
        resp = _make_response("<html><body>No title</body></html>")
        art = self.E.extract(resp)
        assert art is not None
        assert art.title is None

    def test_extracts_meta_description(self):
        resp = _make_response(
            '<html><head><meta name="description" content="Test page"></head></html>'
        )
        art = self.E.extract(resp)
        assert art is not None
        assert art.meta_tags.get("description") == "Test page"

    def test_extracted_at_is_utc(self):
        resp = _make_response("<html></html>")
        art = self.E.extract(resp)
        assert art is not None
        assert art.extracted_at.tzinfo == timezone.utc

    def test_non_html_returns_none(self):
        resp = _make_response('{"key": "value"}', content_type="application/json")
        assert self.E.extract(resp) is None

    def test_empty_body_returns_none(self):
        resp = _make_response("", content_type="text/html")
        assert self.E.extract(resp) is None

    def test_malformed_html_handled_gracefully(self):
        resp = _make_response(
            "<html><b>Unclosed <div><a href='/ok'>Link</div>",
        )
        art = self.E.extract(resp)
        assert art is not None  # lxml repairs it
        assert any("/ok" in u for u in art.all_links)


# ---------------------------------------------------------------------------
# Crawler tests (async)
# ---------------------------------------------------------------------------


class TestCrawler:
    @pytest.mark.anyio
    async def test_crawls_root_page(self):
        pages = {"https://example.com/": "<html><body>Root</body></html>"}
        t = _target(max_pages=5)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=_html_transport(pages)) as c:
            results = await Crawler(ctx, c).crawl()
        assert len(results) == 1
        assert results[0].url == "https://example.com/"

    @pytest.mark.anyio
    async def test_crawls_linked_pages(self):
        pages = {
            "https://example.com/": '<html><body><a href="/p1">P1</a></body></html>',
            "https://example.com/p1": "<html><body>Page 1</body></html>",
        }
        t = _target(max_pages=5)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=_html_transport(pages)) as c:
            results = await Crawler(ctx, c).crawl()
        urls = {r.url for r in results}
        assert "https://example.com/" in urls
        assert "https://example.com/p1" in urls

    @pytest.mark.anyio
    async def test_respects_max_pages(self):
        pages = {
            "https://example.com/": (
                '<html><body>'
                '<a href="/p1">P1</a><a href="/p2">P2</a><a href="/p3">P3</a>'
                '</body></html>'
            ),
            "https://example.com/p1": "<html><body>P1</body></html>",
            "https://example.com/p2": "<html><body>P2</body></html>",
            "https://example.com/p3": "<html><body>P3</body></html>",
        }
        t = _target(max_pages=2, rate=10.0)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=_html_transport(pages)) as c:
            results = await Crawler(ctx, c).crawl()
        assert len(results) == 2
        assert ctx.pages_crawled == 2

    @pytest.mark.anyio
    async def test_respects_max_depth(self):
        # depth 0: root → links to /d1
        # depth 1: /d1  → links to /d2
        # depth 2: /d2  → links to /d3  (NOT crawled when max_depth=1)
        pages = {
            "https://example.com/": '<html><body><a href="/d1">D1</a></body></html>',
            "https://example.com/d1": '<html><body><a href="/d2">D2</a></body></html>',
            "https://example.com/d2": '<html><body><a href="/d3">D3</a></body></html>',
            "https://example.com/d3": "<html><body>D3</body></html>",
        }
        t = _target(max_pages=20, max_depth=1, rate=10.0)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=_html_transport(pages)) as c:
            results = await Crawler(ctx, c).crawl()
        urls = {r.url for r in results}
        assert "https://example.com/" in urls
        assert "https://example.com/d1" in urls
        assert "https://example.com/d2" not in urls
        assert "https://example.com/d3" not in urls

    @pytest.mark.anyio
    async def test_blocks_external_domains(self):
        pages = {
            "https://example.com/": (
                '<html><body>'
                '<a href="/internal">Int</a>'
                '<a href="https://evil.com/steal">Ext</a>'
                '</body></html>'
            ),
            "https://example.com/internal": "<html><body>Internal</body></html>",
        }
        t = _target(max_pages=10)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=_html_transport(pages)) as c:
            results = await Crawler(ctx, c).crawl()
        urls = {r.url for r in results}
        assert not any("evil.com" in u for u in urls)

    @pytest.mark.anyio
    async def test_skips_duplicate_urls(self):
        # Root links to /page twice (different anchor text)
        pages = {
            "https://example.com/": (
                '<html><body>'
                '<a href="/page">First</a>'
                '<a href="/page">Second</a>'
                '</body></html>'
            ),
            "https://example.com/page": "<html><body>Page</body></html>",
        }
        t = _target(max_pages=10)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=_html_transport(pages)) as c:
            results = await Crawler(ctx, c).crawl()
        page_hits = [r for r in results if r.url == "https://example.com/page"]
        assert len(page_hits) == 1

    @pytest.mark.anyio
    async def test_handles_http_failure_safely(self):
        async def error_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        t = _target(max_pages=5)
        ctx = ScanContext(t)
        async with SafeHttpClient(
            t.scan_options, transport=httpx.MockTransport(error_handler)
        ) as c:
            results = await Crawler(ctx, c).crawl()
        # No exception propagated; result recorded with error
        assert len(results) == 1
        assert results[0].artifacts is None
        assert results[0].response.failed
        assert len(ctx.scan_result.errors) == 1

    @pytest.mark.anyio
    async def test_skips_non_html_content(self):
        pages = {
            "https://example.com/": (
                200,
                '<html><body><a href="/data.json">JSON</a><a href="/page">HTML</a></body></html>',
                "text/html",
            ),
            "https://example.com/data.json": (
                200,
                '{"key": "value"}',
                "application/json",
            ),
            "https://example.com/page": (200, "<html><body>Page</body></html>", "text/html"),
        }
        t = _target(max_pages=10)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=_transport(pages)) as c:
            results = await Crawler(ctx, c).crawl()
        # JSON page is fetched but has no artifacts extracted
        json_result = next(r for r in results if "data.json" in r.url)
        assert json_result.artifacts is None
        # HTML page has artifacts
        html_result = next(r for r in results if r.url == "https://example.com/page")
        assert html_result.artifacts is not None

    @pytest.mark.anyio
    async def test_does_not_submit_forms(self):
        # A page with a POST form to an external domain.
        # The crawler must NOT make a POST request to that form action.
        submitted_to: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            submitted_to.append(f"{request.method}:{request.url}")
            if "evil.com" in str(request.url):
                return httpx.Response(200, text="<html>captured</html>",
                                      headers={"content-type": "text/html"})
            return httpx.Response(
                200,
                text='<html><body>'
                     '<form action="https://evil.com/capture" method="POST">'
                     '<input type="text" name="data">'
                     '</form></body></html>',
                headers={"content-type": "text/html"},
            )

        t = _target(max_pages=5)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=httpx.MockTransport(handler)) as c:
            await Crawler(ctx, c).crawl()

        # No request to evil.com should have been made
        assert not any("evil.com" in entry for entry in submitted_to)
        # Only GET requests were made
        assert all(entry.startswith("GET:") for entry in submitted_to)

    @pytest.mark.anyio
    async def test_crawl_result_contains_artifacts(self):
        pages = {
            "https://example.com/": "<html><head><title>Home</title></head><body></body></html>",
        }
        t = _target(max_pages=5)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=_html_transport(pages)) as c:
            results = await Crawler(ctx, c).crawl()
        assert results[0].artifacts is not None
        assert results[0].artifacts.title == "Home"

    @pytest.mark.anyio
    async def test_finish_returns_completed_scan_result(self):
        pages = {"https://example.com/": "<html><body>Done</body></html>"}
        t = _target(max_pages=5)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=_html_transport(pages)) as c:
            await Crawler(ctx, c).crawl()
        result = ctx.finish()
        from webhound.models.scan_result import ScanStatus
        assert result.status == ScanStatus.COMPLETED
        assert result.urls_crawled == 1

    @pytest.mark.anyio
    async def test_handles_404_gracefully(self):
        pages = {
            "https://example.com/": (
                '<html><body><a href="/missing">Missing</a></body></html>'
            ),
        }
        async def handler(request: httpx.Request) -> httpx.Response:
            if "/missing" in str(request.url):
                return httpx.Response(404, text="Not Found", headers={"content-type": "text/html"})
            return httpx.Response(200, text=pages["https://example.com/"],
                                  headers={"content-type": "text/html"})

        t = _target(max_pages=5)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=httpx.MockTransport(handler)) as c:
            results = await Crawler(ctx, c).crawl()
        # 404 is not a failure; it's a valid HTTP response
        missing = next(r for r in results if "/missing" in r.url)
        assert missing.response.status_code == 404
        assert not missing.response.failed

    @pytest.mark.anyio
    async def test_context_tracks_pages_crawled(self):
        pages = {
            "https://example.com/": (
                '<html><body><a href="/p1">P1</a><a href="/p2">P2</a></body></html>'
            ),
            "https://example.com/p1": "<html>P1</html>",
            "https://example.com/p2": "<html>P2</html>",
        }
        t = _target(max_pages=10)
        ctx = ScanContext(t)
        async with SafeHttpClient(t.scan_options, transport=_html_transport(pages)) as c:
            await Crawler(ctx, c).crawl()
        assert ctx.pages_crawled == 3
