# WebHound — scanner/tests/test_crawler.py
# Additional Crawler tests complementing test_crawl.py.
# Focuses on BFS depth/page budgets, CrawlResult structure, and
# edge cases not covered by the existing suite.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import httpx
import pytest

from webhound.core.crawler import CrawlResult, Crawler
from webhound.core.http_client import HttpResponse, SafeHttpClient
from webhound.core.retry_policy import NO_RETRY_POLICY
from webhound.core.scan_context import ScanContext
from webhound.models.target import ScanOptions, Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_URL = "https://example.com"
_BASE_URL_SLASH = "https://example.com/"

_HTML_ONE_LINK = (
    "<html><body>"
    '<a href="/page2">Page 2</a>'
    "</body></html>"
)
_HTML_NO_LINKS = "<html><body>No links here.</body></html>"


def _target(max_pages: int = 10, max_depth: int = 3) -> Target:
    return Target.from_url(
        _BASE_URL,
        scan_options=ScanOptions(
            max_pages=max_pages,
            max_depth=max_depth,
            rate_limit_rps=10.0,
        ),
    )


def _mock_transport(pages: dict[str, tuple[int, str, str]]) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        key = str(request.url).rstrip("/")
        match_key = None
        for k in pages:
            if k.rstrip("/") == key:
                match_key = k
                break
        if match_key is None:
            return httpx.Response(404, text="not found", headers={"content-type": "text/html"})
        status, body, ct = pages[match_key]
        return httpx.Response(status, text=body, headers={"content-type": ct})
    return httpx.MockTransport(handler)


def _simple_transport(body: str = _HTML_NO_LINKS, status: int = 200) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text=body, headers={"content-type": "text/html"})
    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# CrawlResult dataclass
# ---------------------------------------------------------------------------


class TestCrawlResultStructure:
    def _make_response(self, url: str = _BASE_URL_SLASH) -> HttpResponse:
        return HttpResponse(
            request_id=uuid4(),
            original_url=url,
            url=url,
            status_code=200,
            headers={"content-type": "text/html"},
            body="<html></html>",
            content_type="text/html",
            elapsed_ms=10.0,
            redirect_count=0,
            redirect_chain=[],
            captured_at=datetime.now(timezone.utc),
        )

    def test_crawl_result_has_url(self):
        r = CrawlResult(url=_BASE_URL_SLASH, depth=0, response=self._make_response(), artifacts=None)
        assert r.url == _BASE_URL_SLASH

    def test_crawl_result_has_depth(self):
        r = CrawlResult(url=_BASE_URL_SLASH, depth=2, response=self._make_response(), artifacts=None)
        assert r.depth == 2

    def test_crawl_result_artifacts_none_when_non_html(self):
        r = CrawlResult(url=_BASE_URL_SLASH, depth=0, response=self._make_response(), artifacts=None)
        assert r.artifacts is None


# ---------------------------------------------------------------------------
# Crawler — seeds root URL
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_crawler_seeds_root_url():
    target = _target()
    ctx = ScanContext(target)
    async with SafeHttpClient(
        target.scan_options,
        transport=_simple_transport(),
        retry_policy=NO_RETRY_POLICY,
    ) as client:
        crawler = Crawler(ctx, client)
        results = await crawler.crawl()
    assert len(results) >= 1
    assert results[0].url.startswith(_BASE_URL)


@pytest.mark.anyio
async def test_crawler_returns_crawl_results_list():
    target = _target()
    ctx = ScanContext(target)
    async with SafeHttpClient(
        target.scan_options,
        transport=_simple_transport(),
        retry_policy=NO_RETRY_POLICY,
    ) as client:
        results = await Crawler(ctx, client).crawl()
    assert isinstance(results, list)
    assert all(isinstance(r, CrawlResult) for r in results)


# ---------------------------------------------------------------------------
# Crawler — max_pages budget
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_crawler_respects_max_pages():
    target = _target(max_pages=1)
    ctx = ScanContext(target)
    # Provide a page with multiple links — crawler should stop after 1 page.
    html = (
        "<html><body>"
        '<a href="/a">A</a><a href="/b">B</a><a href="/c">C</a>'
        "</body></html>"
    )
    async with SafeHttpClient(
        target.scan_options,
        transport=_simple_transport(html),
        retry_policy=NO_RETRY_POLICY,
    ) as client:
        results = await Crawler(ctx, client).crawl()
    assert len(results) <= 1


# ---------------------------------------------------------------------------
# Crawler — max_depth budget
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_crawler_respects_max_depth():
    target = _target(max_pages=100, max_depth=1)
    ctx = ScanContext(target)
    pages = {
        _BASE_URL_SLASH: (200, '<html><body><a href="/level1">L1</a></body></html>', "text/html"),
        "https://example.com/level1": (200, '<html><body><a href="/level2">L2</a></body></html>', "text/html"),
        "https://example.com/level2": (200, "<html><body>Deep</body></html>", "text/html"),
    }
    async with SafeHttpClient(
        target.scan_options,
        transport=_mock_transport(pages),
        retry_policy=NO_RETRY_POLICY,
    ) as client:
        results = await Crawler(ctx, client).crawl()
    urls_visited = [r.url.rstrip("/") for r in results]
    # Level 2 should not be visited when max_depth=1
    assert all("level2" not in u for u in urls_visited)


# ---------------------------------------------------------------------------
# Crawler — error handling
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_crawler_continues_after_failed_response():
    target = _target(max_pages=5, max_depth=2)
    ctx = ScanContext(target)
    error_count = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal error_count
        if "/bad" in str(request.url):
            raise httpx.ConnectError("simulated error", request=request)
        return httpx.Response(
            200,
            text='<html><body><a href="/bad">Bad</a></body></html>',
            headers={"content-type": "text/html"},
        )

    transport = httpx.MockTransport(handler)
    async with SafeHttpClient(
        target.scan_options,
        transport=transport,
        retry_policy=NO_RETRY_POLICY,
    ) as client:
        results = await Crawler(ctx, client).crawl()
    # Should have at least the root result, even though /bad failed
    assert len(results) >= 1


# ---------------------------------------------------------------------------
# Crawler — non-HTML responses produce no artifacts
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_crawler_non_html_response_has_no_artifacts():
    target = _target()
    ctx = ScanContext(target)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="{}", headers={"content-type": "application/json"})

    async with SafeHttpClient(
        target.scan_options,
        transport=httpx.MockTransport(handler),
        retry_policy=NO_RETRY_POLICY,
    ) as client:
        results = await Crawler(ctx, client).crawl()
    assert len(results) == 1
    assert results[0].artifacts is None


# ---------------------------------------------------------------------------
# Crawler — external links not followed
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_crawler_does_not_follow_external_links():
    target = _target(max_pages=10, max_depth=3)
    ctx = ScanContext(target)
    html = (
        "<html><body>"
        '<a href="https://evil.com/steal">External</a>'
        "</body></html>"
    )
    visited_hosts: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        visited_hosts.append(request.url.host)
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    async with SafeHttpClient(
        target.scan_options,
        transport=httpx.MockTransport(handler),
        retry_policy=NO_RETRY_POLICY,
    ) as client:
        await Crawler(ctx, client).crawl()
    assert all(h == "example.com" for h in visited_hosts), \
        f"External host visited: {visited_hosts}"


# ---------------------------------------------------------------------------
# Crawler — pages_crawled counter
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_crawler_updates_pages_crawled():
    target = _target(max_pages=3, max_depth=1)
    ctx = ScanContext(target)
    html = '<html><body><a href="/a">A</a><a href="/b">B</a></body></html>'
    async with SafeHttpClient(
        target.scan_options,
        transport=_simple_transport(html),
        retry_policy=NO_RETRY_POLICY,
    ) as client:
        results = await Crawler(ctx, client).crawl()
    assert ctx.pages_crawled == len(results)
