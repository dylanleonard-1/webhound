# WebHound — scanner/tests/test_visibility_crawl_integration.py
# Phase 2 integration: the Crawler driven by the visibility frontier reaches
# pages the homepage never links (sitemap/form-action), while the legacy
# anchor-only path (visibility OFF) does not. No real network — MockTransport.

from __future__ import annotations

import httpx
import pytest

from webhound.core.crawler import Crawler
from webhound.core.http_client import SafeHttpClient
from webhound.core.scan_context import ScanContext
from webhound.core.visibility.context import VisibilityContext
from webhound.core.visibility.discovered_url import UrlStatus
from webhound.models.target import ScanOptions, Target

_HTML = "text/html"


def _transport(pages: dict[str, tuple[int, str, str]]) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        key = str(request.url).rstrip("/")
        for k, (status, body, ct) in pages.items():
            if k.rstrip("/") == key:
                return httpx.Response(status, text=body, headers={"content-type": ct})
        return httpx.Response(404, text="nope", headers={"content-type": _HTML})

    return httpx.MockTransport(handler)


def _target(**opts) -> Target:
    return Target.from_url(
        "https://example.com/",
        scan_options=ScanOptions(max_pages=50, max_depth=3, rate_limit_rps=10.0, **opts),
    )


# Homepage links ONLY to /about. /hidden is reachable only via the sitemap.
_PAGES = {
    "https://example.com/": (200, '<a href="/about">About</a>', _HTML),
    "https://example.com/about": (200, "<p>about</p>", _HTML),
    "https://example.com/hidden": (200, "<p>hidden</p>", _HTML),
}


@pytest.mark.asyncio
async def test_legacy_crawl_misses_unlinked_page():
    ctx = ScanContext(_target())
    async with SafeHttpClient(
        ctx.target.scan_options, transport=_transport(_PAGES)
    ) as client:
        results = await Crawler(ctx, client).crawl()
    crawled = {r.url.rstrip("/") for r in results}
    assert "https://example.com/about" in crawled
    # The unlinked page is invisible to the anchor-only crawl.
    assert "https://example.com/hidden" not in crawled


@pytest.mark.asyncio
async def test_visibility_crawl_reaches_sitemap_only_page():
    ctx = ScanContext(_target())
    vis = VisibilityContext(
        ctx.scope, max_pages=50, max_depth=3, respect_robots=True,
    )
    vis.seed_root(ctx.target.url)
    # Simulate the seeder having found /hidden in the sitemap.
    from webhound.core.visibility.discovered_url import UrlSource

    vis.frontier.add("https://example.com/hidden", source=UrlSource.SITEMAP, depth=1)
    ctx.visibility = vis

    async with SafeHttpClient(
        ctx.target.scan_options, transport=_transport(_PAGES)
    ) as client:
        results = await Crawler(ctx, client).crawl()

    crawled = {r.url.rstrip("/") for r in results}
    # Frontier-driven crawl reaches BOTH the linked and the sitemap-only page.
    assert "https://example.com/about" in crawled
    assert "https://example.com/hidden" in crawled
    # Inventory reflects crawled status + provenance.
    hidden = vis.inventory.get("https://example.com/hidden")
    assert hidden.status == UrlStatus.CRAWLED
    assert UrlSource.SITEMAP in hidden.sources
    # The visibility crawl found at least as many pages as legacy + 1.
    assert vis.inventory.pages_crawled >= 3
