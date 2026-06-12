# WebHound — scanner/tests/test_visibility_browser_routes.py
# Phase 4 tests: feeding browser-discovered navigable URLs (rendered-DOM
# anchors + SPA client routes) into the frontier. No network/Playwright —
# duck-typed telemetry fakes.

from __future__ import annotations

from webhound.core.scope import ScopeChecker
from webhound.core.visibility.browser_routes import feed_browser_routes
from webhound.core.visibility.discovered_url import UrlSource, UrlStatus
from webhound.core.visibility.frontier import VisibilityFrontier
from webhound.models.target import ScanOptions, Target


def _frontier(url: str = "https://example.com/", **opts) -> VisibilityFrontier:
    target = Target.from_url(url, scan_options=ScanOptions(**opts))
    return VisibilityFrontier(ScopeChecker(target), max_pages=50, max_depth=5)


class _Tel:
    def __init__(self, page_url, *, final_url=None, rendered_links=(), client_routes=()):
        self.page_url = page_url
        self.final_url = final_url
        self.rendered_links = list(rendered_links)
        self.client_routes = list(client_routes)


def test_feeds_rendered_links_as_anchor():
    fr = _frontier()
    tels = [_Tel(
        "https://example.com/",
        rendered_links=["https://example.com/spa-only", "https://example.com/contact"],
    )]
    n = feed_browser_routes(fr, tels)
    assert n == 2
    du = fr.inventory.get("https://example.com/spa-only")
    assert du is not None
    assert UrlSource.ANCHOR in du.sources
    assert "rendered_link" in du.tags and "browser_explorer" in du.tags
    assert du.status == UrlStatus.QUEUED


def test_feeds_client_routes_with_framework_tag():
    fr = _frontier()
    tels = [_Tel(
        "https://example.com/",
        client_routes=[("/dashboard", "next_data"), ("/account", "data_href")],
    )]
    feed_browser_routes(fr, tels)
    dash = fr.inventory.get("https://example.com/dashboard")
    assert dash is not None
    assert UrlSource.JS_ROUTE in dash.sources
    assert "nextjs" in dash.tags  # next_data → nextjs
    acct = fr.inventory.get("https://example.com/account")
    assert "data_href" in acct.tags


def test_cross_origin_rendered_link_skipped_with_reason():
    fr = _frontier()
    tels = [_Tel("https://example.com/", rendered_links=["https://other.com/x"])]
    feed_browser_routes(fr, tels)
    du = fr.inventory.get("https://other.com/x")
    assert du is not None
    assert du.status == UrlStatus.SKIPPED
    assert "out of scope" in du.skip_reason


def test_child_depth_from_page_depth():
    fr = _frontier()
    # Seed the page at depth 2 so its browser-discovered children land at 3.
    fr.add("https://example.com/section", source=UrlSource.ANCHOR, depth=2)
    tels = [_Tel(
        "https://example.com/section",
        client_routes=[("/section/detail", "anchor")],
    )]
    feed_browser_routes(fr, tels)
    du = fr.inventory.get("https://example.com/section/detail")
    assert du is not None
    assert du.depth == 3


def test_final_url_preferred_over_page_url():
    fr = _frontier()
    tels = [_Tel(
        "https://example.com/redirect-src",
        final_url="https://example.com/landing",
        rendered_links=["nested"],
    )]
    feed_browser_routes(fr, tels)
    # 'nested' resolves against final_url.
    assert fr.inventory.get("https://example.com/nested") is not None


def test_empty_telemetries_is_noop():
    fr = _frontier()
    assert feed_browser_routes(fr, []) == 0
    assert feed_browser_routes(fr, None) == 0
