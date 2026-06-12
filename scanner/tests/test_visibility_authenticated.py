# WebHound — scanner/tests/test_visibility_authenticated.py
# Phase 9 tests: authenticated-surface report section + authenticated tagging
# of browser-discovered routes. No network/Playwright.

from __future__ import annotations

from webhound.core.scope import ScopeChecker
from webhound.core.visibility.browser_routes import feed_browser_routes
from webhound.core.visibility.context import VisibilityContext
from webhound.core.visibility.frontier import VisibilityFrontier
from webhound.core.visibility.report import build_visibility_report
from webhound.models.target import ScanOptions, Target


def _frontier(url="https://example.com/", **opts):
    target = Target.from_url(url, scan_options=ScanOptions(**opts))
    return VisibilityFrontier(ScopeChecker(target), max_pages=50, max_depth=5)


class _Tel:
    def __init__(self, page_url, client_routes=()):
        self.page_url = page_url
        self.final_url = None
        self.rendered_links = []
        self.client_routes = list(client_routes)


def test_extra_tags_applied_to_routes():
    fr = _frontier()
    tels = [_Tel("https://example.com/account", client_routes=[("/orders", "anchor")])]
    feed_browser_routes(fr, tels, extra_tags={"authenticated"})
    du = fr.inventory.get("https://example.com/orders")
    assert du is not None
    assert "authenticated" in du.tags


# --- report authenticated section ---


class _FakeScanResult:
    def __init__(self, metadata):
        self.metadata = metadata


class _FakeBrowser:
    def get_all_forms(self):
        return []

    def get_all_network_requests(self):
        return []

    def get_all_script_urls(self):
        return []


class _FakeCtx:
    def __init__(self, metadata):
        target = Target.from_url("https://example.com/", scan_options=ScanOptions())
        self.visibility = VisibilityContext(
            ScopeChecker(target), max_pages=10, max_depth=3
        )
        self.scan_result = _FakeScanResult(metadata)
        self.browser = _FakeBrowser()


def test_report_authenticated_section_from_metadata():
    meta = {
        "auth": {
            "available": True,
            "mode": "combined",
            "expired": False,
            "authenticated_page_count": 4,
            "authenticated_api_count": 7,
            "authenticated_form_count": 2,
            "authenticated_route_count": 5,
            "authenticated_third_parties": ["a.com", "b.com"],
            "auth_domains": ["example.com"],
        }
    }
    ctx = _FakeCtx(meta)
    report = build_visibility_report(ctx, crawl_results=[], domain="example.com")
    auth = report["authenticated"]
    assert auth["enabled"] is True
    assert auth["mode"] == "combined"
    assert auth["pages"] == 4
    assert auth["apis"] == 7
    assert auth["routes"] == 5
    assert auth["third_parties"] == 2


def test_report_authenticated_section_defaults_when_absent():
    ctx = _FakeCtx({})
    report = build_visibility_report(ctx, crawl_results=[], domain="example.com")
    assert report["authenticated"]["enabled"] is False
