# WebHound — scanner/tests/test_visibility_route_harvester.py
# Phase 3 tests: JS-route harvesting into the frontier. Reuses the real
# route_extractor.routes_from_script_text. No network.

from __future__ import annotations

from webhound.core.scope import ScopeChecker
from webhound.core.visibility.discovered_url import UrlSource, UrlStatus
from webhound.core.visibility.frontier import VisibilityFrontier
from webhound.core.visibility.route_harvester import harvest_js_routes
from webhound.models.target import ScanOptions, Target


def _frontier(url: str = "https://example.com/", **opts) -> VisibilityFrontier:
    target = Target.from_url(url, scan_options=ScanOptions(**opts))
    return VisibilityFrontier(
        ScopeChecker(target), max_pages=50, max_depth=4,
    )


class _Artifacts:
    def __init__(self, url, inline_scripts=()):
        self.url = url
        self.inline_scripts = list(inline_scripts)
        self.scripts = []


def test_harvests_route_literals_from_inline_script():
    fr = _frontier()
    arts = _Artifacts(
        "https://example.com/",
        inline_scripts=[
            'const routes = ["/dashboard", "/account/settings", "/blog/[slug]"];'
        ],
    )
    n = harvest_js_routes(fr, arts, depth=0, parent="https://example.com/")
    assert n >= 2
    inv = fr.inventory
    dash = inv.get("https://example.com/dashboard")
    assert dash is not None
    assert UrlSource.JS_ROUTE in dash.sources
    assert "inline_script" in dash.tags
    assert dash.status == UrlStatus.QUEUED


def test_skips_cross_origin_route_literals():
    fr = _frontier()
    # A literal that resolves to another host must not enter the page frontier.
    arts = _Artifacts(
        "https://example.com/",
        inline_scripts=['fetch("https://evil.com/api"); const r = "/ok";'],
    )
    harvest_js_routes(fr, arts, depth=0, parent="https://example.com/")
    assert fr.inventory.get("https://example.com/ok") is not None
    assert fr.inventory.get("https://evil.com/api") is None


def test_skips_asset_shaped_literals():
    fr = _frontier()
    arts = _Artifacts(
        "https://example.com/",
        inline_scripts=['load("/static/app.js"); route("/real-page");'],
    )
    harvest_js_routes(fr, arts, depth=0, parent="https://example.com/")
    # /static/app.js is asset/noise-shaped → route_extractor filters it out.
    assert fr.inventory.get("https://example.com/static/app.js") is None
    assert fr.inventory.get("https://example.com/real-page") is not None


def test_child_depth_is_parent_plus_one():
    fr = _frontier()
    arts = _Artifacts(
        "https://example.com/x", inline_scripts=['nav("/y-route")']
    )
    harvest_js_routes(fr, arts, depth=2, parent="https://example.com/x")
    du = fr.inventory.get("https://example.com/y-route")
    assert du is not None
    assert du.depth == 3


def test_no_inline_scripts_is_noop():
    fr = _frontier()
    arts = _Artifacts("https://example.com/", inline_scripts=[])
    assert harvest_js_routes(fr, arts, depth=0, parent=None) == 0
