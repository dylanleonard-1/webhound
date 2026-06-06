# WebHound — tests/test_route_extractor.py
# Phase-6B client-route discovery. Pure unit tests — no Playwright,
# no navigation.

from __future__ import annotations

import pytest

from webhound.browser.models import BrowserTelemetry, RenderedScript
from webhound.browser.route_extractor import (
    capture_routes,
    collect_routes,
    routes_from_script_text,
)


def _tel(**kw) -> BrowserTelemetry:
    tel = BrowserTelemetry(page_url="https://target.test/app")
    for k, v in kw.items():
        setattr(tel, k, v)
    return tel


# ---------------------------------------------------------------------------
# Script-string extraction
# ---------------------------------------------------------------------------


def test_route_literals_extracted_from_script_text() -> None:
    js = """
      router.push('/dashboard/settings');
      const x = "/api/v1/users";
      navigate("/blog/[slug]");
      fetch('/cart');
    """
    routes = routes_from_script_text(js)
    assert "/dashboard/settings" in routes
    assert "/api/v1/users" in routes
    assert "/blog/[slug]" in routes
    assert "/cart" in routes


def test_asset_paths_and_noise_filtered() -> None:
    js = """
      import('/static/chunk-abc123.js');
      const css = "/assets/main.css";
      const img = '/img/logo.png';
      const cdn = "//cdn.example.com/x";
      const nx = '/_next/static/chunks/pages/index-1a2b.js';
      const num = "/1234/5678";
    """
    assert routes_from_script_text(js) == []


def test_script_string_route_cap() -> None:
    js = "\n".join(f"x('/page-{i}/view');" for i in range(400))
    assert len(routes_from_script_text(js)) == 150


# ---------------------------------------------------------------------------
# collect_routes — source merging + dedup
# ---------------------------------------------------------------------------


def test_collect_routes_merges_sources_with_priority() -> None:
    tel = _tel(
        rendered_links=[
            "https://target.test/pricing",
            "https://other.example.com/external",  # cross-origin → not a route
        ],
        rendered_scripts=[RenderedScript(
            kind="inline", is_inline=True,
            snippet="router.push('/hidden-admin')",
        )],
    )
    probe = {
        "nextPage": "/products/[id]",
        "nextRoutes": ["/checkout", "/pricing"],  # /pricing dupes anchor
        "nuxtRoute": "/landing",
        "dataHrefs": ["/promo"],
    }
    collect_routes(tel, probe)
    routes = dict(tel.client_routes)
    assert routes["/pricing"] == "anchor"          # anchor wins the dupe
    assert routes["/products/[id]"] == "next_data"
    assert routes["/checkout"] == "next_data"
    assert routes["/landing"] == "nuxt"
    assert routes["/promo"] == "data_href"
    assert routes["/hidden-admin"] == "script_string"
    assert "/external" not in routes


def test_collect_routes_handles_missing_probe() -> None:
    tel = _tel(rendered_links=["https://target.test/about"])
    collect_routes(tel, None)
    assert tel.client_routes == [("/about", "anchor")]


def test_collect_routes_cap_enforced() -> None:
    tel = _tel(rendered_links=[
        f"https://target.test/page-{i}" for i in range(800)
    ])
    collect_routes(tel, None)
    assert len(tel.client_routes) == 500


# ---------------------------------------------------------------------------
# capture_routes — defensive evaluate wrapper
# ---------------------------------------------------------------------------


class _FailingPage:
    async def evaluate(self, _script):
        raise RuntimeError("destroyed")


@pytest.mark.asyncio
async def test_capture_routes_probe_failure_still_collects() -> None:
    """Probe eval dies → anchors are still folded in."""
    tel = _tel(rendered_links=["https://target.test/contact"])
    await capture_routes(_FailingPage(), tel)
    assert ("/contact", "anchor") in tel.client_routes
    assert any("route probe failed" in e for e in tel.errors)
