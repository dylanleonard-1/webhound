# WebHound — scanner/tests/test_visibility_surfaces_assets.py
# Phase 7 tests: asset intelligence section. Reuses the real extractor's
# per-page asset fields. No network.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from webhound.core.extractor import Extractor
from webhound.core.http_client import HttpResponse
from webhound.core.visibility.surfaces import build_assets_section


def _artifacts(url: str, html: str):
    resp = HttpResponse(
        request_id=uuid4(), original_url=url, url=url, status_code=200,
        headers={"content-type": "text/html"}, body=html,
        content_type="text/html", elapsed_ms=10.0, redirect_count=0,
        redirect_chain=[], captured_at=datetime.now(timezone.utc),
    )
    return Extractor().extract(resp)


class _Result:
    def __init__(self, artifacts):
        self.artifacts = artifacts


def test_classifies_scripts_styles_images():
    html = (
        '<script src="https://cdn.example.com/app.js"></script>'
        '<script>console.log(1)</script>'
        '<link rel="stylesheet" href="https://cdn.example.com/site.css">'
        '<img src="https://img.example.com/logo.png">'
    )
    results = [_Result(_artifacts("https://example.com/", html))]
    section = build_assets_section(results, primary_host="example.com")
    assert section["scripts"] >= 1
    assert section["stylesheets"] >= 1
    assert section["images"] >= 1
    assert section["inline_scripts"] == 1
    # All cdn/img hosts differ from example.com → third-party assets.
    assert section["third_party_assets"] >= 3


def test_browser_script_urls_merged():
    class _Browser:
        def get_all_script_urls(self):
            return ["https://example.com/chunk.js", "https://vendor.com/sdk.js"]

    section = build_assets_section(
        [], browser_discovery=_Browser(), primary_host="example.com"
    )
    assert section["scripts"] == 2
    assert section["same_host_assets"] == 1
    assert section["third_party_assets"] == 1


def test_empty_when_no_assets():
    results = [_Result(_artifacts("https://example.com/", "<p>hi</p>"))]
    section = build_assets_section(results, primary_host="example.com")
    assert section["count"] == 0
