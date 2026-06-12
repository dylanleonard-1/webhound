# WebHound — scanner/tests/test_visibility_surfaces_api.py
# Phase 6 tests: API endpoint inventory section. Reuses the real
# endpoint_discovery extractor/classifier via PageArtifacts. No network.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from webhound.core.extractor import Extractor
from webhound.core.http_client import HttpResponse
from webhound.core.visibility.surfaces import build_api_section


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


def test_static_rest_and_graphql_endpoints_inventoried():
    html = (
        "<script>"
        'fetch("/api/v1/users");'
        'fetch("https://example.com/graphql");'
        "</script>"
    )
    results = [_Result(_artifacts("https://example.com/", html))]
    section = build_api_section(results, primary_host="example.com")
    assert section["count"] >= 2
    assert section["rest"] >= 1
    assert section["graphql"] >= 1
    # Both endpoints are same-origin (example.com).
    assert section["same_origin"] >= 2


def test_cross_origin_api_counted():
    html = '<script>fetch("https://api.vendor.com/api/data");</script>'
    results = [_Result(_artifacts("https://example.com/", html))]
    section = build_api_section(results, primary_host="example.com")
    assert section["cross_origin"] >= 1


def test_browser_observed_endpoints_merged():
    class _Art:
        def __init__(self, url, kind="fetch", ct="application/json"):
            self.url = url
            self.initiator_kind = kind
            self.content_type = ct

    class _Browser:
        def get_all_network_requests(self):
            return [_Art("https://example.com/api/observed?ts=1")]

    results = []
    section = build_api_section(
        results, browser_discovery=_Browser(), primary_host="example.com"
    )
    assert section["count"] == 1
    assert section["observed_in_browser"] == 1
    # query string stripped → bare url in samples.
    assert section["samples"][0]["url"] == "https://example.com/api/observed"


def test_empty_when_no_endpoints():
    results = [_Result(_artifacts("https://example.com/", "<p>hi</p>"))]
    section = build_api_section(results, primary_host="example.com")
    assert section["count"] == 0
