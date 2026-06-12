"""Audit #2 — endpoint_discovery must not count social/profile links as API endpoints,
and a bare URL in a script body must be API-shaped. Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

from datetime import datetime, timezone

from webhound.core.extractor import PageArtifacts
from webhound.engines.api_discovery.endpoint_discovery import (
    EndpointDiscoveryEngine,
    _gather_endpoints,
    _host_is_social,
    _looks_like_api_url,
)


def _arts(url="https://t.test/", inline_scripts=None, inline_js_request_urls=None):
    return PageArtifacts(
        url=url, status_code=200, content_type="text/html", title=None,
        all_links=[], internal_links=[], external_links=[], scripts=[],
        inline_scripts=inline_scripts or [], external_script_urls=[], forms=[],
        cookies=[], response_headers={}, meta_tags={},
        inline_js_request_urls=inline_js_request_urls or [],
        extracted_at=datetime.now(timezone.utc),
    )


def test_host_is_social():
    assert _host_is_social("x.com") is True
    assert _host_is_social("www.linkedin.com") is True
    assert _host_is_social("github.com") is True
    assert _host_is_social("api.webhoundsecurity.com") is False


def test_looks_like_api_url():
    assert _looks_like_api_url("https://x.com/webhoundsecurity") is False           # social
    assert _looks_like_api_url("https://webhoundsecurity.com/about") is False        # marketing
    assert _looks_like_api_url("https://api.example.com/v2/users") is True           # /v2/
    assert _looks_like_api_url("https://example.com/api/orders") is True             # /api/
    assert _looks_like_api_url("https://example.com/graphql") is True
    assert _looks_like_api_url("https://example.com/data.json") is True


def test_social_link_in_script_body_not_an_endpoint():
    # The real FP: a social profile link inside a __NEXT_DATA__/JSON blob.
    body = '{"props":{"sameAs":["https://x.com/webhoundsecurity","https://www.linkedin.com/company/wh"]}}'
    eps = _gather_endpoints(_arts(inline_scripts=[body]))
    assert eps == [], f"social links must not count as endpoints, got {eps}"
    # And no "API surface mapped" finding is emitted.
    assert EndpointDiscoveryEngine().analyze(_arts(inline_scripts=[body])) == []


def test_real_api_paths_still_discovered():
    body = 'fetch("/api/scan"); const u = "https://example.com/graphql"; const s = "https://x.com/foo";'
    eps = _gather_endpoints(_arts(inline_scripts=[body]))
    assert "/api/scan" in eps
    assert "https://example.com/graphql" in eps
    assert "https://x.com/foo" not in eps  # social excluded


def test_real_fetch_targets_kept_social_dropped():
    # inline_js_request_urls = genuine fetch/XHR targets; keep non-social ones.
    arts = _arts(inline_js_request_urls=["https://t.test/api/me", "https://x.com/intent/tweet"])
    eps = _gather_endpoints(arts)
    assert "https://t.test/api/me" in eps
    assert "https://x.com/intent/tweet" not in eps
