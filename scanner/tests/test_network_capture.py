# WebHound — tests/test_network_capture.py
# Phase-6B network-request classification. Pure unit tests, no
# Playwright, no network.

from __future__ import annotations

from webhound.browser.models import BrowserTelemetry, NetworkArtifact
from webhound.browser.network_capture import (
    classify_artifact,
    looks_like_api,
    summarize_network,
)


def _art(url, kind="script", page="https://target.test/app",
         content_type=None) -> NetworkArtifact:
    return NetworkArtifact(
        url=url, method="GET", initiator_kind=kind,
        page_url=page, content_type=content_type,
    )


# ---------------------------------------------------------------------------
# looks_like_api
# ---------------------------------------------------------------------------


def test_fetch_and_xhr_are_api_by_kind() -> None:
    assert looks_like_api("https://t.test/x", initiator_kind="fetch")[0]
    assert looks_like_api("https://t.test/x", initiator_kind="xhr")[0]
    assert looks_like_api("wss://t.test/x", initiator_kind="websocket")[0]


def test_api_path_tokens() -> None:
    for path in ("/api/v2/users", "/graphql", "/wp-json/wp/v2/posts",
                 "/wp-admin/admin-ajax.php"):
        is_api, reason = looks_like_api(f"https://t.test{path}")
        assert is_api, path
        assert reason and reason.startswith("path:")


def test_api_segment_tokens_are_segment_anchored() -> None:
    # /search is a full segment → API-ish.
    assert looks_like_api("https://t.test/search?q=x")[0]
    assert looks_like_api("https://t.test/cart")[0]
    assert looks_like_api("https://t.test/auth/callback")[0]
    # "research" merely *contains* "search" → must NOT fire.
    assert not looks_like_api("https://t.test/research")[0]
    assert not looks_like_api("https://t.test/cartography")[0]


def test_json_content_type_is_api() -> None:
    is_api, reason = looks_like_api(
        "https://t.test/data", content_type="application/json; charset=utf-8",
    )
    assert is_api and reason == "content_type:json"


def test_plain_asset_is_not_api() -> None:
    assert not looks_like_api(
        "https://t.test/assets/logo.png",
        initiator_kind="image", content_type="image/png",
    )[0]


# ---------------------------------------------------------------------------
# classify_artifact — origin / third-party
# ---------------------------------------------------------------------------


def test_same_origin_detection() -> None:
    cls = classify_artifact(_art("https://target.test/static/app.js"))
    assert cls.is_same_origin is True
    assert cls.is_third_party is False


def test_subdomain_is_cross_origin_but_first_party() -> None:
    """cdn.target.test differs by hostname but shares the registrable
    domain — it must not be called third-party."""
    cls = classify_artifact(_art("https://cdn.target.test/app.js"))
    assert cls.is_same_origin is False
    assert cls.is_third_party is False


def test_other_registrable_domain_is_third_party() -> None:
    cls = classify_artifact(_art("https://analytics.vendor.com/beacon"))
    assert cls.is_same_origin is False
    assert cls.is_third_party is True


def test_classify_uses_explicit_page_host_over_page_url() -> None:
    cls = classify_artifact(
        _art("https://other.test/x"), page_host="other.test",
    )
    assert cls.is_same_origin is True


# ---------------------------------------------------------------------------
# summarize_network
# ---------------------------------------------------------------------------


def test_summarize_network_rollup() -> None:
    tel = BrowserTelemetry(page_url="https://target.test/")
    tel.add(_art("https://target.test/api/users", kind="fetch"))
    tel.add(_art("https://target.test/static/app.js", kind="script"))
    tel.add(_art("https://vendor.com/pixel.gif", kind="image"))
    tel.add(_art("https://vendor.com/v1/collect", kind="xhr"))

    s = summarize_network([tel], primary_host="target.test")
    assert s.total_requests == 4
    assert s.api_requests == 2          # fetch + xhr
    assert s.same_origin_requests == 2
    assert s.third_party_requests == 2
    assert s.third_party_domains == {"vendor.com"}
    d = s.to_dict()
    assert d["browser_api_requests"] == 2
    assert d["browser_third_party_domains"] == ["vendor.com"]
    assert "https://target.test/api/users" in d["browser_api_sample_urls"]


def test_summarize_api_sample_cap() -> None:
    tel = BrowserTelemetry(page_url="https://target.test/")
    for i in range(60):
        tel.add(_art(f"https://target.test/api/items/{i}", kind="fetch"))
    s = summarize_network([tel])
    assert s.api_requests == 60
    assert len(s.api_sample_urls) == 25
