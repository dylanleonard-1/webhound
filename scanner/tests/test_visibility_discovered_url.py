# WebHound — scanner/tests/test_visibility_discovered_url.py
# Phase 1 tests: DiscoveredUrl record + normalize_url canonicalization wrapper.

from __future__ import annotations

import pytest

from webhound.core.visibility import (
    DiscoveredUrl,
    UrlSource,
    UrlStatus,
    canonicalize,
    normalize_url,
)


# ---------------------------------------------------------------------------
# normalize_url / canonicalize — delegates to UrlNormalizer
# ---------------------------------------------------------------------------


def test_normalize_url_canonical_form():
    assert normalize_url("HTTP://Example.com:80//a//b?x=1#frag") == (
        "http://example.com/a/b?x=1"
    )


def test_normalize_url_strips_https_default_port_and_fragment():
    assert normalize_url("https://Example.com:443/path#section") == (
        "https://example.com/path"
    )


def test_normalize_url_empty_path_becomes_slash():
    assert normalize_url("https://example.com") == "https://example.com/"


def test_normalize_url_resolves_relative_against_base():
    assert normalize_url("/about", base_url="https://example.com/x/y") == (
        "https://example.com/about"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "javascript:alert(1)",
        "mailto:a@b.com",
        "tel:+15551234",
        "data:text/html,hi",
        "#top",
        "",
        "   ",
        "ftp://example.com/file",
    ],
)
def test_normalize_url_rejects_non_crawlable(bad):
    assert normalize_url(bad) is None


def test_canonicalize_is_alias_of_normalize_url():
    assert canonicalize is normalize_url


# ---------------------------------------------------------------------------
# DiscoveredUrl.create
# ---------------------------------------------------------------------------


def test_create_sets_canonical_url_and_source():
    du = DiscoveredUrl.create(
        "HTTPS://Example.com/A?b=2#x", source=UrlSource.SITEMAP
    )
    assert du is not None
    assert du.url == "https://example.com/A?b=2"
    assert du.normalized == du.url
    assert du.sources == {UrlSource.SITEMAP}
    assert du.discovered_via == UrlSource.SITEMAP
    assert du.status == UrlStatus.PENDING


def test_create_resolves_relative_with_base_and_depth_parent():
    du = DiscoveredUrl.create(
        "team",
        source=UrlSource.ANCHOR,
        base_url="https://example.com/about/",
        depth=2,
        parent="https://example.com/about/",
    )
    assert du is not None
    assert du.url == "https://example.com/about/team"
    assert du.depth == 2
    assert du.parent == "https://example.com/about/"


def test_create_returns_none_for_uncrawlable():
    assert DiscoveredUrl.create("mailto:x@y.com", source=UrlSource.ANCHOR) is None
    assert DiscoveredUrl.create("#frag", source=UrlSource.ANCHOR) is None


# ---------------------------------------------------------------------------
# Mutation helpers
# ---------------------------------------------------------------------------


def test_add_source_unions_and_keeps_first_discovered_via():
    du = DiscoveredUrl.create("https://example.com/", source=UrlSource.SEED)
    assert du is not None
    du.add_source(UrlSource.SITEMAP)
    du.add_source(UrlSource.ANCHOR)
    assert du.sources == {UrlSource.SEED, UrlSource.SITEMAP, UrlSource.ANCHOR}
    assert du.discovered_via == UrlSource.SEED  # first one wins


def test_mark_crawled_records_status_and_clears_skip():
    du = DiscoveredUrl.create("https://example.com/", source=UrlSource.SEED)
    assert du is not None
    du.mark_skipped("temporarily")
    du.mark_crawled(status_code=200, content_type="text/html")
    assert du.status == UrlStatus.CRAWLED
    assert du.status_code == 200
    assert du.content_type == "text/html"
    assert du.skip_reason is None


def test_mark_skipped_records_reason():
    du = DiscoveredUrl.create("https://example.com/x", source=UrlSource.JS_ROUTE)
    assert du is not None
    du.mark_skipped("out of scope: external domain")
    assert du.status == UrlStatus.SKIPPED
    assert du.skip_reason == "out of scope: external domain"


def test_mark_queued_only_promotes_from_pending():
    du = DiscoveredUrl.create("https://example.com/", source=UrlSource.SEED)
    assert du is not None
    du.mark_queued()
    assert du.status == UrlStatus.QUEUED
    # A terminal state is never overwritten by mark_queued.
    du.mark_crawled(status_code=200)
    du.mark_queued()
    assert du.status == UrlStatus.CRAWLED


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def test_to_dict_is_json_safe_and_sorted_sources():
    du = DiscoveredUrl.create("https://example.com/", source=UrlSource.SEED)
    assert du is not None
    du.add_source(UrlSource.SITEMAP)
    du.mark_crawled(status_code=200, content_type="text/html")
    d = du.to_dict()
    assert d["url"] == "https://example.com/"
    assert d["sources"] == ["seed", "sitemap"]
    assert d["discovered_via"] == "seed"
    assert d["status"] == "crawled"
    assert d["status_code"] == 200
    assert d["skip_reason"] is None
    # All values must be JSON-serializable primitives.
    import json

    json.dumps(d)
