# WebHound — scanner/tests/test_visibility_frontier.py
# Phase 2 tests: inventory dedup, robots policy, the priority frontier, and the
# artifact harvester. No network — pure scheduling + parsing.

from __future__ import annotations

import pytest

from webhound.core.scope import ScopeChecker
from webhound.core.visibility.discovered_url import UrlSource, UrlStatus
from webhound.core.visibility.frontier import VisibilityFrontier
from webhound.core.visibility.harvester import harvest_artifacts
from webhound.core.visibility.inventory import DiscoveredUrlInventory
from webhound.core.visibility.robots_policy import RobotsRules
from webhound.models.target import ScanOptions, Target, TargetScope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scope(url: str = "https://example.com/", **opts) -> ScopeChecker:
    target = Target.from_url(url, scan_options=ScanOptions(**opts))
    return ScopeChecker(target)


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def test_inventory_dedupes_and_merges_provenance():
    inv = DiscoveredUrlInventory()
    a = inv.add_raw("https://example.com/p", source=UrlSource.SITEMAP, depth=1)
    b = inv.add_raw("https://example.com/p", source=UrlSource.ANCHOR, depth=3)
    assert a is b  # same canonical → same record
    assert len(inv) == 1
    assert a.sources == {UrlSource.SITEMAP, UrlSource.ANCHOR}
    assert a.depth == 1  # shallowest wins


def test_inventory_rejects_uncrawlable():
    inv = DiscoveredUrlInventory()
    assert inv.add_raw("mailto:x@y.com", source=UrlSource.ANCHOR) is None
    assert len(inv) == 0


def test_inventory_rollups():
    inv = DiscoveredUrlInventory()
    d1 = inv.add_raw("https://example.com/a", source=UrlSource.SITEMAP)
    d2 = inv.add_raw("https://example.com/b", source=UrlSource.ANCHOR)
    d1.mark_crawled(status_code=200)
    d2.mark_skipped("out of scope: external domain")
    assert inv.pages_found == 2
    assert inv.pages_crawled == 1
    assert inv.status_counts()["crawled"] == 1
    assert inv.skip_reason_counts()["out of scope: external domain"] == 1


# ---------------------------------------------------------------------------
# Robots policy
# ---------------------------------------------------------------------------


def test_robots_disallow_blocks_path():
    rules = RobotsRules.from_robots_txt(
        "User-agent: *\nDisallow: /admin\nAllow: /admin/public\n"
    )
    assert rules.has_rules
    assert not rules.is_allowed("https://example.com/admin/secret")
    assert rules.is_allowed("https://example.com/admin/public/page")  # allow wins
    assert rules.is_allowed("https://example.com/blog")


def test_robots_only_star_group_applies():
    rules = RobotsRules.from_robots_txt(
        "User-agent: BadBot\nDisallow: /\n\nUser-agent: *\nDisallow: /private\n"
    )
    assert rules.is_allowed("https://example.com/anything")
    assert not rules.is_allowed("https://example.com/private/x")


def test_robots_wildcard_and_anchor():
    rules = RobotsRules.from_robots_txt(
        "User-agent: *\nDisallow: /*.pdf$\nDisallow: /tmp/*\n"
    )
    assert not rules.is_allowed("https://example.com/files/report.pdf")
    assert not rules.is_allowed("https://example.com/tmp/anything")
    assert rules.is_allowed("https://example.com/files/report.html")


def test_robots_empty_is_permissive():
    rules = RobotsRules.from_robots_txt("")
    assert not rules.has_rules
    assert rules.is_allowed("https://example.com/whatever")


# ---------------------------------------------------------------------------
# Frontier — scope, depth, robots, priority, budget
# ---------------------------------------------------------------------------


def test_frontier_seed_and_next():
    fr = VisibilityFrontier(_scope(), max_pages=10, max_depth=3)
    fr.seed("https://example.com/")
    du = fr.next()
    assert du is not None
    assert du.url == "https://example.com/"
    assert du.status == UrlStatus.QUEUED


def test_frontier_skips_out_of_scope_with_reason():
    fr = VisibilityFrontier(_scope(), max_pages=10, max_depth=3)
    du = fr.add("https://evil.com/x", source=UrlSource.ANCHOR, depth=1)
    assert du is not None
    assert du.in_scope is False
    assert du.status == UrlStatus.SKIPPED
    assert "out of scope" in du.skip_reason


def test_frontier_skips_over_depth_with_reason():
    fr = VisibilityFrontier(_scope(), max_pages=10, max_depth=2)
    du = fr.add("https://example.com/deep", source=UrlSource.ANCHOR, depth=5)
    assert du.status == UrlStatus.SKIPPED
    assert "max depth" in du.skip_reason


def test_frontier_respects_robots_but_never_blocks_seed():
    rules = RobotsRules.from_robots_txt("User-agent: *\nDisallow: /\n")
    fr = VisibilityFrontier(
        _scope(), max_pages=10, max_depth=3, respect_robots=True, robots_rules=rules
    )
    # Seed is never robots-blocked.
    seed = fr.seed("https://example.com/")
    assert seed.status == UrlStatus.QUEUED
    # A discovered URL under Disallow: / is skipped with a robots reason.
    du = fr.add("https://example.com/page", source=UrlSource.ANCHOR, depth=1)
    assert du.status == UrlStatus.SKIPPED
    assert "robots" in du.skip_reason


def test_frontier_robots_override_when_disabled():
    rules = RobotsRules.from_robots_txt("User-agent: *\nDisallow: /\n")
    fr = VisibilityFrontier(
        _scope(), max_pages=10, max_depth=3, respect_robots=False, robots_rules=rules
    )
    du = fr.add("https://example.com/page", source=UrlSource.ANCHOR, depth=1)
    assert du.status == UrlStatus.QUEUED  # override honoured


def test_frontier_priority_high_value_first():
    fr = VisibilityFrontier(_scope(), max_pages=10, max_depth=5)
    fr.add("https://example.com/blog/post-1", source=UrlSource.ANCHOR, depth=1)
    fr.add("https://example.com/login", source=UrlSource.ANCHOR, depth=1)
    fr.add("https://example.com/asset", source=UrlSource.SCRIPT_SRC, depth=1)
    # login (high-value keyword → priority 0) comes out before the blog post.
    first = fr.next()
    assert "/login" in first.url


def test_frontier_sitemap_prioritised_over_asset():
    fr = VisibilityFrontier(_scope(), max_pages=10, max_depth=5)
    fr.add("https://example.com/z-asset", source=UrlSource.SCRIPT_SRC, depth=1)
    fr.add("https://example.com/a-sitemap-page", source=UrlSource.SITEMAP, depth=1)
    first = fr.next()
    assert "sitemap-page" in first.url


def test_frontier_dedupe_does_not_requeue():
    fr = VisibilityFrontier(_scope(), max_pages=10, max_depth=5)
    fr.add("https://example.com/p", source=UrlSource.ANCHOR, depth=1)
    fr.add("https://example.com/p", source=UrlSource.SITEMAP, depth=1)
    assert fr.next().url == "https://example.com/p"
    assert fr.next() is None  # only queued once
    assert fr.inventory.get("https://example.com/p").sources == {
        UrlSource.ANCHOR,
        UrlSource.SITEMAP,
    }


def test_frontier_page_budget_drains_remaining_as_skipped():
    fr = VisibilityFrontier(_scope(), max_pages=1, max_depth=5)
    fr.add("https://example.com/one", source=UrlSource.ANCHOR, depth=1)
    fr.add("https://example.com/two", source=UrlSource.ANCHOR, depth=1)
    first = fr.next()
    fr.mark_crawled(first, status_code=200)
    # Budget spent → next() returns None and remaining is skipped w/ reason.
    assert fr.next() is None
    two = fr.inventory.get("https://example.com/two")
    assert two.status == UrlStatus.SKIPPED
    assert "budget" in two.skip_reason


# ---------------------------------------------------------------------------
# Harvester — pulls navigable sources from PageArtifacts
# ---------------------------------------------------------------------------


class _FakeForm:
    def __init__(self, action_url, method):
        self.action_url = action_url
        self.method = method


class _FakeIframe:
    def __init__(self, src_url):
        self.src_url = src_url


class _FakeArtifacts:
    def __init__(self, url, *, all_links=(), forms=(), iframes=(), canonical=()):
        self.url = url
        self.all_links = list(all_links)
        self.forms = list(forms)
        self.iframes = list(iframes)
        self.external_canonical_urls = list(canonical)


def test_harvester_feeds_anchors_forms_iframes():
    fr = VisibilityFrontier(_scope(), max_pages=50, max_depth=5)
    arts = _FakeArtifacts(
        "https://example.com/",
        all_links=["https://example.com/about", "https://example.com/contact"],
        forms=[
            _FakeForm("https://example.com/search", "GET"),
            _FakeForm("https://example.com/login-submit", "POST"),  # never queued
        ],
        iframes=[_FakeIframe("https://example.com/embed")],
    )
    harvest_artifacts(fr, arts, depth=0, parent="https://example.com/")
    inv = fr.inventory
    assert inv.get("https://example.com/about") is not None
    assert inv.get("https://example.com/search") is not None  # GET form action
    # POST form action is a submission — never discovered as a crawl target.
    assert inv.get("https://example.com/login-submit") is None
    assert inv.get("https://example.com/embed") is not None  # same-host iframe
    # Sources recorded correctly.
    assert UrlSource.FORM_ACTION in inv.get("https://example.com/search").sources
    assert UrlSource.IFRAME in inv.get("https://example.com/embed").sources


def test_harvester_child_depth_is_parent_plus_one():
    fr = VisibilityFrontier(_scope(), max_pages=50, max_depth=5)
    arts = _FakeArtifacts(
        "https://example.com/x",
        all_links=["https://example.com/y"],
    )
    harvest_artifacts(fr, arts, depth=2, parent="https://example.com/x")
    assert fr.inventory.get("https://example.com/y").depth == 3
