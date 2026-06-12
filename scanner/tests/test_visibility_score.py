# WebHound — scanner/tests/test_visibility_score.py
# Phase 11 tests: the visibility/coverage score + limitations.

from __future__ import annotations

from webhound.core.visibility.discovered_url import UrlSource
from webhound.core.visibility.inventory import DiscoveredUrlInventory
from webhound.core.visibility.score import compute_visibility_score


def _inv(crawled_depths):
    inv = DiscoveredUrlInventory()
    for i, depth in enumerate(crawled_depths):
        d = inv.add_raw(f"https://example.com/p{i}", source=UrlSource.ANCHOR,
                        depth=depth)
        d.mark_crawled(status_code=200)
    return inv


def _report(**kw):
    base = {
        "pages_found": 10,
        "pages_crawled": 10,
        "source_counts": {"seed": 1, "anchor": 8, "sitemap": 5,
                          "js_route": 2, "form_action": 1},
        "skip_reason_counts": {},
        "forms": {"count": 3},
        "api": {"count": 4},
        "assets": {"count": 9},
        "third_party": {"count": 6},
    }
    base.update(kw)
    return base


def test_full_coverage_scores_high():
    inv = _inv([0, 1, 2, 3])
    score, breakdown, limitations = compute_visibility_score(
        _report(), inventory=inv, max_depth=3, browser_available=True,
    )
    assert score >= 90
    assert breakdown["components"]["completion"] == 45.0  # 10/10
    assert limitations == []


def test_partial_completion_lowers_score():
    inv = _inv([0, 1])
    score, breakdown, _ = compute_visibility_score(
        _report(pages_found=20, pages_crawled=5),
        inventory=inv, max_depth=4, browser_available=True,
    )
    # completion = 5/20 = 0.25 → 11.25 of 45.
    assert breakdown["components"]["completion"] == 11.2 or breakdown["components"]["completion"] == 11.3
    assert score < 70


def test_budget_and_robots_limitations():
    inv = _inv([0, 1])
    report = _report(skip_reason_counts={
        "page budget reached (5 pages)": 12,
        "disallowed by robots.txt": 3,
        "max depth exceeded (4 > 3)": 2,
    })
    _score, _bd, limitations = compute_visibility_score(
        report, inventory=inv, max_depth=3, browser_available=True,
    )
    text = " ".join(limitations)
    assert "page budget" in text
    assert "robots.txt" in text
    assert "max_depth" in text


def test_browser_unavailable_limitation_and_penalty():
    inv = _inv([0, 1, 2])
    score_with, _, _ = compute_visibility_score(
        _report(), inventory=inv, max_depth=3, browser_available=True,
    )
    score_without, bd, limitations = compute_visibility_score(
        _report(), inventory=inv, max_depth=3, browser_available=False,
    )
    assert score_without < score_with  # browser component halved
    assert any("JavaScript/SPA" in m for m in limitations)


def test_botid_single_page_limitation():
    inv = _inv([0])
    report = _report(pages_found=1, pages_crawled=1,
                     source_counts={"seed": 1, "anchor": 1},
                     forms={"count": 0}, api={"count": 0},
                     assets={"count": 0}, third_party={"count": 0})
    score, _bd, limitations = compute_visibility_score(
        report, inventory=inv, max_depth=3, browser_available=False,
    )
    assert any("entry page" in m for m in limitations)
    assert score < 50
