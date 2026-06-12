# WebHound — scanner/webhound/core/visibility/score.py
# Phase 11: the 0-100 visibility / coverage score + an explainable breakdown +
# a plain-language limitations list.
#
# This measures how COMPLETELY the scan saw the site's public surface — NOT how
# secure the site is (that's the risk score). The breakdown mirrors the risk
# scorer's "show WHY" pattern so the dashboard can explain every point.
#
# Safe-mode: pure arithmetic over the already-built report + inventory.

from __future__ import annotations

from typing import Any

from webhound.core.visibility.discovered_url import UrlStatus

# Component weights (sum = 100).
_W_COMPLETION = 45   # crawled / found
_W_BREADTH = 20      # how many distinct discovery sources contributed
_W_DEPTH = 15        # deepest level reached vs the configured max
_W_BROWSER = 10      # did the JS/SPA browser pass run
_W_SURFACES = 10     # forms/api/assets/third_party actually inventoried

# Distinct discovery sources we'd expect a thorough crawl to exercise.
_BREADTH_TARGET = 5


def compute_visibility_score(
    report: dict,
    *,
    inventory: Any,
    max_depth: int,
    browser_available: bool,
) -> tuple[int, dict, list[str]]:
    """Return ``(score, breakdown, limitations)``.

    *score* is 0-100. *breakdown* explains each weighted component. *limitations*
    is a list of plain-language caveats drawn from skip reasons + coverage gaps."""
    pages_found = max(0, int(report.get("pages_found", 0)))
    pages_crawled = max(0, int(report.get("pages_crawled", 0)))
    source_counts = report.get("source_counts", {}) or {}
    skip_reasons = report.get("skip_reason_counts", {}) or {}

    # 1. Crawl completion — fraction of discovered in-scope pages we fetched.
    completion = (pages_crawled / pages_found) if pages_found else 0.0
    completion = min(1.0, completion)
    # A "100% crawl" of a single discovered page is not real coverage — when
    # only the entry page was found (common under a bot-challenge / WAF), the
    # completion signal is untrustworthy, so halve its credit.
    if pages_found <= 1:
        completion *= 0.5

    # 2. Discovery breadth — distinct sources that actually contributed.
    distinct_sources = len([s for s, c in source_counts.items() if c > 0])
    breadth = min(1.0, distinct_sources / _BREADTH_TARGET)

    # 3. Depth — deepest crawled level vs configured max_depth.
    crawled_depths = [
        d.depth for d in inventory.all() if d.status == UrlStatus.CRAWLED
    ]
    reached = max(crawled_depths) if crawled_depths else 0
    depth_frac = min(1.0, reached / max_depth) if max_depth > 0 else 0.0

    # 4. Browser coverage — JS/SPA exploration ran?
    browser_frac = 1.0 if browser_available else 0.5

    # 5. Surface discovery — how many surface types we inventoried.
    surface_hits = sum(
        1 for key in ("forms", "api", "assets", "third_party")
        if (report.get(key) or {}).get("count", 0) > 0
    )
    surfaces = surface_hits / 4.0

    components = {
        "completion": round(completion * _W_COMPLETION, 1),
        "breadth": round(breadth * _W_BREADTH, 1),
        "depth": round(depth_frac * _W_DEPTH, 1),
        "browser": round(browser_frac * _W_BROWSER, 1),
        "surfaces": round(surfaces * _W_SURFACES, 1),
    }
    score = int(round(sum(components.values())))
    score = max(0, min(100, score))

    breakdown = {
        "score": score,
        "components": components,
        "weights": {
            "completion": _W_COMPLETION, "breadth": _W_BREADTH,
            "depth": _W_DEPTH, "browser": _W_BROWSER, "surfaces": _W_SURFACES,
        },
        "inputs": {
            "pages_found": pages_found,
            "pages_crawled": pages_crawled,
            "completion_ratio": round(completion, 3),
            "distinct_sources": distinct_sources,
            "depth_reached": reached,
            "max_depth": max_depth,
            "browser_available": browser_available,
            "surface_types_found": surface_hits,
        },
    }

    limitations = _build_limitations(
        report, skip_reasons=skip_reasons, browser_available=browser_available,
        pages_found=pages_found, pages_crawled=pages_crawled,
    )
    return score, breakdown, limitations


def _build_limitations(
    report: dict,
    *,
    skip_reasons: dict,
    browser_available: bool,
    pages_found: int,
    pages_crawled: int,
) -> list[str]:
    out: list[str] = []

    budget_skips = sum(
        c for r, c in skip_reasons.items() if "budget" in r.lower()
    )
    if budget_skips:
        out.append(
            f"Crawl truncated at the page budget — {budget_skips} discovered "
            "URL(s) were not crawled. Increase max_pages for fuller coverage."
        )

    robots_skips = sum(
        c for r, c in skip_reasons.items() if "robots" in r.lower()
    )
    if robots_skips:
        out.append(
            f"{robots_skips} URL(s) skipped per robots.txt (respected by "
            "default; a verified customer can opt to override)."
        )

    depth_skips = sum(
        c for r, c in skip_reasons.items() if "depth" in r.lower()
    )
    if depth_skips:
        out.append(
            f"{depth_skips} URL(s) beyond max_depth were not crawled — "
            "increase max_depth to reach deeper pages."
        )

    if not browser_available:
        out.append(
            "JavaScript/SPA exploration did not run (browser pass disabled or "
            "unavailable) — client-rendered routes may be under-counted."
        )

    if pages_found <= 1 and pages_crawled <= 1:
        out.append(
            "Only the entry page was reachable — the site may be bot-protected "
            "(challenge/WAF) or fully JS-gated. Run with an allowlisted IP / "
            "the browser pass for representative coverage."
        )

    return out
