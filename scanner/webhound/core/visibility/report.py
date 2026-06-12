# WebHound — scanner/webhound/core/visibility/report.py
# Assembles the visibility report JSON from the discovery inventory + the
# per-surface aggregators (forms/api/assets/third_party) + (later phases) the
# site graph + visibility score. Grows one section per phase.
#
# Definition of done (the report shape):
#   domain, crawl_mode, pages_found, pages_crawled,
#   forms/api/js_routes/assets/third_party counts,
#   site_graph_generated, visibility_score, limitations
#
# Safe-mode: pure aggregation. No network.

from __future__ import annotations

import logging
from typing import Any

from webhound.core.visibility.discovered_url import UrlSource
from webhound.core.visibility.surfaces import (
    build_api_section,
    build_forms_section,
)

logger = logging.getLogger(__name__)


def build_visibility_report(
    ctx: Any,
    *,
    crawl_results: list,
    domain: str | None,
) -> dict:
    """Build the visibility report from ctx.visibility + the scan's crawl
    results. Best-effort per section — a failing aggregator degrades to an
    empty section rather than aborting the report."""
    vis = ctx.visibility
    inv = vis.inventory

    report: dict = {
        "domain": domain,
        "crawl_mode": "visibility",
        "pages_found": inv.pages_found,
        "pages_crawled": inv.pages_crawled,
        "status_counts": inv.status_counts(),
        "source_counts": inv.source_counts(),
        "skip_reason_counts": inv.skip_reason_counts(),
        # js_routes: distinct URLs whose provenance includes a JS route source.
        "js_routes": len(inv.by_source(UrlSource.JS_ROUTE)),
        "site_graph_generated": False,
        "visibility_score": None,
        "limitations": [],
    }

    browser = getattr(ctx, "browser", None)

    # Phase 5 — forms.
    try:
        report["forms"] = build_forms_section(
            crawl_results, browser_discovery=browser,
        )
    except Exception:  # noqa: BLE001
        logger.debug("visibility forms section failed", exc_info=True)
        report["forms"] = {"count": 0}

    # Phase 6 — API endpoints.
    try:
        report["api"] = build_api_section(
            crawl_results, browser_discovery=browser, primary_host=domain,
        )
    except Exception:  # noqa: BLE001
        logger.debug("visibility api section failed", exc_info=True)
        report["api"] = {"count": 0}

    return report
