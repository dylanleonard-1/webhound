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
    build_assets_section,
    build_forms_section,
    build_third_party_section,
)

logger = logging.getLogger(__name__)

# Cap on per-URL records embedded in the report JSON (keeps metadata bounded;
# the page tree + counts still reflect the full inventory).
_URL_CAP = 1500


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
        # Per-URL discovery inventory (capped) — powers the dashboard page tree,
        # the skip-reasons panel, and the discovered_urls persistence table.
        "discovered_urls": [d.to_dict() for d in inv.all()][:_URL_CAP],
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

    # Phase 7 — assets.
    try:
        report["assets"] = build_assets_section(
            crawl_results, browser_discovery=browser, primary_host=domain,
        )
    except Exception:  # noqa: BLE001
        logger.debug("visibility assets section failed", exc_info=True)
        report["assets"] = {"count": 0}

    # Phase 8 — third-party hosts (reuses the scan-wide external host inventory
    # the orchestrator already aggregated into metadata).
    try:
        external_hosts = []
        meta = getattr(getattr(ctx, "scan_result", None), "metadata", None) or {}
        external_hosts = meta.get("external_host_inventory") or []
        report["third_party"] = build_third_party_section(
            external_hosts, primary_host=domain,
        )
    except Exception:  # noqa: BLE001
        logger.debug("visibility third_party section failed", exc_info=True)
        report["third_party"] = {"count": 0}

    # Phase 10 — site graph + page tree. Reuses the Security Graph summary the
    # orchestrator already built (metadata.security_graph_summary) and derives
    # the navigation page tree from the inventory's parent pointers.
    try:
        from webhound.core.visibility.site_graph import build_site_graph_section

        meta = getattr(getattr(ctx, "scan_result", None), "metadata", None) or {}
        report["site_graph"] = build_site_graph_section(
            inv, security_graph_summary=meta.get("security_graph_summary"),
        )
        report["site_graph_generated"] = True
    except Exception:  # noqa: BLE001
        logger.debug("visibility site graph section failed", exc_info=True)

    # Phase 9 — authenticated surface. Consent-gated: only meaningful when a
    # session was supplied (auth_mode != public_only). REUSES the AuthContext
    # the orchestrator already folded into metadata.auth from the authenticated
    # browser pass; the authenticated routes/pages are already crawled via the
    # Phase-4 browser follow-up (the browser pass ran with the session).
    try:
        meta = getattr(getattr(ctx, "scan_result", None), "metadata", None) or {}
        auth_meta = meta.get("auth") or {}
        report["authenticated"] = {
            "enabled": bool(auth_meta.get("available")),
            "mode": auth_meta.get("mode"),
            "expired": bool(auth_meta.get("expired")),
            "pages": auth_meta.get("authenticated_page_count", 0),
            "apis": auth_meta.get("authenticated_api_count", 0),
            "forms": auth_meta.get("authenticated_form_count", 0),
            "routes": auth_meta.get("authenticated_route_count", 0),
            "third_parties": len(
                auth_meta.get("authenticated_third_parties", []) or []
            ),
            "auth_domains": auth_meta.get("auth_domains", []),
        }
    except Exception:  # noqa: BLE001
        logger.debug("visibility authenticated section failed", exc_info=True)
        report["authenticated"] = {"enabled": False}

    # Phase 11 — visibility score + limitations (computed last, over the
    # assembled report). Transparent breakdown so the dashboard explains WHY.
    try:
        from webhound.core.visibility.score import compute_visibility_score

        opts = getattr(getattr(ctx, "target", None), "scan_options", None)
        max_depth = getattr(opts, "max_depth", 0) or 0
        browser_available = bool(getattr(browser, "available", False))
        score, breakdown, limitations = compute_visibility_score(
            report, inventory=inv, max_depth=max_depth,
            browser_available=browser_available,
        )
        report["visibility_score"] = score
        report["score_breakdown"] = breakdown
        report["limitations"] = limitations
    except Exception:  # noqa: BLE001
        logger.debug("visibility score failed", exc_info=True)

    return report
