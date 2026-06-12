# WebHound — scanner/webhound/core/visibility/browser_routes.py
# Phase 4: feed browser-discovered navigable URLs into the frontier.
#
# The Playwright pass (reusing safe_interactions to expand menus/accordions and
# trigger lazy loaders WITHOUT clicking anything destructive) renders SPA pages
# and captures:
#   * tel.rendered_links   — <a href> present in the post-hydration DOM
#   * tel.client_routes    — (route, source) pairs from route_extractor
#                            (anchor / next_data / nuxt / data_href / script_string)
# Both are navigable PAGE candidates the static crawl can't see. This module
# folds them into the unified frontier with rich provenance tags so a bounded
# supplementary crawl (orchestrator) can fetch + analyse them like any page.
#
# Network artifacts (fetch/XHR/WebSocket/GraphQL) are NOT page candidates — they
# are API endpoints, inventoried by Phase 6, never crawled as pages here.
#
# Safe-mode: pure scheduling. No network, no JS execution, no clicks (the
# clicks already happened safely inside the browser pass).

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

from webhound.core.visibility.discovered_url import UrlSource, normalize_url
from webhound.core.visibility.frontier import VisibilityFrontier

# route_extractor's client_route "source" → a fine-grained provenance tag.
_ROUTE_SOURCE_TAG: dict[str, str] = {
    "anchor": "rendered_link",
    "next_data": "nextjs",
    "nuxt": "nuxt",
    "data_href": "data_href",
    "script_string": "inline_script",
}


def _page_depth(frontier: VisibilityFrontier, page_url: str | None) -> int:
    """Crawl depth of the rendered page, so children get depth+1. Falls back to
    depth 1 when the page isn't in the inventory (e.g. browser-only entry)."""
    norm = normalize_url(page_url or "")
    if norm:
        du = frontier.inventory.get(norm)
        if du is not None:
            return du.depth
    return 0


def feed_browser_routes(
    frontier: VisibilityFrontier,
    telemetries: list[Any],  # list[BrowserTelemetry] — duck-typed
    *,
    extra_tags: set[str] | None = None,
) -> int:
    """Fold every browser-discovered navigable URL on *telemetries* into
    *frontier*. Returns the count of raw candidates submitted (the frontier
    decides scope/robots/depth/budget and logs skips).

    *extra_tags* are merged onto every URL — e.g. {"authenticated"} when the
    browser pass ran with a session (Phase 9)."""
    submitted = 0
    extra = set(extra_tags or set())
    for tel in telemetries or []:
        page_url = getattr(tel, "final_url", None) or getattr(tel, "page_url", None)
        if not page_url:
            continue
        child_depth = _page_depth(frontier, page_url) + 1

        # 1. Rendered-DOM anchors.
        for link in getattr(tel, "rendered_links", None) or []:
            if not link:
                continue
            frontier.add(
                link,
                source=UrlSource.ANCHOR,
                base_url=page_url,
                depth=child_depth,
                parent=page_url,
                tags={"rendered_link", "browser_explorer"} | extra,
            )
            submitted += 1

        # 2. SPA client routes (route, source) — resolve paths to this host.
        for entry in getattr(tel, "client_routes", None) or []:
            try:
                route, src = entry
            except (TypeError, ValueError):
                continue
            if not route:
                continue
            absolute = urljoin(page_url, route)
            tag = _ROUTE_SOURCE_TAG.get(src or "", "js_route")
            frontier.add(
                absolute,
                source=UrlSource.JS_ROUTE,
                base_url=page_url,
                depth=child_depth,
                parent=page_url,
                tags={"browser_explorer", "js_route", tag} | extra,
            )
            submitted += 1
    return submitted
