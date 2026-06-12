# WebHound — scanner/webhound/core/visibility/route_harvester.py
# Phase 3: feed JS-discovered client routes into the frontier.
#
# SPA routers register routes that never appear as <a href>. This harvester
# REUSES route_extractor.routes_from_script_text (the same route-shaped-literal
# extractor the browser pass uses) to pull route candidates from a page's
# inline scripts during the static crawl, resolves them to same-host absolute
# URLs, and feeds the in-scope ones into the unified frontier as JS_ROUTE.
#
# Scope: navigable PAGE routes only. JS fetch/XHR/WebSocket/GraphQL targets are
# API endpoints, not pages — they are inventoried by the API-discovery layer
# (Phase 6), never crawled as pages here.
#
# Browser-rendered routes (window.__NEXT_DATA__ / __NUXT__ / __BUILD_MANIFEST /
# data-href) are surfaced by the browser pass and fed back in Phase 4.
#
# Safe-mode: pure string parsing. No network, no JS execution.

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

from webhound.browser.route_extractor import routes_from_script_text
from webhound.core.visibility.discovered_url import UrlSource
from webhound.core.visibility.frontier import VisibilityFrontier

# Per-page cap so a pathological bundle can't flood the frontier (the frontier
# also scope/budget-bounds, but cap early to keep the inventory tidy).
_MAX_ROUTES_PER_PAGE = 200


def _inline_script_bodies(artifacts: Any) -> list[str]:
    """Collect inline-script source text from PageArtifacts, tolerating both
    the ``inline_scripts`` shortcut list and the structured ``scripts`` list."""
    bodies: list[str] = []
    for body in getattr(artifacts, "inline_scripts", None) or []:
        if body:
            bodies.append(body)
    if not bodies:
        for s in getattr(artifacts, "scripts", None) or []:
            if getattr(s, "is_inline", False) and getattr(s, "content", None):
                bodies.append(s.content)
    return bodies


def harvest_js_routes(
    frontier: VisibilityFrontier,
    artifacts: Any,  # PageArtifacts — duck-typed to avoid an import cycle
    *,
    depth: int,
    parent: str | None,
) -> int:
    """Extract route-shaped literals from *artifacts*' inline scripts and feed
    the resulting same-host navigable routes into *frontier* as JS_ROUTE.

    Returns the number of route candidates submitted (the frontier decides
    scope/robots/depth and logs skips). Child depth is ``depth + 1``.
    """
    if artifacts is None:
        return 0
    base = getattr(artifacts, "url", None) or parent
    if not base:
        return 0
    page_host = (urlparse(base).hostname or "").lower()

    submitted = 0
    seen: set[str] = set()
    for body in _inline_script_bodies(artifacts):
        for route_path in routes_from_script_text(body):
            if len(seen) >= _MAX_ROUTES_PER_PAGE:
                break
            # routes_from_script_text yields path-shaped strings ("/dashboard").
            absolute = urljoin(base, route_path)
            # Only same-host routes are navigable pages on THIS site; the
            # frontier's scope check is the authority, but pre-filtering host
            # keeps cross-origin literals out of the page inventory entirely.
            if (urlparse(absolute).hostname or "").lower() != page_host:
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            frontier.add(
                absolute,
                source=UrlSource.JS_ROUTE,
                base_url=base,
                depth=depth + 1,
                parent=parent,
                tags={"inline_script", "js_route"},
            )
            submitted += 1
    return submitted
