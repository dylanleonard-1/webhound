# WebHound — scanner/webhound/core/visibility/harvester.py
# Phase 2: fold a crawled page's discovery sources into the frontier.
#
# Reuses the EXISTING static extractor output (PageArtifacts) — no new parsing.
# The legacy crawler enqueued only ``artifacts.all_links`` (<a href>); this
# harvester additionally feeds canonical links, same-host iframes, and GET form
# actions back into the unified frontier as navigable crawl candidates.
#
# Deliberate boundary: asset URLs (script/style/image src) are NOT enqueued as
# pages here — crawling a .js/.css yields no page graph and would inflate
# pages_found. They are surfaced by the existing url_discovery / asset
# inventory (Phase 7). The frontier stays a *page* frontier.
#
# Safe-mode: a form's GET *action* may become a navigable URL, but forms are
# NEVER submitted and POST/PUT/DELETE actions are never enqueued.

from __future__ import annotations

from typing import Any

from webhound.core.visibility.discovered_url import UrlSource
from webhound.core.visibility.frontier import VisibilityFrontier


def harvest_artifacts(
    frontier: VisibilityFrontier,
    artifacts: Any,  # PageArtifacts — duck-typed to avoid an import cycle
    *,
    depth: int,
    parent: str | None,
) -> int:
    """Feed every navigable discovery source on *artifacts* into *frontier*.

    Returns the number of raw candidates submitted (not the number actually
    queued — the frontier decides scope/robots/depth and logs skips). Child
    depth is ``depth + 1``.
    """
    if artifacts is None:
        return 0

    child_depth = depth + 1
    base = getattr(artifacts, "url", None) or parent
    submitted = 0

    def _add(raw: str | None, source: UrlSource) -> None:
        nonlocal submitted
        if not raw:
            return
        frontier.add(
            raw, source=source, base_url=base, depth=child_depth, parent=parent,
        )
        submitted += 1

    # 1. Anchors — the legacy source (already-normalized internal+external).
    for link in getattr(artifacts, "all_links", None) or []:
        _add(link, UrlSource.ANCHOR)

    # 2. Canonical / hreflang alternates (external_canonical_urls holds the
    #    cross-origin ones the extractor captured; scope filters the rest).
    for link in getattr(artifacts, "external_canonical_urls", None) or []:
        _add(link, UrlSource.CANONICAL)

    # 3. Same-host iframes can be real embedded pages — enqueue those; the
    #    frontier's scope check drops cross-origin frames (recorded as skips).
    for iframe in getattr(artifacts, "iframes", None) or []:
        src = getattr(iframe, "src_url", None)
        if src:
            _add(src, UrlSource.IFRAME)

    # 4. GET form actions are navigable URLs. POST/PUT/DELETE actions are
    #    submissions — NEVER enqueued (safe-mode).
    for form in getattr(artifacts, "forms", None) or []:
        action_url = getattr(form, "action_url", None)
        method = (getattr(form, "method", "GET") or "GET").upper()
        if action_url and method == "GET":
            _add(action_url, UrlSource.FORM_ACTION)

    return submitted
