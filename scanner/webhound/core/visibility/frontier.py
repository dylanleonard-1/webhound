# WebHound — scanner/webhound/core/visibility/frontier.py
# Phase 2 (the KEY fix): the unified discovery frontier.
#
# The legacy crawler only enqueues <a href> anchor links, so discovery breadth
# is capped by what the homepage links to. The VisibilityFrontier feeds EVERY
# discovery source back into the crawl — sitemap/sitemap_index, robots paths,
# canonical/hreflang, iframe/script src, form actions (GET targets only — never
# a submission), JS-discovered routes, and ASM subdomains — deduped by canonical
# URL, prioritised, scope- and robots-gated, depth/budget-bounded, with the
# REASON every URL was skipped logged for the dashboard.
#
# Authority split: this frontier owns priority ordering + the DiscoveredUrl
# inventory; it consults a ScopeChecker for same-domain scope and a RobotsRules
# for politeness. Budgets (max_pages/max_depth) are enforced here. The crawler
# bridges each crawl back to ScanContext for the security pipeline's accounting.
#
# Safe-mode: pure scheduling + string parsing. No network, no JS execution. A
# form's GET *action* may be enqueued as a navigable URL, but a form is NEVER
# submitted and POST actions are never enqueued.

from __future__ import annotations

import heapq
import logging
from urllib.parse import urlparse

from webhound.core.scope import ScopeChecker
from webhound.core.visibility.discovered_url import (
    DiscoveredUrl,
    UrlSource,
    UrlStatus,
)
from webhound.core.visibility.inventory import DiscoveredUrlInventory
from webhound.core.visibility.robots_policy import ALLOW_ALL, RobotsRules

logger = logging.getLogger(__name__)

# Path keywords that mark high-value pages we want crawled early. These are the
# pages that most expand visibility of the real attack/discovery surface.
_HIGH_VALUE_KEYWORDS = (
    "login", "signin", "sign-in", "account", "accounts", "dashboard",
    "admin", "billing", "checkout", "cart", "profile", "settings",
    "portal", "member", "auth", "console", "manage",
)

# Per-source base priority (lower = crawled first).
_SOURCE_PRIORITY: dict[UrlSource, int] = {
    UrlSource.SEED: 0,
    UrlSource.SITEMAP: 0,
    UrlSource.ROBOTS: 1,
    UrlSource.ANCHOR: 1,
    UrlSource.CANONICAL: 1,
    UrlSource.FORM_ACTION: 1,
    UrlSource.MANUAL: 0,
    UrlSource.JS_ROUTE: 2,
    UrlSource.JS_FETCH: 2,
    UrlSource.REDIRECT: 1,
    UrlSource.ASM: 3,
    UrlSource.IFRAME: 3,
    UrlSource.SCRIPT_SRC: 3,
    UrlSource.OTHER: 2,
}


class VisibilityFrontier:
    """Priority frontier that unifies all discovery sources into one crawl
    queue, gated by scope + robots + depth + page budget."""

    def __init__(
        self,
        scope: ScopeChecker,
        *,
        max_pages: int,
        max_depth: int,
        respect_robots: bool = True,
        robots_rules: RobotsRules | None = None,
        inventory: DiscoveredUrlInventory | None = None,
    ) -> None:
        self.scope = scope
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.respect_robots = respect_robots
        self.robots_rules = robots_rules or ALLOW_ALL
        self.inventory = inventory if inventory is not None else DiscoveredUrlInventory()
        # Min-heap of (priority, seq, normalized_url). seq breaks ties (FIFO).
        self._heap: list[tuple[int, int, str]] = []
        self._seq = 0
        # Normalized URLs already routed through add()'s decision logic — a
        # re-discovery only merges provenance, never re-decides or re-queues.
        self._decided: set[str] = set()
        self._crawled = 0

    # ------------------------------------------------------------------
    # Discovery → frontier
    # ------------------------------------------------------------------

    def add(
        self,
        raw_url: str,
        *,
        source: UrlSource,
        base_url: str | None = None,
        depth: int = 0,
        parent: str | None = None,
        tags: set[str] | None = None,
    ) -> DiscoveredUrl | None:
        """Canonicalize, dedupe, and decide *raw_url*.

        Always records the URL in the inventory (so the visibility report sees
        everything found). Decides — queue / skip-out-of-scope / skip-depth /
        skip-robots — exactly once per canonical URL; re-discovery only unions
        provenance. Returns the canonical record (``None`` if uncrawlable)."""
        du = self.inventory.add_raw(
            raw_url, source=source, base_url=base_url, depth=depth,
            parent=parent, tags=tags,
        )
        if du is None:
            return None

        # Already decided once — just keep the merged provenance.
        if du.normalized in self._decided:
            return du
        self._decided.add(du.normalized)

        # 1. Scope — same registered domain / subdir / list, per ScopeChecker.
        if not self.scope.is_in_scope(du.normalized):
            du.in_scope = False
            reason = self.scope.out_of_scope_reason(du.normalized) or "out of scope"
            du.mark_skipped(f"out of scope: {reason}")
            logger.debug("frontier skip [scope] %s — %s", du.normalized, reason)
            return du

        # 2. Depth budget.
        if depth > self.max_depth:
            du.mark_skipped(f"max depth exceeded ({depth} > {self.max_depth})")
            logger.debug("frontier skip [depth] %s", du.normalized)
            return du

        # 3. robots.txt — never block the seed; honour Disallow otherwise.
        if (
            self.respect_robots
            and source != UrlSource.SEED
            and self.robots_rules.has_rules
            and not self.robots_rules.is_allowed(du.normalized)
        ):
            du.mark_skipped("disallowed by robots.txt")
            logger.debug("frontier skip [robots] %s", du.normalized)
            return du

        # Eligible — enqueue with priority.
        priority = self._priority(du, source)
        self._seq += 1
        heapq.heappush(self._heap, (priority, self._seq, du.normalized))
        du.mark_queued()
        return du

    def seed(self, url: str) -> DiscoveredUrl | None:
        """Seed the root target URL at depth 0 (never robots-blocked)."""
        return self.add(url, source=UrlSource.SEED, depth=0)

    # ------------------------------------------------------------------
    # Frontier → crawler
    # ------------------------------------------------------------------

    def next(self) -> DiscoveredUrl | None:
        """Pop the highest-priority pending URL, or ``None`` when the queue is
        empty or the page budget is spent. When the budget runs out, every URL
        still queued is marked skipped with a logged reason."""
        if self._crawled >= self.max_pages:
            self._drain_budget()
            return None
        while self._heap:
            _prio, _seq, normalized = heapq.heappop(self._heap)
            du = self.inventory.get(normalized)
            if du is None or du.status != UrlStatus.QUEUED:
                continue
            return du
        return None

    def mark_crawled(
        self,
        du: DiscoveredUrl,
        *,
        status_code: int | None = None,
        content_type: str | None = None,
    ) -> None:
        du.mark_crawled(status_code=status_code, content_type=content_type)
        self._crawled += 1

    def mark_failed(self, du: DiscoveredUrl, reason: str) -> None:
        du.mark_failed(reason)

    @property
    def crawled_count(self) -> int:
        return self._crawled

    @property
    def queued_count(self) -> int:
        return sum(
            1
            for _p, _s, n in self._heap
            if (d := self.inventory.get(n)) and d.status == UrlStatus.QUEUED
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _drain_budget(self) -> None:
        """Mark every still-queued URL as skipped (page budget reached)."""
        reason = f"page budget reached ({self.max_pages} pages)"
        while self._heap:
            _p, _s, normalized = heapq.heappop(self._heap)
            du = self.inventory.get(normalized)
            if du is not None and du.status == UrlStatus.QUEUED:
                du.mark_skipped(reason)

    def _priority(self, du: DiscoveredUrl, source: UrlSource) -> int:
        base = _SOURCE_PRIORITY.get(source, 2)
        path = (urlparse(du.normalized).path or "/").lower()
        if path in ("/", ""):
            return 0
        if any(kw in path for kw in _HIGH_VALUE_KEYWORDS):
            base = min(base, 0)
        # Shallower pages slightly preferred within the same band.
        return base
