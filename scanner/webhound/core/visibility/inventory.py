# WebHound — scanner/webhound/core/visibility/inventory.py
# Phase 1/2: the canonical DiscoveredUrl inventory.
#
# One record per canonical URL, regardless of how many discovery sources
# surfaced it. Re-discovering a URL merges provenance (unions sources), keeps
# the shallowest depth, and remembers the first parent — so the inventory is
# the single source of truth for "what did we find, how, and what happened to
# it". Powers the frontier dedup, the visibility report, and the dashboard.
#
# Safe-mode: pure in-memory data structure. No network.

from __future__ import annotations

from collections import Counter

from webhound.core.visibility.discovered_url import (
    DiscoveredUrl,
    UrlSource,
    UrlStatus,
)


class DiscoveredUrlInventory:
    """Deduplicated collection of :class:`DiscoveredUrl`, keyed by canonical URL."""

    def __init__(self) -> None:
        self._by_url: dict[str, DiscoveredUrl] = {}

    # ------------------------------------------------------------------
    # Mutation
    # ------------------------------------------------------------------

    def add(self, du: DiscoveredUrl) -> DiscoveredUrl:
        """Insert *du*, or merge it into the existing record for the same
        canonical URL. Returns the canonical record (the one stored).

        Merge semantics:
        - sources are unioned;
        - depth keeps the shallowest (a URL reachable at depth 1 and depth 4
          is recorded at depth 1 — its cheapest discovery);
        - parent keeps the first non-null one seen;
        - lifecycle status / skip_reason are NOT overwritten by a re-discovery
          (only explicit mark_* calls change those).
        """
        existing = self._by_url.get(du.normalized)
        if existing is None:
            self._by_url[du.normalized] = du
            return du

        for s in du.sources:
            existing.add_source(s)
        existing.add_tags(du.tags)
        if du.depth < existing.depth:
            existing.depth = du.depth
        if existing.parent is None and du.parent is not None:
            existing.parent = du.parent
        return existing

    def add_raw(
        self,
        raw_url: str,
        *,
        source: UrlSource,
        base_url: str | None = None,
        depth: int = 0,
        parent: str | None = None,
        in_scope: bool = True,
        tags: set[str] | None = None,
    ) -> DiscoveredUrl | None:
        """Canonicalize *raw_url* and add it. Returns the canonical record, or
        ``None`` when the URL is not crawlable (non-http(s), empty host, …)."""
        du = DiscoveredUrl.create(
            raw_url,
            source=source,
            base_url=base_url,
            depth=depth,
            parent=parent,
            in_scope=in_scope,
            tags=tags,
        )
        if du is None:
            return None
        return self.add(du)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get(self, normalized: str) -> DiscoveredUrl | None:
        return self._by_url.get(normalized)

    def __contains__(self, normalized: str) -> bool:
        return normalized in self._by_url

    def __len__(self) -> int:
        return len(self._by_url)

    def all(self) -> list[DiscoveredUrl]:
        return list(self._by_url.values())

    def by_status(self, status: UrlStatus) -> list[DiscoveredUrl]:
        return [d for d in self._by_url.values() if d.status == status]

    def by_source(self, source: UrlSource) -> list[DiscoveredUrl]:
        return [d for d in self._by_url.values() if source in d.sources]

    # ------------------------------------------------------------------
    # Rollups for the visibility report
    # ------------------------------------------------------------------

    def status_counts(self) -> dict[str, int]:
        c: Counter[str] = Counter(d.status.value for d in self._by_url.values())
        return dict(c)

    def source_counts(self) -> dict[str, int]:
        """Count how many URLs carry each discovery source (a URL with two
        sources counts toward both)."""
        c: Counter[str] = Counter()
        for d in self._by_url.values():
            for s in d.sources:
                c[s.value] += 1
        return dict(c)

    def skip_reason_counts(self) -> dict[str, int]:
        """Rollup of WHY URLs were skipped — drives the dashboard panel."""
        c: Counter[str] = Counter(
            d.skip_reason
            for d in self._by_url.values()
            if d.status == UrlStatus.SKIPPED and d.skip_reason
        )
        return dict(c)

    @property
    def pages_found(self) -> int:
        """Total distinct in-scope URLs discovered (crawlable surface)."""
        return sum(1 for d in self._by_url.values() if d.in_scope)

    @property
    def pages_crawled(self) -> int:
        return sum(
            1 for d in self._by_url.values() if d.status == UrlStatus.CRAWLED
        )

    def to_dict(self, *, include_urls: bool = False, url_cap: int = 2000) -> dict:
        """Compact summary for the visibility report. Set *include_urls* to
        embed the per-URL records (capped) for the dashboard's page tree."""
        out: dict = {
            "total": len(self._by_url),
            "pages_found": self.pages_found,
            "pages_crawled": self.pages_crawled,
            "status_counts": self.status_counts(),
            "source_counts": self.source_counts(),
            "skip_reason_counts": self.skip_reason_counts(),
        }
        if include_urls:
            out["urls"] = [d.to_dict() for d in self._by_url.values()][:url_cap]
        return out
