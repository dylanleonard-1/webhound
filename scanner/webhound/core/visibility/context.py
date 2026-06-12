# WebHound — scanner/webhound/core/visibility/context.py
# Phase 2: per-scan visibility state — the inventory + frontier bundle that the
# orchestrator attaches to ScanContext.visibility when visibility_enabled.
#
# When this is absent (default, visibility OFF) the crawler takes its legacy
# anchor-only path and scan behaviour is byte-for-byte identical to today.
#
# Safe-mode: pure state container. No network.

from __future__ import annotations

from webhound.core.scope import ScopeChecker
from webhound.core.visibility.discovered_url import UrlSource
from webhound.core.visibility.frontier import VisibilityFrontier
from webhound.core.visibility.harvester import harvest_artifacts
from webhound.core.visibility.inventory import DiscoveredUrlInventory
from webhound.core.visibility.robots_policy import ALLOW_ALL, RobotsRules
from webhound.core.visibility.seeder import SeedSources


class VisibilityContext:
    """Holds the discovery inventory + frontier for one scan."""

    def __init__(
        self,
        scope: ScopeChecker,
        *,
        max_pages: int,
        max_depth: int,
        respect_robots: bool = True,
        robots_rules: RobotsRules | None = None,
    ) -> None:
        self.inventory = DiscoveredUrlInventory()
        self.frontier = VisibilityFrontier(
            scope,
            max_pages=max_pages,
            max_depth=max_depth,
            respect_robots=respect_robots,
            robots_rules=robots_rules or ALLOW_ALL,
            inventory=self.inventory,
        )

    # ------------------------------------------------------------------
    # Seeding
    # ------------------------------------------------------------------

    def seed_root(self, url: str) -> None:
        self.frontier.seed(url)

    def apply_seed_sources(self, sources: SeedSources, *, base_url: str) -> None:
        """Fold robots/sitemap seed URLs into the frontier. The robots_rules
        from *sources* should already have been passed to the frontier at
        construction (so politeness applies to every add)."""
        for loc in sources.sitemap_urls:
            self.frontier.add(loc, source=UrlSource.SITEMAP, depth=1)
        for path in sources.robots_allow_paths:
            # robots Allow paths are relative — resolve against the site root.
            self.frontier.add(path, source=UrlSource.ROBOTS, base_url=base_url, depth=1)

    # ------------------------------------------------------------------
    # Per-page harvest
    # ------------------------------------------------------------------

    def harvest(self, artifacts, *, depth: int, parent: str | None) -> int:
        """Feed a crawled page's navigable links into the frontier."""
        return harvest_artifacts(self.frontier, artifacts, depth=depth, parent=parent)

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def to_dict(self, *, include_urls: bool = False) -> dict:
        return self.inventory.to_dict(include_urls=include_urls)
