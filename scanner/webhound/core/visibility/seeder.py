# WebHound — scanner/webhound/core/visibility/seeder.py
# Phase 2: seed the frontier from robots.txt + sitemap(s).
#
# REUSES the robots_sitemap engine's parsers (_parse_robots, _parse_sitemap_urls)
# rather than re-implementing them. Fetches /robots.txt and the referenced +
# conventional sitemaps (sitemap.xml, sitemap_index.xml), follows one level of
# sitemap-index nesting, and returns:
#   * a RobotsRules built from robots.txt (for the frontier's politeness gate),
#   * the list of sitemap <loc> URLs to seed,
#   * the robots Allow paths (also seedable — they advertise real surface).
#
# SSRF-safe: only same-host sitemaps are fetched (a crafted robots.txt cannot
# redirect us to an external Sitemap: URL). Bounded fetch count + timeouts come
# from the shared SafeHttpClient.
#
# Safe-mode: GET only, no JS execution.

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from webhound.core.http_client import SafeHttpClient
from webhound.core.visibility.robots_policy import ALLOW_ALL, RobotsRules
from webhound.engines.recon.robots_sitemap import (
    _parse_robots,
    _parse_sitemap_urls,
)
from webhound.models.target import Target

logger = logging.getLogger(__name__)

# Caps so a hostile / huge sitemap can't blow up the seed phase.
_MAX_SITEMAPS_FETCHED = 10
_MAX_SEED_URLS = 5000


@dataclass
class SeedSources:
    """Result of the pre-crawl seed fetch."""

    robots_rules: RobotsRules = field(default_factory=lambda: ALLOW_ALL)
    sitemap_urls: list[str] = field(default_factory=list)
    robots_allow_paths: list[str] = field(default_factory=list)
    fetched_sitemaps: list[str] = field(default_factory=list)


def _same_host(url: str, target: Target) -> bool:
    try:
        return (urlparse(url).hostname or "").lower() == (
            target.hostname or ""
        ).lower()
    except Exception:  # noqa: BLE001
        return False


def _looks_like_sitemap_index(loc_urls: list[str]) -> bool:
    """A sitemap index's <loc> entries point at other .xml sitemaps."""
    return any(u.lower().rstrip("/").endswith(".xml") for u in loc_urls)


async def fetch_seed_sources(target: Target, client: SafeHttpClient) -> SeedSources:
    """Fetch robots.txt + sitemaps for *target* and return seedable URLs.

    Best-effort: any fetch/parse failure degrades to whatever was gathered so
    far (an empty SeedSources in the worst case). Never raises."""
    out = SeedSources()

    # -- robots.txt --
    try:
        robots_url = f"{target.base_url}/robots.txt"
        resp = await client.get(robots_url)
        if resp.is_success and resp.body:
            out.robots_rules = RobotsRules.from_robots_txt(resp.body)
            disallow, allow, sitemaps = _parse_robots(resp.body)
            out.robots_allow_paths = list(allow)
            # Only same-host Sitemap: URLs (SSRF guard).
            robots_sitemaps = [
                s for s in sitemaps if _same_host(s, target)
            ]
        else:
            robots_sitemaps = []
    except Exception:  # noqa: BLE001
        logger.debug("visibility seeder: robots.txt fetch failed", exc_info=True)
        robots_sitemaps = []

    # -- sitemap candidates (robots-referenced + conventional) --
    candidates: list[str] = list(dict.fromkeys(
        robots_sitemaps
        + [
            f"{target.base_url}/sitemap.xml",
            f"{target.base_url}/sitemap_index.xml",
        ]
    ))

    seen_sitemaps: set[str] = set()
    seed_urls: list[str] = []

    async def _fetch_sitemap(sm_url: str, *, allow_nested: bool) -> None:
        if (
            sm_url in seen_sitemaps
            or len(out.fetched_sitemaps) >= _MAX_SITEMAPS_FETCHED
            or not _same_host(sm_url, target)
        ):
            return
        seen_sitemaps.add(sm_url)
        try:
            resp = await client.get(sm_url)
        except Exception:  # noqa: BLE001
            logger.debug("visibility seeder: sitemap fetch failed %s", sm_url)
            return
        if not (resp.is_success and resp.body):
            return
        out.fetched_sitemaps.append(sm_url)
        locs = _parse_sitemap_urls(resp.body)
        if allow_nested and _looks_like_sitemap_index(locs):
            # One level of sitemap-index recursion.
            for child in locs:
                await _fetch_sitemap(child, allow_nested=False)
        else:
            for loc in locs:
                if len(seed_urls) < _MAX_SEED_URLS:
                    seed_urls.append(loc)

    for cand in candidates:
        await _fetch_sitemap(cand, allow_nested=True)

    out.sitemap_urls = seed_urls
    return out
