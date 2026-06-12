# WebHound — scanner/webhound/core/visibility/discovered_url.py
# Phase 1: the canonical DiscoveredUrl record + canonicalization helpers.
#
# A DiscoveredUrl is the single source of truth for one URL the visibility
# layer has found, regardless of WHICH discovery source surfaced it (sitemap,
# anchor, JS route, form action, ASM subdomain, redirect, …). It carries
# provenance, crawl depth, parent, status, and — crucially — the REASON a URL
# was skipped, so the dashboard can explain why every URL was or wasn't crawled.
#
# Canonicalization REUSES core.scope.UrlNormalizer (the scanner's single
# canonical-form authority) so the visibility inventory dedupes URLs exactly
# the way the crawler's visited-set does. We never fork normalization.
#
# Safe-mode: pure data + string parsing. No network, no JS execution.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from webhound.core.scope import UrlNormalizer


# ---------------------------------------------------------------------------
# Canonicalization (thin wrappers over the existing UrlNormalizer)
# ---------------------------------------------------------------------------


def normalize_url(url: str, base_url: str | None = None) -> str | None:
    """Return the canonical form of *url*, or ``None`` if it should not be
    crawled (non-http(s) scheme, empty host, javascript:/mailto:/etc).

    Thin delegate to :meth:`UrlNormalizer.normalize` — the scanner's single
    canonicalization authority — so the visibility inventory and the crawler's
    visited-set agree on what "the same URL" means.

    Canonical form (from UrlNormalizer): scheme + host lowercased, default
    ports stripped, fragment dropped, duplicate slashes collapsed, empty path
    → ``/``, query preserved as-is.
    """
    return UrlNormalizer.normalize(url, base_url=base_url)


# Public alias — some call sites read more clearly as ``canonicalize``.
canonicalize = normalize_url


# ---------------------------------------------------------------------------
# Provenance + lifecycle enums
# ---------------------------------------------------------------------------


class UrlSource(str, Enum):
    """How a URL entered the discovery inventory. Drives frontier priority
    (Phase 2) and dashboard provenance ("found via: sitemap + anchor")."""

    SEED = "seed"                  # the root target URL
    SITEMAP = "sitemap"            # <loc> in sitemap.xml / sitemap_index.xml
    ROBOTS = "robots"              # Allow/Disallow/Sitemap paths in robots.txt
    ANCHOR = "anchor"              # <a href> in static or rendered HTML
    CANONICAL = "canonical"        # <link rel="canonical"> / hreflang
    IFRAME = "iframe"              # <iframe src>
    SCRIPT_SRC = "script_src"      # <script src> (navigable same-origin only)
    FORM_ACTION = "form_action"    # <form action> GET target (never a submission)
    JS_ROUTE = "js_route"          # SPA client route (Next/Nuxt/router/data-href)
    JS_FETCH = "js_fetch"          # fetch/XHR/import path discovered in JS source
    ASM = "asm"                    # subdomain from CT logs / DNS prefix probe
    REDIRECT = "redirect"          # Location / redirect-chain hop
    MANUAL = "manual"              # operator-supplied / scope_urls
    OTHER = "other"


class UrlStatus(str, Enum):
    """Lifecycle of a DiscoveredUrl through the frontier + crawl."""

    PENDING = "pending"            # discovered, eligible, not yet crawled
    CRAWLED = "crawled"            # fetched successfully
    SKIPPED = "skipped"            # intentionally not crawled (see skip_reason)
    FAILED = "failed"             # fetch attempted but errored
    QUEUED = "queued"              # accepted into the frontier queue


@dataclass
class DiscoveredUrl:
    """One canonical URL the visibility layer discovered, with full provenance.

    Dedup key is :attr:`normalized`. The inventory (Phase 2) merges repeated
    discoveries of the same canonical URL into one record, unioning
    :attr:`sources` and keeping the shallowest depth / first parent.
    """

    url: str                                  # canonical URL (== normalized)
    normalized: str                           # canonical form (dedup key)
    sources: set[UrlSource] = field(default_factory=set)
    depth: int = 0                            # crawl depth (0 = seed)
    parent: str | None = None                 # canonical URL that surfaced this
    status: UrlStatus = UrlStatus.PENDING
    skip_reason: str | None = None            # WHY it was skipped (explainable)
    in_scope: bool = True
    status_code: int | None = None            # populated after a crawl
    content_type: str | None = None           # populated after a crawl
    retry_count: int = 0
    # First source seen wins for the human-facing "discovered via" headline;
    # the full set lives in ``sources``.
    discovered_via: UrlSource | None = None

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        raw_url: str,
        *,
        source: UrlSource,
        base_url: str | None = None,
        depth: int = 0,
        parent: str | None = None,
        in_scope: bool = True,
    ) -> "DiscoveredUrl | None":
        """Build a DiscoveredUrl from a raw (possibly relative) URL.

        Returns ``None`` when the URL canonicalizes to nothing crawlable
        (non-http(s), empty host, javascript:/mailto:/etc) — the caller drops
        it rather than tracking an uncrawlable entry.
        """
        normalized = normalize_url(raw_url, base_url=base_url)
        if not normalized:
            return None
        return cls(
            url=normalized,
            normalized=normalized,
            sources={source},
            depth=depth,
            parent=parent,
            in_scope=in_scope,
            discovered_via=source,
        )

    # ------------------------------------------------------------------
    # Mutation helpers (used by the inventory on re-discovery)
    # ------------------------------------------------------------------

    def add_source(self, source: UrlSource) -> None:
        """Record an additional discovery source for this URL."""
        self.sources.add(source)
        if self.discovered_via is None:
            self.discovered_via = source

    def mark_crawled(
        self, *, status_code: int | None = None, content_type: str | None = None
    ) -> None:
        self.status = UrlStatus.CRAWLED
        self.status_code = status_code
        self.content_type = content_type
        self.skip_reason = None

    def mark_skipped(self, reason: str) -> None:
        """Mark this URL as intentionally not crawled, recording WHY. The
        reason is surfaced verbatim in the dashboard's skip-reasons panel."""
        self.status = UrlStatus.SKIPPED
        self.skip_reason = reason

    def mark_failed(self, reason: str) -> None:
        self.status = UrlStatus.FAILED
        self.skip_reason = reason

    def mark_queued(self) -> None:
        # Only promote from PENDING — never override a terminal state.
        if self.status == UrlStatus.PENDING:
            self.status = UrlStatus.QUEUED

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """JSON-safe dict for the visibility report + persistence."""
        return {
            "url": self.url,
            "normalized": self.normalized,
            "sources": sorted(s.value for s in self.sources),
            "discovered_via": self.discovered_via.value
            if self.discovered_via
            else None,
            "depth": self.depth,
            "parent": self.parent,
            "status": self.status.value,
            "skip_reason": self.skip_reason,
            "in_scope": self.in_scope,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "retry_count": self.retry_count,
        }
