# WebHound — scanner/webhound/core/crawler.py
# BFS crawler: drives the scan loop using ScanContext + SafeHttpClient.
#
# Safe-mode guarantees:
#   - GET requests only — no POST, PUT, DELETE.
#   - Forms are discovered but NEVER submitted.
#   - External domains are NEVER crawled (scope rules enforced by ScanContext).
#   - max_pages and max_depth budgets are always respected.
#   - HTTP errors and network failures are recorded — never raised to caller.

from __future__ import annotations

from dataclasses import dataclass, field

from webhound.core.extractor import Extractor, PageArtifacts, _is_html
from webhound.core.http_client import HttpResponse, SafeHttpClient
from webhound.core.scan_context import QueueItem, ScanContext

# Engine name used when recording crawler errors in ScanContext.
_ENGINE = "crawler"


# ---------------------------------------------------------------------------
# CrawlResult
# ---------------------------------------------------------------------------


@dataclass
class CrawlResult:
    """Output of crawling a single URL.

    ``artifacts`` is ``None`` when the response was not HTML or the request
    failed — the ``response`` field always holds the raw result.
    """

    url: str
    depth: int
    response: HttpResponse
    artifacts: PageArtifacts | None


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------


class Crawler:
    """BFS crawler that populates a :class:`ScanContext` with page artifacts.

    Usage::

        ctx = ScanContext(target)
        async with SafeHttpClient(target.scan_options) as client:
            crawler = Crawler(ctx, client)
            results = await crawler.crawl()
        scan_result = ctx.finish()

    The caller is responsible for managing the ``SafeHttpClient`` lifecycle.
    """

    def __init__(self, context: ScanContext, client: SafeHttpClient) -> None:
        self._ctx = context
        self._client = client
        self._extractor = Extractor()

    async def crawl(self) -> list[CrawlResult]:
        """Run the BFS crawl until the queue is empty or budgets are exhausted.

        Seeds the queue with the target root URL on first call.
        Returns all :class:`CrawlResult` objects produced during the run.

        When ``ctx.visibility`` is present (ScanOptions.visibility_enabled) the
        crawl is driven by the unified discovery frontier, which feeds every
        discovery source — sitemap/robots/canonical/iframe/form/JS/ASM — back
        into the queue rather than just ``<a href>`` links. Absent → the legacy
        anchor-only path below, byte-for-byte unchanged.
        """
        if self._ctx.visibility is not None:
            return await self._crawl_with_frontier()

        # Seed only once — idempotent if called again after partial crawl.
        if not self._ctx.has_work and self._ctx.pages_crawled == 0:
            self._ctx.seed(self._ctx.target.url)

        results: list[CrawlResult] = []

        while self._ctx.has_work:
            item = self._ctx.dequeue()
            if item is None:
                break
            result = await self._crawl_one(item)
            results.append(result)

            # Enqueue links discovered on this page.
            if result.artifacts is not None:
                child_depth = item.depth + 1
                for link in result.artifacts.all_links:
                    self._ctx.enqueue(link, child_depth)

        return results

    async def _crawl_with_frontier(self) -> list[CrawlResult]:
        """Visibility-layer crawl: the frontier is the single enqueue authority.

        The per-page security engines downstream are unchanged — they simply
        receive more in-scope pages. Every crawled page's status is recorded on
        its DiscoveredUrl and bridged to ScanContext for the legacy page-count.
        """
        vis = self._ctx.visibility
        frontier = vis.frontier

        # Seed the root if the frontier is empty (idempotent across partial runs).
        if frontier.crawled_count == 0 and frontier.queued_count == 0:
            vis.seed_root(self._ctx.target.url)

        results: list[CrawlResult] = []

        while True:
            du = frontier.next()
            if du is None:
                break
            item = QueueItem(url=du.url, depth=du.depth)
            result = await self._crawl_one(item)
            results.append(result)

            resp = result.response
            if resp.failed:
                frontier.mark_failed(du, resp.error or "request failed")
            else:
                frontier.mark_crawled(
                    du,
                    status_code=resp.status_code,
                    content_type=resp.content_type,
                )

            # Feed this page's navigable discovery sources back in.
            if result.artifacts is not None:
                vis.harvest(result.artifacts, depth=du.depth, parent=du.url)

        return results

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _crawl_one(self, item: QueueItem) -> CrawlResult:
        """Fetch *item.url*, extract artifacts, update context."""
        url = item.url
        depth = item.depth

        # Mark visited before fetching so concurrent engines see it as done.
        self._ctx.mark_visited(url, depth)

        response = await self._client.get(url)

        # Record network/HTTP failures as non-fatal errors.
        if response.failed:
            self._ctx.record_error(_ENGINE, response.error or "request failed", url=url)
            return CrawlResult(url=url, depth=depth, response=response, artifacts=None)

        # Only extract from HTML responses.
        if not _is_html(response.content_type):
            return CrawlResult(url=url, depth=depth, response=response, artifacts=None)

        artifacts = self._extractor.extract(response)

        # Update scan result telemetry on the context's scan result.
        self._ctx.scan_result.requests_made += 1

        return CrawlResult(url=url, depth=depth, response=response, artifacts=artifacts)
