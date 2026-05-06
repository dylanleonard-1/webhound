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
        """
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
