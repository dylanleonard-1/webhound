# WebHound — scanner/webhound/core/scan_context.py
# ScanContext: mutable runtime state for a single scan run.
#
# Ties together Target, ScanResult, ScopeChecker, and the URL queue.
# The crawler and engines interact with this object rather than managing
# their own state, keeping coordination in one place.

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from webhound.core.engine_tracker import EngineTracker

if TYPE_CHECKING:
    from webhound.browser.models import BrowserDiscovery
from webhound.core.scope import ScopeChecker, UrlNormalizer
from webhound.models.finding import Finding
from webhound.models.scan_result import ScanError, ScanResult, ScanStatus
from webhound.models.target import Target


@dataclass
class QueueItem:
    """A URL awaiting crawling, plus the crawl depth at which it was discovered."""

    url: str
    depth: int


class ScanContext:
    """Runtime state container for a single scan run.

    Responsibilities:
    - Track which URLs have been visited (deduplication).
    - Enforce max-pages and max-depth budgets.
    - Maintain the crawl queue (FIFO BFS order by default).
    - Record findings and non-fatal errors into the ScanResult.
    - Provide the single point of truth for scan progress.

    Instantiate once, pass to the crawler and engines.  Not thread-safe by
    itself — use ``asyncio`` coroutines in a single event loop.
    """

    def __init__(self, target: Target) -> None:
        self.target: Target = target
        self.scan_result: ScanResult = ScanResult(
            target=target,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(timezone.utc),
        )
        self.scope: ScopeChecker = ScopeChecker(target)

        self.tracker: EngineTracker = EngineTracker()

        self._visited: set[str] = set()
        self._queued: set[str] = set()          # Track queued URLs to avoid duplicates
        self._queue: deque[QueueItem] = deque()
        self._depth_map: dict[str, int] = {}    # normalized_url → crawl depth
        self._pages_crawled: int = 0

        # Phase-6C: browser discovery output. Set by the orchestrator
        # after the browser pass; None when the pass never ran (profile
        # gated it off / quick scans). Engines and reporting should go
        # through the ``browser`` property, which always returns a
        # usable (possibly empty) BrowserDiscovery.
        self.browser_discovery: "BrowserDiscovery | None" = None
        # Static crawl results (CrawlResult list) — attached after the
        # crawl so post-crawl passes can correlate static + rendered
        # views without re-plumbing every call site.
        self.crawl_results: list[Any] = []

        # Phase-9 framework detection result (ScanFrameworkResult), set
        # by the orchestrator's framework pass before WADE runs so WADE
        # can consult the platform's normal-change patterns. None until
        # that pass runs.
        self.framework_result: Any = None

        # Phase-10 authenticated-scan context (AuthContext). Always set
        # by the orchestrator; defaults to a public_only context with no
        # session. Secret-free — safe for metadata/reports.
        self.auth: Any = None

    # ------------------------------------------------------------------
    # Browser discovery access (Phase-6C)
    # ------------------------------------------------------------------

    @property
    def browser(self) -> "BrowserDiscovery":
        """Browser discovery data, never None — an empty deferred
        container is returned when the browser pass didn't run, so
        callers can use the accessors unconditionally."""
        if self.browser_discovery is None:
            from webhound.browser.models import BrowserDiscovery
            self.browser_discovery = BrowserDiscovery(
                deferred=True, error="browser pass not run",
            )
        return self.browser_discovery

    # ------------------------------------------------------------------
    # Progress / budget properties
    # ------------------------------------------------------------------

    @property
    def pages_crawled(self) -> int:
        return self._pages_crawled

    @property
    def max_pages(self) -> int:
        return self.target.scan_options.max_pages

    @property
    def max_depth(self) -> int:
        return self.target.scan_options.max_depth

    @property
    def pages_remaining(self) -> int:
        return max(0, self.max_pages - self._pages_crawled)

    @property
    def queue_size(self) -> int:
        return len(self._queue)

    @property
    def visited_count(self) -> int:
        return len(self._visited)

    @property
    def is_budget_exhausted(self) -> bool:
        return self._pages_crawled >= self.max_pages

    @property
    def has_work(self) -> bool:
        return bool(self._queue) and not self.is_budget_exhausted

    # ------------------------------------------------------------------
    # URL lifecycle
    # ------------------------------------------------------------------

    def can_crawl(self, url: str, depth: int = 0) -> bool:
        """True if *url* should be crawled — in scope, not visited, within budget."""
        normalized = UrlNormalizer.normalize(url)
        if not normalized:
            return False
        if normalized in self._visited:
            return False
        if normalized in self._queued:
            return False
        if self.is_budget_exhausted:
            return False
        if depth > self.max_depth:
            return False
        return self.scope.is_in_scope(url)

    def mark_visited(self, url: str, depth: int = 0) -> None:
        """Record *url* as crawled and increment the page counter."""
        normalized = UrlNormalizer.normalize(url) or url
        self._visited.add(normalized)
        self._queued.discard(normalized)
        self._depth_map[normalized] = depth
        self._pages_crawled += 1

    def is_visited(self, url: str) -> bool:
        normalized = UrlNormalizer.normalize(url) or url
        return normalized in self._visited

    def depth_of(self, url: str) -> int | None:
        """Return the depth at which *url* was crawled, or None if not visited."""
        normalized = UrlNormalizer.normalize(url) or url
        return self._depth_map.get(normalized)

    # ------------------------------------------------------------------
    # Queue management
    # ------------------------------------------------------------------

    def enqueue(self, url: str, depth: int) -> bool:
        """Add *url* to the crawl queue if eligible.  Returns True if added."""
        if not self.can_crawl(url, depth):
            return False
        normalized = UrlNormalizer.normalize(url)
        if not normalized:
            return False
        self._queued.add(normalized)
        self._queue.append(QueueItem(url=normalized, depth=depth))
        return True

    def dequeue(self) -> QueueItem | None:
        """Pop and return the next URL from the queue, or None if empty."""
        if not self._queue:
            return None
        return self._queue.popleft()

    def seed(self, url: str) -> None:
        """Add the root target URL as the initial seed (depth 0)."""
        normalized = UrlNormalizer.normalize(url) or url
        self._queued.add(normalized)
        self._queue.appendleft(QueueItem(url=normalized, depth=0))

    # ------------------------------------------------------------------
    # Findings and errors
    # ------------------------------------------------------------------

    def add_finding(self, finding: Finding) -> None:
        """Record a finding into the scan result."""
        self.scan_result.add_finding(finding)

    def record_error(
        self,
        engine: str,
        message: str,
        url: str | None = None,
        recoverable: bool = True,
    ) -> None:
        """Record a non-fatal scan error."""
        self.scan_result.add_error(
            ScanError(
                engine=engine,
                message=message,
                url=url,
                recoverable=recoverable,
            )
        )

    # ------------------------------------------------------------------
    # Completion
    # ------------------------------------------------------------------

    def finish(self) -> ScanResult:
        """Mark the scan complete and return the finalised ScanResult."""
        self.scan_result.urls_crawled = self._pages_crawled
        self.scan_result.pages_analyzed = self._pages_crawled
        self.scan_result.engine_diagnostics = self.tracker.build_statuses()
        self.scan_result.mark_complete()
        return self.scan_result

    # ------------------------------------------------------------------
    # Debug / introspection
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Return a lightweight progress snapshot suitable for logging."""
        return {
            "pages_crawled": self._pages_crawled,
            "pages_remaining": self.pages_remaining,
            "queue_size": self.queue_size,
            "visited_count": self.visited_count,
            "findings": len(self.scan_result.findings),
            "errors": len(self.scan_result.errors),
            "budget_exhausted": self.is_budget_exhausted,
        }
