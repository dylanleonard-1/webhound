# WebHound — scanner/webhound/core/performance.py
# Scan telemetry: aggregates timing, request, and engine metrics from a
# completed ScanResult into a single queryable object.
#
# Design notes:
#   - Pure data extraction — no I/O, no scanning logic.
#   - Zero-division safety throughout (0.0 returned instead of raising).
#   - All durations exposed in human-readable and machine-readable forms.
#   - ``ScanTelemetry`` is intentionally separate from ScanResult to keep
#     the model layer thin; telemetry is computed on demand, not stored.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from webhound.models.scan_result import ScanResult


@dataclass
class ScanTelemetry:
    """Aggregated performance telemetry for a completed scan.

    Build via :meth:`from_result` rather than constructing directly.

    All timing fields are in seconds unless the name ends in ``_ms``.
    """

    # Timing
    total_duration_seconds: float
    crawl_duration_seconds: float | None        # None when not instrumented
    engine_durations_ms: dict[str, float]       # engine_name → total ms

    # HTTP request counters
    total_requests: int
    successful_requests: int
    failed_requests: int
    retried_requests: int
    skipped_requests: int
    avg_request_ms: float

    # Crawl throughput
    pages_crawled: int
    pages_per_second: float                     # 0.0 if duration unavailable

    # Findings distribution
    findings_per_engine: dict[str, int]         # engine_name → count

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_result(cls, result: "ScanResult") -> "ScanTelemetry":
        """Build a ``ScanTelemetry`` from a completed (or partial) ScanResult."""
        duration = result.duration_seconds or 0.0
        crawl_dur: float | None = result.metadata.get("crawl_duration_seconds")

        fetch: dict[str, Any] = result.metadata.get("fetch_stats", {})
        rt: dict[str, Any] = fetch.get("response_time_ms", {})

        pages = result.urls_crawled
        pps = (
            round(pages / crawl_dur, 2)
            if crawl_dur and crawl_dur > 0
            else 0.0
        )

        engine_durations_ms = {
            d.name: round(d.duration_ms, 2)
            for d in result.engine_diagnostics
        }
        findings_per_engine = {
            d.name: d.findings_count
            for d in result.engine_diagnostics
        }

        return cls(
            total_duration_seconds=round(duration, 3),
            crawl_duration_seconds=(
                round(crawl_dur, 3) if crawl_dur is not None else None
            ),
            engine_durations_ms=engine_durations_ms,
            total_requests=fetch.get("requests_made", 0),
            successful_requests=fetch.get("successful", 0),
            failed_requests=fetch.get("failed", 0),
            retried_requests=fetch.get("retried", 0),
            skipped_requests=fetch.get("skipped", 0),
            avg_request_ms=round(rt.get("mean", 0.0), 2),
            pages_crawled=pages,
            pages_per_second=pps,
            findings_per_engine=findings_per_engine,
        )

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------

    def slowest_engines(self, n: int = 5) -> list[tuple[str, float]]:
        """Return the top-*n* engines sorted by total duration (ms), descending."""
        return sorted(
            self.engine_durations_ms.items(),
            key=lambda kv: kv[1],
            reverse=True,
        )[:n]

    def total_engine_ms(self) -> float:
        """Sum of all engine durations in milliseconds."""
        return round(sum(self.engine_durations_ms.values()), 2)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of all telemetry."""
        return {
            "timing_stats": {
                "total_duration_seconds": self.total_duration_seconds,
                "crawl_duration_seconds": self.crawl_duration_seconds,
                "total_engine_ms": self.total_engine_ms(),
                "engine_durations_ms": self.engine_durations_ms,
            },
            "request_stats": {
                "total_requests": self.total_requests,
                "successful_requests": self.successful_requests,
                "failed_requests": self.failed_requests,
                "retried_requests": self.retried_requests,
                "skipped_requests": self.skipped_requests,
                "avg_request_ms": self.avg_request_ms,
            },
            "crawl_stats": {
                "pages_crawled": self.pages_crawled,
                "pages_per_second": self.pages_per_second,
            },
            "findings_per_engine": self.findings_per_engine,
            "slowest_engines": [
                {"name": name, "duration_ms": ms}
                for name, ms in self.slowest_engines(5)
            ],
        }
