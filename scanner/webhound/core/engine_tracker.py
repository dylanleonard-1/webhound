# WebHound — scanner/webhound/core/engine_tracker.py
# Accumulates per-engine execution data across all pages in a scan run.
#
# Each engine appears exactly once in the final diagnostics, with aggregate
# findings, timing, and error state across every page it analyzed.

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from webhound.models.engine_status import EngineRunStatus, EngineStatus
from webhound.models.finding import Finding

# ---------------------------------------------------------------------------
# Engine-name → category mapping
# ---------------------------------------------------------------------------

_ENGINE_CATEGORIES: dict[str, str] = {
    "security_headers":     "headers",
    "cors":                 "headers",
    "cookie_scanner":       "cookies",
    "tls_checker":          "tls_dns",
    "dns_checker":          "tls_dns",
    "js_collector":         "javascript",
    "js_analyzer":          "javascript",
    "obfuscation_detector": "javascript",
    "third_party_domains":  "javascript",
    "technology":           "technology",
    "sensitive_paths":      "recon",
    "robots_sitemap":       "recon",
    "form_risk":            "forms",
    "input_analysis":       "forms",
    "injected_js":          "compromise",
    "hidden_iframes":       "compromise",
    "seo_spam":             "compromise",
    "suspicious_redirects": "compromise",
}

_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")


# ---------------------------------------------------------------------------
# Internal mutable accumulator
# ---------------------------------------------------------------------------


@dataclass
class _Accumulator:
    """Mutable, in-flight record for one engine across all pages."""

    name: str
    category: str
    is_passive: bool = True
    total_duration_ms: float = 0.0
    total_findings: int = 0
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {k: 0 for k in _SEVERITY_KEYS}
    )
    failed: bool = False
    error_message: str | None = None
    skipped: bool = False
    skipped_reason: str | None = None
    affected_target: str | None = None
    first_started_at: datetime | None = None
    last_finished_at: datetime | None = None


# ---------------------------------------------------------------------------
# Public tracker
# ---------------------------------------------------------------------------


class EngineTracker:
    """Collects execution data for every engine invoked during a scan.

    Call :meth:`record_run`, :meth:`record_error`, or :meth:`record_skip`
    as engines execute, then :meth:`build_statuses` at scan completion to
    obtain the finalized :class:`EngineStatus` list for ``ScanResult``.
    """

    def __init__(self) -> None:
        self._acc: dict[str, _Accumulator] = {}

    # ------------------------------------------------------------------
    # Recording API
    # ------------------------------------------------------------------

    def record_run(
        self,
        name: str,
        findings: list[Finding],
        duration_ms: float,
        started_at: datetime,
        finished_at: datetime,
        affected_target: str | None = None,
    ) -> None:
        """Record a successful engine invocation (zero or more findings)."""
        acc = self._get(name)
        acc.total_duration_ms += duration_ms
        acc.total_findings += len(findings)
        if acc.first_started_at is None:
            acc.first_started_at = started_at
        acc.last_finished_at = finished_at
        if affected_target and acc.affected_target is None:
            acc.affected_target = affected_target
        for f in findings:
            key = f.severity.value.lower()
            if key in acc.severity_counts:
                acc.severity_counts[key] += 1

    def record_error(
        self,
        name: str,
        error: str,
        duration_ms: float = 0.0,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
    ) -> None:
        """Record an engine that raised an exception."""
        acc = self._get(name)
        acc.failed = True
        if acc.error_message is None:
            acc.error_message = error
        acc.total_duration_ms += duration_ms
        if started_at and acc.first_started_at is None:
            acc.first_started_at = started_at
        if finished_at:
            acc.last_finished_at = finished_at

    def record_skip(self, name: str, reason: str) -> None:
        """Record an engine that was intentionally not called."""
        acc = self._get(name)
        acc.skipped = True
        acc.skipped_reason = reason

    # ------------------------------------------------------------------
    # Finalization
    # ------------------------------------------------------------------

    def build_statuses(self) -> list[EngineStatus]:
        """Convert all accumulators to finalized, immutable EngineStatus objects."""
        statuses: list[EngineStatus] = []
        for acc in self._acc.values():
            if acc.skipped:
                status = EngineRunStatus.SKIPPED
            elif acc.failed:
                status = EngineRunStatus.FAILED
            elif acc.total_findings > 0:
                status = EngineRunStatus.FINDINGS
            else:
                status = EngineRunStatus.PASSED

            statuses.append(EngineStatus(
                name=acc.name,
                category=acc.category,
                status=status,
                findings_count=acc.total_findings,
                severity_counts=acc.severity_counts.copy(),
                skipped_reason=acc.skipped_reason,
                error_message=acc.error_message,
                duration_ms=round(acc.total_duration_ms, 2),
                affected_target=acc.affected_target,
                is_passive=acc.is_passive,
                started_at=acc.first_started_at,
                finished_at=acc.last_finished_at,
            ))
        return statuses

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get(self, name: str) -> _Accumulator:
        if name not in self._acc:
            self._acc[name] = _Accumulator(
                name=name,
                category=_ENGINE_CATEGORIES.get(name, "unknown"),
            )
        return self._acc[name]
