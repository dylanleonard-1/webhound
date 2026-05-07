# WebHound — scanner/webhound/core/retry_policy.py
# Retry policy and exponential backoff helpers for HTTP request resilience.
#
# Design constraints (safe-mode-first):
#   - Only idempotent GET/HEAD requests are retried — never state-mutating methods.
#   - Retry delays respect the site's rate limits (backoff grows exponentially).
#   - 429 responses honour the Retry-After header when present.
#   - Maximum retry count is capped to prevent infinite loops.

from __future__ import annotations

import math
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# RetryPolicy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RetryPolicy:
    """Immutable configuration for request retry behaviour.

    All values are deliberately conservative to avoid placing extra load on
    the target server — the scanner's safe-mode guarantee applies to retries.
    """

    max_retries: int = 2
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 30.0
    backoff_multiplier: float = 2.0
    retry_on_status: frozenset[int] = field(
        default_factory=lambda: frozenset({429, 500, 502, 503, 504})
    )
    retry_on_timeout: bool = True


#: Safe default policy used by SafeHttpClient unless overridden.
DEFAULT_RETRY_POLICY = RetryPolicy()

#: No-retry policy — useful in tests and when the caller manages retries.
NO_RETRY_POLICY = RetryPolicy(max_retries=0)


# ---------------------------------------------------------------------------
# Backoff computation
# ---------------------------------------------------------------------------


def compute_backoff_delay(attempt: int, policy: RetryPolicy) -> float:
    """Return the delay in seconds before the next retry attempt.

    Uses exponential backoff: ``base * multiplier ** attempt``, capped at
    ``max_delay_seconds``.  *attempt* is zero-indexed (first retry = 0).

    >>> compute_backoff_delay(0, RetryPolicy(base_delay_seconds=1.0, backoff_multiplier=2.0))
    1.0
    >>> compute_backoff_delay(1, RetryPolicy(base_delay_seconds=1.0, backoff_multiplier=2.0))
    2.0
    """
    raw = policy.base_delay_seconds * (policy.backoff_multiplier ** attempt)
    return min(raw, policy.max_delay_seconds)


def should_retry(
    status_code: int,
    error: str | None,
    attempt: int,
    policy: RetryPolicy,
) -> bool:
    """Return True if the request should be retried.

    *attempt* is zero-indexed — ``attempt == 0`` means the first attempt just
    failed; the function returns True to trigger the first retry.
    """
    if attempt >= policy.max_retries:
        return False
    if status_code in policy.retry_on_status:
        return True
    if policy.retry_on_timeout and error and "timeout" in error.lower():
        return True
    return False


def parse_retry_after(retry_after_header: str | None) -> float | None:
    """Parse a ``Retry-After`` header value and return delay in seconds.

    Supports integer-second values only (date-based values are ignored).
    Returns ``None`` when the header is absent or not an integer.
    """
    if not retry_after_header:
        return None
    try:
        return float(int(retry_after_header.strip()))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# FetchStats — scan-wide HTTP request counters and timing
# ---------------------------------------------------------------------------


@dataclass
class FetchStats:
    """Counters and timing data aggregated across all HTTP requests in a scan."""

    requests_made: int = 0
    successful: int = 0
    failed: int = 0
    retried: int = 0
    timed_out: int = 0
    rate_limited: int = 0
    skipped: int = 0

    # Timing (ms) — only updated for successful responses
    elapsed_ms_total: float = 0.0
    elapsed_ms_min: float = math.inf
    elapsed_ms_max: float = 0.0

    def record(self, elapsed_ms: float, *, is_success: bool) -> None:
        """Record timing for one completed request."""
        self.requests_made += 1
        if is_success:
            self.successful += 1
            self.elapsed_ms_total += elapsed_ms
            if elapsed_ms < self.elapsed_ms_min:
                self.elapsed_ms_min = elapsed_ms
            if elapsed_ms > self.elapsed_ms_max:
                self.elapsed_ms_max = elapsed_ms
        else:
            self.failed += 1

    @property
    def mean_elapsed_ms(self) -> float:
        """Average response time over all successful requests."""
        if self.successful == 0:
            return 0.0
        return round(self.elapsed_ms_total / self.successful, 2)

    @property
    def min_elapsed_ms(self) -> float:
        """Minimum response time; 0.0 when no successful requests recorded."""
        return 0.0 if math.isinf(self.elapsed_ms_min) else round(self.elapsed_ms_min, 2)

    @property
    def max_elapsed_ms(self) -> float:
        return round(self.elapsed_ms_max, 2)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable summary dict."""
        return {
            "requests_made": self.requests_made,
            "successful": self.successful,
            "failed": self.failed,
            "retried": self.retried,
            "timed_out": self.timed_out,
            "rate_limited": self.rate_limited,
            "skipped": self.skipped,
            "response_time_ms": {
                "mean": self.mean_elapsed_ms,
                "min": self.min_elapsed_ms,
                "max": self.max_elapsed_ms,
            },
        }
