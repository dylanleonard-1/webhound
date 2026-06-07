# WebHound API — apps/api/platform/jobs/retry_policy.py
# Phase-19 Task 4: scan-job retry/timeout/dead-letter policy. Pure
# decision logic the worker consults — it does NOT run jobs.
#
# Rules (from the spec):
#   * transient network failure → retry (bounded backoff)
#   * scanner logic / validation error → DO NOT infinite retry (dead-letter)
#   * browser failure degrades gracefully (handled in the scanner; here it
#     is NOT a job-level failure)
#   * domain-verification failure → do not enqueue a deep scan (caller gates)

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

MAX_RETRIES = 3
BASE_BACKOFF_SECONDS = 30
# Per-profile wall-clock job timeout (seconds) — caps a stuck job.
_PROFILE_TIMEOUT = {
    "quick": 180, "standard": 600, "monitor": 300,
    "deep": 1800, "enterprise": 2700,
}
_DEFAULT_TIMEOUT = 900


class FailureClass(str, Enum):
    TRANSIENT = "transient"          # retryable (network, timeout, 5xx, redis)
    PERMANENT = "permanent"          # do not retry (logic/validation/4xx)
    DEGRADED = "degraded"            # partial success — not a job failure


# Error-type / message fragments → class.
_TRANSIENT_HINTS = (
    "timeout", "timed out", "connection", "connectionreset", "econnreset",
    "temporarily", "503", "502", "504", "rate limit", "redis",
    "broker", "network", "dns", "ssl", "read timed out",
)
_PERMANENT_HINTS = (
    "validation", "invalid", "not found", "404", "401", "403",
    "unverified", "out of scope", "ssrf", "blocked", "scope",
    "valueerror", "keyerror", "typeerror", "assertionerror",
    "permission", "quota", "unauthorized",
)
_DEGRADED_HINTS = (
    "browser pass failed", "playwright", "chromium",
    "degraded gracefully",
)


@dataclass(frozen=True)
class RetryDecision:
    should_retry: bool
    failure_class: FailureClass
    attempt: int
    max_retries: int
    backoff_seconds: int
    dead_letter: bool
    reason: str


def classify_failure(error: str | Exception) -> FailureClass:
    text = str(error).lower()
    if any(h in text for h in _DEGRADED_HINTS):
        return FailureClass.DEGRADED
    if any(h in text for h in _PERMANENT_HINTS):
        return FailureClass.PERMANENT
    if any(h in text for h in _TRANSIENT_HINTS):
        return FailureClass.TRANSIENT
    # Unknown errors: retry ONCE conservatively, then dead-letter.
    return FailureClass.TRANSIENT


def decide_retry(
    error: str | Exception, *, attempt: int, max_retries: int = MAX_RETRIES,
) -> RetryDecision:
    """Decide whether a failed job should retry. ``attempt`` is the
    1-based attempt that just failed."""
    cls = classify_failure(error)
    if cls == FailureClass.PERMANENT:
        return RetryDecision(
            should_retry=False, failure_class=cls, attempt=attempt,
            max_retries=max_retries, backoff_seconds=0, dead_letter=True,
            reason="permanent error — dead-lettered, will not retry")
    if cls == FailureClass.DEGRADED:
        return RetryDecision(
            should_retry=False, failure_class=cls, attempt=attempt,
            max_retries=max_retries, backoff_seconds=0, dead_letter=False,
            reason="partial/degraded — job succeeds with reduced coverage")
    # Transient.
    if attempt >= max_retries:
        return RetryDecision(
            should_retry=False, failure_class=cls, attempt=attempt,
            max_retries=max_retries, backoff_seconds=0, dead_letter=True,
            reason=f"transient error but {attempt} attempts exhausted — "
                   "dead-lettered")
    backoff = BASE_BACKOFF_SECONDS * (2 ** (attempt - 1))   # 30, 60, 120…
    return RetryDecision(
        should_retry=True, failure_class=cls, attempt=attempt,
        max_retries=max_retries, backoff_seconds=backoff, dead_letter=False,
        reason=f"transient error — retry {attempt}/{max_retries} in "
               f"{backoff}s")


def job_timeout_seconds(profile: str | None) -> int:
    return _PROFILE_TIMEOUT.get((profile or "").lower(), _DEFAULT_TIMEOUT)
