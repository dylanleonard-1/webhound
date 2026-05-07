# WebHound — scanner/tests/test_hardening.py
# Phase 17: real-world validation and runtime hardening tests.
#
# Covers: retry policy math, FetchStats, HTTP client retry behaviour,
# FP confidence suppression, engine timeout isolation, malformed response
# resilience, and performance metrics in the JSON report.

from __future__ import annotations

import asyncio
from unittest.mock import patch

import httpx
import pytest

from webhound.core.fp_filter import FPFilter, _MIN_CONFIDENCE
from webhound.core.http_client import SafeHttpClient
from webhound.core.retry_policy import (
    DEFAULT_RETRY_POLICY,
    NO_RETRY_POLICY,
    FetchStats,
    RetryPolicy,
    compute_backoff_delay,
    parse_retry_after,
    should_retry,
)
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    scanner_engine: str = "test",
    category: FindingCategory = FindingCategory.JAVASCRIPT,
    confidence: float = 1.0,
    evidence_location: str = "https://example.com/",
    evidence_content: str = "",
) -> Finding:
    return Finding(
        title="Test Finding",
        description="Desc",
        severity=Severity.MEDIUM,
        category=category,
        scanner_engine=scanner_engine,
        confidence=confidence,
        evidence=[Evidence(
            evidence_type=EvidenceType.HTTP_RESPONSE,
            location=evidence_location,
            content=evidence_content,
            source_engine=scanner_engine,
        )],
    )


def _fast_options() -> ScanOptions:
    """Scan options with max allowed RPS to make tests near-instant."""
    return ScanOptions(rate_limit_rps=10.0, request_timeout_seconds=5)


class _SequencedTransport(httpx.AsyncBaseTransport):
    """Mock transport that replays a fixed list of responses in order."""

    def __init__(self, responses: list) -> None:
        self._responses = list(responses)
        self._idx = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if self._idx >= len(self._responses):
            return self._responses[-1]
        r = self._responses[self._idx]
        self._idx += 1
        if isinstance(r, Exception):
            raise r
        return r

    @property
    def call_count(self) -> int:
        return self._idx


def _resp(status: int, body: bytes = b"OK", headers: dict | None = None) -> httpx.Response:
    h = {"content-type": "text/html; charset=utf-8"}
    if headers:
        h.update(headers)
    return httpx.Response(status, content=body, headers=h)


# ---------------------------------------------------------------------------
# RetryPolicy — unit tests
# ---------------------------------------------------------------------------


def test_compute_backoff_delay_base():
    policy = RetryPolicy(base_delay_seconds=1.0, backoff_multiplier=2.0)
    assert compute_backoff_delay(0, policy) == pytest.approx(1.0)
    assert compute_backoff_delay(1, policy) == pytest.approx(2.0)
    assert compute_backoff_delay(2, policy) == pytest.approx(4.0)


def test_compute_backoff_delay_capped():
    policy = RetryPolicy(base_delay_seconds=1.0, backoff_multiplier=2.0, max_delay_seconds=3.0)
    assert compute_backoff_delay(5, policy) == pytest.approx(3.0)


def test_should_retry_respects_max_retries():
    policy = RetryPolicy(max_retries=2)
    assert should_retry(503, None, 0, policy) is True
    assert should_retry(503, None, 1, policy) is True
    assert should_retry(503, None, 2, policy) is False  # exhausted


def test_should_retry_on_retryable_status():
    policy = RetryPolicy(max_retries=3)
    for status in (429, 500, 502, 503, 504):
        assert should_retry(status, None, 0, policy) is True


def test_should_retry_not_on_client_error():
    policy = RetryPolicy(max_retries=3)
    for status in (200, 301, 400, 401, 403, 404):
        assert should_retry(status, None, 0, policy) is False


def test_should_retry_on_timeout():
    policy = RetryPolicy(max_retries=3, retry_on_timeout=True)
    assert should_retry(0, "timeout: read timeout", 0, policy) is True


def test_should_retry_no_timeout_when_disabled():
    policy = RetryPolicy(max_retries=3, retry_on_timeout=False)
    assert should_retry(0, "timeout: read timeout", 0, policy) is False


def test_parse_retry_after_integer():
    assert parse_retry_after("30") == pytest.approx(30.0)
    assert parse_retry_after("  5  ") == pytest.approx(5.0)


def test_parse_retry_after_none_on_bad_input():
    assert parse_retry_after(None) is None
    assert parse_retry_after("") is None
    assert parse_retry_after("Thu, 01 Jan 2099 00:00:00 GMT") is None


# ---------------------------------------------------------------------------
# FetchStats — unit tests
# ---------------------------------------------------------------------------


def test_fetch_stats_record_success():
    stats = FetchStats()
    stats.record(120.5, is_success=True)
    assert stats.requests_made == 1
    assert stats.successful == 1
    assert stats.failed == 0
    assert stats.mean_elapsed_ms == pytest.approx(120.5)
    assert stats.min_elapsed_ms == pytest.approx(120.5)
    assert stats.max_elapsed_ms == pytest.approx(120.5)


def test_fetch_stats_record_failure():
    stats = FetchStats()
    stats.record(0.0, is_success=False)
    assert stats.requests_made == 1
    assert stats.failed == 1
    assert stats.successful == 0
    assert stats.mean_elapsed_ms == pytest.approx(0.0)
    assert stats.min_elapsed_ms == pytest.approx(0.0)


def test_fetch_stats_min_max():
    stats = FetchStats()
    stats.record(50.0, is_success=True)
    stats.record(200.0, is_success=True)
    assert stats.min_elapsed_ms == pytest.approx(50.0)
    assert stats.max_elapsed_ms == pytest.approx(200.0)
    assert stats.mean_elapsed_ms == pytest.approx(125.0)


def test_fetch_stats_to_dict():
    stats = FetchStats()
    stats.record(100.0, is_success=True)
    stats.retried = 2
    stats.timed_out = 1
    d = stats.to_dict()
    assert d["requests_made"] == 1
    assert d["successful"] == 1
    assert d["retried"] == 2
    assert d["timed_out"] == 1
    assert "response_time_ms" in d
    assert d["response_time_ms"]["mean"] == pytest.approx(100.0)


# ---------------------------------------------------------------------------
# SafeHttpClient — retry integration tests
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_client_returns_200_on_first_try():
    transport = _SequencedTransport([_resp(200, b"<html></html>")])
    async with SafeHttpClient(_fast_options(), transport=transport) as client:
        r = await client.get("https://example.com/")
    assert r.status_code == 200
    assert r.retry_count == 0
    assert client.fetch_stats.successful == 1
    assert client.fetch_stats.retried == 0


@pytest.mark.anyio
async def test_client_retries_on_503_then_succeeds():
    policy = RetryPolicy(max_retries=2, base_delay_seconds=0.001)
    transport = _SequencedTransport([_resp(503), _resp(200, b"<html></html>")])
    async with SafeHttpClient(_fast_options(), transport=transport, retry_policy=policy) as client:
        r = await client.get("https://example.com/")
    assert r.status_code == 200
    assert r.retry_count == 1
    assert client.fetch_stats.retried == 1
    assert client.fetch_stats.successful == 1


@pytest.mark.anyio
async def test_client_exhausts_retries_returns_last_response():
    policy = RetryPolicy(max_retries=2, base_delay_seconds=0.001)
    transport = _SequencedTransport([_resp(503), _resp(503), _resp(503)])
    async with SafeHttpClient(_fast_options(), transport=transport, retry_policy=policy) as client:
        r = await client.get("https://example.com/")
    # After max_retries exhausted, the final 503 response is returned as-is
    assert r.status_code == 503
    assert r.retry_count == 2
    assert client.fetch_stats.retried == 2


@pytest.mark.anyio
async def test_client_handles_429_with_retry_after():
    policy = RetryPolicy(max_retries=2, base_delay_seconds=0.001)
    transport = _SequencedTransport([
        _resp(429, headers={"retry-after": "0"}),  # Retry-After: 0s
        _resp(200, b"<html></html>"),
    ])
    async with SafeHttpClient(_fast_options(), transport=transport, retry_policy=policy) as client:
        r = await client.get("https://example.com/")
    assert r.status_code == 200
    assert r.retry_count == 1
    assert client.fetch_stats.rate_limited == 1
    assert client.fetch_stats.retried == 1


@pytest.mark.anyio
async def test_client_records_timeout():
    policy = RetryPolicy(max_retries=0)
    transport = _SequencedTransport([httpx.ReadTimeout("timed out")])
    async with SafeHttpClient(_fast_options(), transport=transport, retry_policy=policy) as client:
        r = await client.get("https://example.com/")
    assert r.failed is True
    assert "timeout" in (r.error or "")
    assert client.fetch_stats.timed_out == 1
    assert client.fetch_stats.failed == 1


@pytest.mark.anyio
async def test_client_retries_on_timeout():
    policy = RetryPolicy(max_retries=1, base_delay_seconds=0.001, retry_on_timeout=True)
    transport = _SequencedTransport([
        httpx.ReadTimeout("timed out"),
        _resp(200, b"<html></html>"),
    ])
    async with SafeHttpClient(_fast_options(), transport=transport, retry_policy=policy) as client:
        r = await client.get("https://example.com/")
    assert r.status_code == 200
    assert r.retry_count == 1
    assert client.fetch_stats.timed_out == 1
    assert client.fetch_stats.retried == 1


@pytest.mark.anyio
async def test_client_no_retry_policy_skips_retries():
    transport = _SequencedTransport([_resp(503), _resp(200)])
    async with SafeHttpClient(_fast_options(), transport=transport, retry_policy=NO_RETRY_POLICY) as client:
        r = await client.get("https://example.com/")
    assert r.status_code == 503
    assert r.retry_count == 0


@pytest.mark.anyio
async def test_client_malformed_body_decodes_safely():
    """A response with undecodable bytes should not raise — body defaults to empty."""
    bad_body = b"\xff\xfe malformed"
    transport = _SequencedTransport([
        httpx.Response(200, content=bad_body,
                       headers={"content-type": "text/html; charset=utf-8"})
    ])
    async with SafeHttpClient(_fast_options(), transport=transport) as client:
        r = await client.get("https://example.com/")
    # errors="replace" means body is non-empty but safe
    assert r.status_code == 200
    assert isinstance(r.body, str)


# ---------------------------------------------------------------------------
# FPFilter — confidence suppression tests
# ---------------------------------------------------------------------------


def test_fp_filter_cdn_domain_reduces_confidence():
    finding = _make_finding(
        scanner_engine="third_party_domains",
        category=FindingCategory.JAVASCRIPT,
        evidence_location="https://cdn.shopify.com/assets/chunk.js",
        confidence=1.0,
    )
    result = FPFilter().filter([finding])
    assert len(result) == 1
    assert result[0].confidence < finding.confidence


def test_fp_filter_technology_engine_reduces_confidence():
    finding = _make_finding(
        scanner_engine="technology",
        category=FindingCategory.TECHNOLOGY,
        confidence=1.0,
    )
    result = FPFilter().filter([finding])
    assert result[0].confidence < 1.0


def test_fp_filter_nextjs_path_reduces_confidence():
    finding = _make_finding(
        scanner_engine="test",
        category=FindingCategory.RECON,
        evidence_location="https://example.com/_next/static/chunk.js",
        confidence=1.0,
    )
    result = FPFilter().filter([finding])
    assert result[0].confidence < 1.0


def test_fp_filter_never_removes_findings():
    findings = [
        _make_finding(scanner_engine="third_party_domains",
                      category=FindingCategory.JAVASCRIPT,
                      evidence_location="https://cdn.shopify.com/x"),
        _make_finding(scanner_engine="security_headers"),
        _make_finding(scanner_engine="technology", category=FindingCategory.TECHNOLOGY),
    ]
    result = FPFilter().filter(findings)
    assert len(result) == len(findings)


def test_fp_filter_respects_confidence_floor():
    """Confidence should never drop below _MIN_CONFIDENCE even with stacked rules."""
    finding = _make_finding(
        scanner_engine="third_party_domains",
        category=FindingCategory.JAVASCRIPT,
        evidence_location="https://cdnjs.cloudflare.com/test.js",
        evidence_content="cdnjs.cloudflare.com",
        confidence=0.05,  # already below floor
    )
    result = FPFilter().filter([finding])
    assert result[0].confidence >= _MIN_CONFIDENCE


def test_fp_filter_no_change_for_genuine_findings():
    finding = _make_finding(
        scanner_engine="security_headers",
        category=FindingCategory.SECURITY_HEADER,
        evidence_location="https://example.com/",
        confidence=0.9,
    )
    result = FPFilter().filter([finding])
    assert result[0].confidence == pytest.approx(0.9)


def test_fp_filter_combined_rules_multiply():
    """A finding matching multiple rules gets compounded suppression."""
    finding = _make_finding(
        scanner_engine="third_party_domains",
        category=FindingCategory.JAVASCRIPT,
        evidence_location="https://cdnjs.cloudflare.com/_next/chunk.js",
        confidence=1.0,
    )
    result_single = FPFilter().filter([
        _make_finding(scanner_engine="third_party_domains",
                      category=FindingCategory.JAVASCRIPT,
                      evidence_location="https://cdnjs.cloudflare.com/lib.js",
                      confidence=1.0)
    ])
    result_multi = FPFilter().filter([finding])
    # CDN + safe path → lower confidence than CDN alone
    assert result_multi[0].confidence <= result_single[0].confidence


# ---------------------------------------------------------------------------
# Engine timeout isolation
# ---------------------------------------------------------------------------


@pytest.mark.anyio
async def test_engine_timeout_isolation():
    """A coroutine engine that hangs is cancelled and its error is recorded."""
    from webhound.core.orchestrator import _safe
    from webhound.core.scan_context import ScanContext

    async def forever_engine() -> list:
        await asyncio.sleep(9999)
        return []

    target = Target.from_url("https://example.com")
    ctx = ScanContext(target)

    with patch("webhound.core.orchestrator._ENGINE_TIMEOUT_SECONDS", 0.05):
        findings = await _safe(ctx, "slow_engine", forever_engine)

    assert findings == []
    assert any("slow_engine" == e.engine for e in ctx.scan_result.errors)
    error_msg = next(e.message for e in ctx.scan_result.errors if e.engine == "slow_engine")
    assert "timeout" in error_msg.lower()


@pytest.mark.anyio
async def test_engine_error_does_not_abort_scan():
    """An engine raising an unexpected exception records an error and returns []."""
    from webhound.core.orchestrator import _safe
    from webhound.core.scan_context import ScanContext

    def crashing_engine() -> list:
        raise ValueError("simulated crash")

    target = Target.from_url("https://example.com")
    ctx = ScanContext(target)
    findings = await _safe(ctx, "crash_engine", crashing_engine)

    assert findings == []
    assert any("crash_engine" == e.engine for e in ctx.scan_result.errors)


# ---------------------------------------------------------------------------
# Performance metrics in JSON report
# ---------------------------------------------------------------------------


def test_performance_metrics_in_json_report():
    from webhound.models.scan_result import ScanResult
    from webhound.reporting.json_report import JsonReport

    target = Target.from_url("https://example.com")
    result = ScanResult(target=target)
    result.metadata["fetch_stats"] = {
        "requests_made": 5,
        "successful": 4,
        "failed": 1,
        "retried": 2,
        "timed_out": 0,
        "rate_limited": 1,
        "skipped": 0,
        "response_time_ms": {"mean": 123.4, "min": 80.0, "max": 200.0},
    }
    result.retry_count = 2
    result.skip_count = 0
    result.mark_complete()

    report = JsonReport().build(result)
    assert "performance" in report
    perf = report["performance"]
    # Performance is now a ScanTelemetry dict with nested sections
    rs = perf["request_stats"]
    assert rs["total_requests"] == 5
    assert rs["retried_requests"] == 2
    assert rs["avg_request_ms"] == pytest.approx(123.4)

    crawl = report["crawl"]
    assert crawl["retry_count"] == 2
    assert crawl["skip_count"] == 0


def test_performance_section_always_present_in_report():
    from webhound.models.scan_result import ScanResult
    from webhound.reporting.json_report import JsonReport

    target = Target.from_url("https://example.com")
    result = ScanResult(target=target)
    result.mark_complete()

    report = JsonReport().build(result)
    assert "performance" in report
    # Even with no fetch_stats, all structural keys are present
    perf = report["performance"]
    assert "timing_stats" in perf
    assert "request_stats" in perf
    assert "crawl_stats" in perf
