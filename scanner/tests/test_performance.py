# WebHound — scanner/tests/test_performance.py
# Tests for Phase 18B: performance benchmarking and scan telemetry.
#
# Covers: ScanTelemetry.from_result(), slowest_engines(), pages_per_second,
# zero-division safety, JSON report performance section, summary performance
# output, and --benchmark CLI flag parsing.

from __future__ import annotations

import argparse
from datetime import datetime, timezone

import pytest

from webhound.core.performance import ScanTelemetry
from webhound.models.engine_status import EngineRunStatus, EngineStatus
from webhound.models.scan_result import ScanResult, ScanStatus
from webhound.models.target import Target


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _target() -> Target:
    return Target.from_url("https://example.com")


def _engine_status(
    name: str,
    duration_ms: float = 100.0,
    findings_count: int = 0,
    status: EngineRunStatus = EngineRunStatus.PASSED,
) -> EngineStatus:
    return EngineStatus(
        name=name,
        category="test",
        status=status,
        findings_count=findings_count,
        duration_ms=duration_ms,
    )


def _result_with_telemetry(
    *,
    pages: int = 5,
    duration_seconds: float = 10.0,
    crawl_duration: float = 4.0,
    engines: list[EngineStatus] | None = None,
    fetch_stats: dict | None = None,
) -> ScanResult:
    result = ScanResult(
        target=_target(),
        status=ScanStatus.COMPLETED,
        urls_crawled=pages,
        pages_analyzed=pages,
        started_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(
            2025, 1, 1, 12, 0, int(duration_seconds), tzinfo=timezone.utc
        ),
        engine_diagnostics=engines or [],
    )
    result.metadata["crawl_duration_seconds"] = crawl_duration
    if fetch_stats is not None:
        result.metadata["fetch_stats"] = fetch_stats
    return result


# ---------------------------------------------------------------------------
# ScanTelemetry.from_result — basic extraction
# ---------------------------------------------------------------------------


class TestScanTelemetryFromResult:
    def test_pages_crawled(self) -> None:
        r = _result_with_telemetry(pages=7)
        tel = ScanTelemetry.from_result(r)
        assert tel.pages_crawled == 7

    def test_total_duration(self) -> None:
        r = _result_with_telemetry(duration_seconds=12)
        tel = ScanTelemetry.from_result(r)
        assert tel.total_duration_seconds == pytest.approx(12.0, abs=0.5)

    def test_crawl_duration_extracted(self) -> None:
        r = _result_with_telemetry(crawl_duration=3.5)
        tel = ScanTelemetry.from_result(r)
        assert tel.crawl_duration_seconds == pytest.approx(3.5)

    def test_crawl_duration_none_when_absent(self) -> None:
        r = ScanResult(target=_target())
        tel = ScanTelemetry.from_result(r)
        assert tel.crawl_duration_seconds is None

    def test_engine_durations_extracted(self) -> None:
        r = _result_with_telemetry(engines=[
            _engine_status("headers", duration_ms=80.0),
            _engine_status("tls", duration_ms=150.0),
        ])
        tel = ScanTelemetry.from_result(r)
        assert tel.engine_durations_ms["headers"] == pytest.approx(80.0)
        assert tel.engine_durations_ms["tls"] == pytest.approx(150.0)

    def test_findings_per_engine_extracted(self) -> None:
        r = _result_with_telemetry(engines=[
            _engine_status("headers", findings_count=3, status=EngineRunStatus.FINDINGS),
            _engine_status("tls", findings_count=0),
        ])
        tel = ScanTelemetry.from_result(r)
        assert tel.findings_per_engine["headers"] == 3
        assert tel.findings_per_engine["tls"] == 0

    def test_request_stats_extracted(self) -> None:
        fetch = {
            "requests_made": 10,
            "successful": 9,
            "failed": 1,
            "retried": 2,
            "skipped": 0,
            "response_time_ms": {"mean": 85.5},
        }
        r = _result_with_telemetry(fetch_stats=fetch)
        tel = ScanTelemetry.from_result(r)
        assert tel.total_requests == 10
        assert tel.successful_requests == 9
        assert tel.failed_requests == 1
        assert tel.retried_requests == 2
        assert tel.skipped_requests == 0
        assert tel.avg_request_ms == pytest.approx(85.5)

    def test_zero_request_stats_when_absent(self) -> None:
        r = ScanResult(target=_target())
        tel = ScanTelemetry.from_result(r)
        assert tel.total_requests == 0
        assert tel.avg_request_ms == 0.0


# ---------------------------------------------------------------------------
# pages_per_second — computation and zero-division safety
# ---------------------------------------------------------------------------


class TestPagesPerSecond:
    def test_normal_calculation(self) -> None:
        r = _result_with_telemetry(pages=10, crawl_duration=5.0)
        tel = ScanTelemetry.from_result(r)
        assert tel.pages_per_second == pytest.approx(2.0)

    def test_zero_duration_returns_zero(self) -> None:
        r = _result_with_telemetry(pages=10, crawl_duration=0.0)
        tel = ScanTelemetry.from_result(r)
        assert tel.pages_per_second == 0.0

    def test_none_crawl_duration_returns_zero(self) -> None:
        r = ScanResult(target=_target(), urls_crawled=5)
        tel = ScanTelemetry.from_result(r)
        assert tel.pages_per_second == 0.0

    def test_zero_pages_with_positive_duration(self) -> None:
        r = _result_with_telemetry(pages=0, crawl_duration=5.0)
        tel = ScanTelemetry.from_result(r)
        assert tel.pages_per_second == 0.0

    def test_result_is_rounded(self) -> None:
        r = _result_with_telemetry(pages=10, crawl_duration=3.0)
        tel = ScanTelemetry.from_result(r)
        # 10/3 ≈ 3.333…
        assert tel.pages_per_second == pytest.approx(3.33, abs=0.01)


# ---------------------------------------------------------------------------
# slowest_engines — sorting and limits
# ---------------------------------------------------------------------------


class TestSlowestEngines:
    def test_sorted_descending(self) -> None:
        r = _result_with_telemetry(engines=[
            _engine_status("fast", duration_ms=10.0),
            _engine_status("slow", duration_ms=500.0),
            _engine_status("medium", duration_ms=100.0),
        ])
        tel = ScanTelemetry.from_result(r)
        names = [name for name, _ in tel.slowest_engines()]
        assert names[0] == "slow"
        assert names[1] == "medium"
        assert names[2] == "fast"

    def test_respects_n_limit(self) -> None:
        r = _result_with_telemetry(engines=[
            _engine_status(f"engine_{i}", duration_ms=float(i * 10))
            for i in range(10)
        ])
        tel = ScanTelemetry.from_result(r)
        assert len(tel.slowest_engines(3)) == 3
        assert len(tel.slowest_engines(5)) == 5

    def test_fewer_than_n_returns_all(self) -> None:
        r = _result_with_telemetry(engines=[
            _engine_status("only", duration_ms=42.0),
        ])
        tel = ScanTelemetry.from_result(r)
        result = tel.slowest_engines(5)
        assert len(result) == 1

    def test_empty_engines_returns_empty(self) -> None:
        r = _result_with_telemetry(engines=[])
        tel = ScanTelemetry.from_result(r)
        assert tel.slowest_engines() == []

    def test_default_n_is_five(self) -> None:
        r = _result_with_telemetry(engines=[
            _engine_status(f"e{i}", duration_ms=float(i))
            for i in range(8)
        ])
        tel = ScanTelemetry.from_result(r)
        assert len(tel.slowest_engines()) == 5


# ---------------------------------------------------------------------------
# total_engine_ms
# ---------------------------------------------------------------------------


def test_total_engine_ms_sums_all():
    r = _result_with_telemetry(engines=[
        _engine_status("a", duration_ms=100.0),
        _engine_status("b", duration_ms=200.0),
        _engine_status("c", duration_ms=50.0),
    ])
    tel = ScanTelemetry.from_result(r)
    assert tel.total_engine_ms() == pytest.approx(350.0)


def test_total_engine_ms_empty():
    r = ScanResult(target=_target())
    tel = ScanTelemetry.from_result(r)
    assert tel.total_engine_ms() == 0.0


# ---------------------------------------------------------------------------
# to_dict — structure and keys
# ---------------------------------------------------------------------------


class TestScanTelemetryToDict:
    def test_top_level_keys(self) -> None:
        r = ScanResult(target=_target())
        d = ScanTelemetry.from_result(r).to_dict()
        assert "timing_stats" in d
        assert "request_stats" in d
        assert "crawl_stats" in d
        assert "findings_per_engine" in d
        assert "slowest_engines" in d

    def test_timing_stats_keys(self) -> None:
        r = ScanResult(target=_target())
        d = ScanTelemetry.from_result(r).to_dict()
        ts = d["timing_stats"]
        assert "total_duration_seconds" in ts
        assert "crawl_duration_seconds" in ts
        assert "total_engine_ms" in ts
        assert "engine_durations_ms" in ts

    def test_request_stats_keys(self) -> None:
        r = ScanResult(target=_target())
        d = ScanTelemetry.from_result(r).to_dict()
        rs = d["request_stats"]
        assert "total_requests" in rs
        assert "successful_requests" in rs
        assert "failed_requests" in rs
        assert "retried_requests" in rs
        assert "skipped_requests" in rs
        assert "avg_request_ms" in rs

    def test_crawl_stats_keys(self) -> None:
        r = ScanResult(target=_target())
        d = ScanTelemetry.from_result(r).to_dict()
        cs = d["crawl_stats"]
        assert "pages_crawled" in cs
        assert "pages_per_second" in cs

    def test_slowest_engines_list_shape(self) -> None:
        r = _result_with_telemetry(engines=[
            _engine_status("e1", duration_ms=120.0),
        ])
        d = ScanTelemetry.from_result(r).to_dict()
        assert len(d["slowest_engines"]) == 1
        assert d["slowest_engines"][0]["name"] == "e1"
        assert d["slowest_engines"][0]["duration_ms"] == pytest.approx(120.0)


# ---------------------------------------------------------------------------
# JSON report performance section
# ---------------------------------------------------------------------------


class TestJsonReportPerformance:
    def test_performance_key_present(self) -> None:
        from webhound.reporting.json_report import JsonReport

        r = _result_with_telemetry(pages=3, crawl_duration=2.0)
        r.mark_complete()
        report = JsonReport().build(r)
        assert "performance" in report

    def test_performance_has_timing_stats(self) -> None:
        from webhound.reporting.json_report import JsonReport

        r = _result_with_telemetry(pages=3, crawl_duration=2.0)
        r.mark_complete()
        report = JsonReport().build(r)
        perf = report["performance"]
        assert "timing_stats" in perf
        assert "request_stats" in perf
        assert "crawl_stats" in perf
        assert "slowest_engines" in perf

    def test_crawl_stats_pages(self) -> None:
        from webhound.reporting.json_report import JsonReport

        r = _result_with_telemetry(pages=7, crawl_duration=3.5)
        r.mark_complete()
        report = JsonReport().build(r)
        assert report["performance"]["crawl_stats"]["pages_crawled"] == 7

    def test_pages_per_second_in_report(self) -> None:
        from webhound.reporting.json_report import JsonReport

        r = _result_with_telemetry(pages=10, crawl_duration=5.0)
        r.mark_complete()
        report = JsonReport().build(r)
        pps = report["performance"]["crawl_stats"]["pages_per_second"]
        assert pps == pytest.approx(2.0)

    def test_request_stats_in_report(self) -> None:
        from webhound.reporting.json_report import JsonReport

        r = _result_with_telemetry(
            pages=5,
            fetch_stats={
                "requests_made": 8, "successful": 7, "failed": 1,
                "retried": 0, "skipped": 0, "response_time_ms": {"mean": 90.0},
            }
        )
        r.mark_complete()
        report = JsonReport().build(r)
        rs = report["performance"]["request_stats"]
        assert rs["total_requests"] == 8
        assert rs["successful_requests"] == 7
        assert rs["failed_requests"] == 1

    def test_slowest_engines_in_report(self) -> None:
        from webhound.reporting.json_report import JsonReport

        r = _result_with_telemetry(engines=[
            _engine_status("slow_engine", duration_ms=450.0),
            _engine_status("fast_engine", duration_ms=50.0),
        ])
        r.mark_complete()
        report = JsonReport().build(r)
        slowest = report["performance"]["slowest_engines"]
        assert len(slowest) >= 1
        assert slowest[0]["name"] == "slow_engine"


# ---------------------------------------------------------------------------
# Summary builder performance section
# ---------------------------------------------------------------------------


class TestSummaryPerformanceSection:
    def _build_summary(self, **kwargs) -> str:
        from webhound.reporting.summary_builder import SummaryBuilder

        r = _result_with_telemetry(**kwargs)
        r.metadata["risk_score"] = 80
        r.metadata["risk_level"] = "low"
        return SummaryBuilder().build(r)

    def test_performance_header_present(self) -> None:
        summary = self._build_summary()
        assert "Performance:" in summary

    def test_duration_present(self) -> None:
        summary = self._build_summary(duration_seconds=5)
        assert "Duration:" in summary

    def test_requests_line_present(self) -> None:
        summary = self._build_summary(
            fetch_stats={
                "requests_made": 8, "successful": 7, "failed": 1,
                "retried": 0, "skipped": 0, "response_time_ms": {"mean": 80.0},
            }
        )
        assert "Requests:" in summary
        assert "8 total" in summary

    def test_slowest_engine_shown_when_available(self) -> None:
        from webhound.reporting.summary_builder import SummaryBuilder

        r = _result_with_telemetry(engines=[
            _engine_status("robots_sitemap", duration_ms=312.0),
        ])
        r.metadata["risk_score"] = 80
        r.metadata["risk_level"] = "low"
        summary = SummaryBuilder().build(r)
        assert "Slowest engine:" in summary
        assert "robots_sitemap" in summary


# ---------------------------------------------------------------------------
# --benchmark flag
# ---------------------------------------------------------------------------


def test_benchmark_flag_registered():
    """--benchmark flag should be parseable without error."""
    import sys

    sys.path.insert(0, "/mnt/c/Users/dmleo/OneDrive/Documents/Scripts/WebHound/scanner")
    from run_scan import _build_arg_parser

    parser = _build_arg_parser()
    args = parser.parse_args(["https://example.com", "--benchmark"])
    assert args.benchmark is True


def test_benchmark_flag_default_false():
    import sys

    sys.path.insert(0, "/mnt/c/Users/dmleo/OneDrive/Documents/Scripts/WebHound/scanner")
    from run_scan import _build_arg_parser

    parser = _build_arg_parser()
    args = parser.parse_args(["https://example.com"])
    assert args.benchmark is False


def test_benchmark_flag_with_profile():
    import sys

    sys.path.insert(0, "/mnt/c/Users/dmleo/OneDrive/Documents/Scripts/WebHound/scanner")
    from run_scan import _build_arg_parser

    parser = _build_arg_parser()
    args = parser.parse_args(["https://example.com", "--profile", "quick", "--benchmark"])
    assert args.benchmark is True
    assert args.profile == "quick"
