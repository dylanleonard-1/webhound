# WebHound — tests/test_engine_health.py
# Phase-19 Task 5/6: engine-health aggregation + performance metrics.

from __future__ import annotations

from types import SimpleNamespace as NS

from webhound.core.engine_health import (
    aggregate_engine_health,
    health_report,
)
from webhound.core.performance_metrics import extract_performance_metrics


def _rec(name, status="passed", findings=0, duration=10.0, error=None):
    return {"name": name, "status": status, "findings_count": findings,
            "duration_ms": duration, "error_message": error}


# ---------------------------------------------------------------------------
# Engine health (Task 5)
# ---------------------------------------------------------------------------


def test_aggregate_success_and_findings() -> None:
    recs = [_rec("headers", "findings", 3), _rec("headers", "passed", 0),
            _rec("headers", "findings", 1)]
    h = aggregate_engine_health(recs)["headers"]
    assert h.runs == 3
    assert h.successes == 3
    assert h.total_findings == 4
    assert h.scans_with_findings == 2
    assert h.findings_rate == round(2 / 3, 4)


def test_failure_rate_flags_unhealthy() -> None:
    recs = ([_rec("tls", "failed", error="boom") for _ in range(6)]
            + [_rec("tls", "passed", 0) for _ in range(4)])
    h = aggregate_engine_health(recs)["tls"]
    assert h.failures == 6
    assert h.failure_rate == 0.6
    assert h.is_unhealthy
    assert "failed" in h.health_note()


def test_timeout_counted() -> None:
    h = aggregate_engine_health([
        _rec("dns", "failed", error="engine timeout after 60s")])["dns"]
    assert h.timeouts == 1


def test_silent_engine_flagged() -> None:
    # 12 successful runs, never any findings → possible breakage.
    recs = [_rec("third_party_domains", "passed", 0) for _ in range(12)]
    h = aggregate_engine_health(recs)["third_party_domains"]
    assert h.is_unhealthy
    assert "0 findings" in h.health_note()


def test_healthy_engine_not_flagged() -> None:
    recs = [_rec("forms", "findings", 1) for _ in range(12)]
    h = aggregate_engine_health(recs)["forms"]
    assert not h.is_unhealthy


def test_skips_excluded_from_runs() -> None:
    recs = [_rec("wade", "skipped"), _rec("wade", "findings", 2)]
    h = aggregate_engine_health(recs)["wade"]
    assert h.skips == 1
    assert h.runs == 1


def test_health_report_surfaces_unhealthy() -> None:
    recs = ([_rec("bad", "failed", error="x") for _ in range(8)]
            + [_rec("good", "findings", 1) for _ in range(8)])
    rep = health_report(recs)
    assert rep["engine_count"] == 2
    assert rep["unhealthy_count"] == 1
    assert any("bad" in n for n in rep["unhealthy_engines"])


# ---------------------------------------------------------------------------
# Performance metrics (Task 6)
# ---------------------------------------------------------------------------


def test_extract_performance_metrics() -> None:
    result = NS(
        duration_seconds=12.5, urls_crawled=8,
        engine_diagnostics=[
            NS(name="sensitive_paths", duration_ms=4200.0),
            NS(name="headers", duration_ms=120.0)],
        metadata={
            "crawl_duration_seconds": 3.2,
            "fetch_stats": {"total": 40, "retried": 2, "skipped": 1},
            "browser_pass": {"duration_ms": 5000.0,
                             "browser_pages_rendered": 5},
            "coverage_summary": {"third_party_domains_observed": 7,
                                 "api_endpoints_observed": 3},
        })
    m = extract_performance_metrics(result)
    assert m["total_scan_seconds"] == 12.5
    assert m["crawl_duration_seconds"] == 3.2
    assert m["pages_crawled"] == 8
    assert m["requests_made"] == 40
    assert m["requests_retried"] == 2
    assert m["browser_render_ms"] == 5000.0
    assert m["apis_observed"] == 3
    # Slowest engine first.
    assert m["slowest_engines"][0]["engine"] == "sensitive_paths"
    assert m["total_engine_ms"] == 4320.0


def test_performance_metrics_minimal_scan() -> None:
    result = NS(duration_seconds=1.0, urls_crawled=1,
                engine_diagnostics=[], metadata={})
    m = extract_performance_metrics(result)
    assert m["total_scan_seconds"] == 1.0
    assert m["slowest_engines"] == []
    assert m["total_engine_ms"] == 0.0
