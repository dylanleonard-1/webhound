# WebHound — scanner/tests/test_engine_diagnostics.py
# Tests for Phase 11: Engine execution transparency and diagnostics.
#
# Covers: EngineTracker (unit), EngineStatus model, orchestrator integration,
# JSON report output, and summary report output.

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

from webhound.core.engine_tracker import EngineTracker, _ENGINE_CATEGORIES
from webhound.core.orchestrator import Scanner
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.engine_status import EngineRunStatus, EngineStatus
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory
from webhound.models.scan_result import ScanResult, ScanStatus
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target
from webhound.reporting.json_report import JsonReport
from webhound.reporting.summary_builder import SummaryBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2025, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
_LATER = datetime(2025, 6, 1, 10, 0, 1, tzinfo=timezone.utc)

_MINIMAL_HTML = (
    "<!DOCTYPE html><html><head><title>T</title></head><body>ok</body></html>"
)


def _finding(
    title: str = "Test",
    severity: Severity = Severity.HIGH,
    engine: str = "security_headers",
    location: str = "https://example.com/",
) -> Finding:
    return Finding(
        title=title,
        description="desc",
        severity=severity,
        category=FindingCategory.SECURITY_HEADER,
        scanner_engine=engine,
        evidence=[
            Evidence(
                evidence_type=EvidenceType.HEADER,
                content="missing",
                location=location,
                source_engine=engine,
            )
        ],
    )


def _target(url: str = "https://example.com") -> Target:
    opts = ScanOptions(max_pages=3, max_depth=1, rate_limit_rps=10.0, verify_tls=False)
    return Target.from_url(url, scan_options=opts)


def _mock_transport(body: str = _MINIMAL_HTML) -> httpx.MockTransport:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            return httpx.Response(
                status_code=200,
                text=body,
                headers={"content-type": "text/html; charset=utf-8"},
            )
        return httpx.Response(status_code=404, text="Not Found")

    return httpx.MockTransport(handler)


def _patch_tls_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    from webhound.engines.tls_dns import dns_checker as _dns, tls_checker as _tls

    monkeypatch.setattr(
        _tls, "probe_tls",
        lambda *a, **k: TlsCertInfo(domain="example.com", connection_failed=True),
    )
    monkeypatch.setattr(
        _dns, "resolve_dns",
        lambda *a, **k: DnsRecords(domain="example.com", a=["93.184.216.34"]),
    )


def _make_completed_result_with_diagnostics() -> ScanResult:
    """Convenience: a ScanResult with representative engine_diagnostics."""
    tracker = EngineTracker()
    f_high = _finding(severity=Severity.HIGH, engine="security_headers")
    tracker.record_run("security_headers", [f_high], 12.5, _NOW, _LATER)
    tracker.record_run("cors", [], 3.0, _NOW, _LATER)
    tracker.record_skip("js_analyzer", "no JavaScript on page")
    tracker.record_error("form_risk", "TimeoutError: timed out", 5.0, _NOW, _LATER)

    target = _target()
    result = ScanResult(
        target=target,
        status=ScanStatus.COMPLETED,
        findings=[f_high],
        engines_run=["security_headers", "cors"],
        urls_crawled=1,
        pages_analyzed=1,
        started_at=_NOW,
        completed_at=_LATER,
    )
    result.recompute_aggregates()
    result.metadata["risk_score"] = 85
    result.metadata["risk_level"] = "low"
    result.metadata["external_domains"] = []
    result.metadata["external_domain_count"] = 0
    result.engine_diagnostics = tracker.build_statuses()
    return result


# ---------------------------------------------------------------------------
# EngineTracker — unit tests
# ---------------------------------------------------------------------------


class TestEngineTrackerRecordRun:
    def test_passed_status_zero_findings(self) -> None:
        tracker = EngineTracker()
        tracker.record_run("cors", [], 10.0, _NOW, _LATER)
        statuses = tracker.build_statuses()
        assert len(statuses) == 1
        s = statuses[0]
        assert s.name == "cors"
        assert s.status == EngineRunStatus.PASSED
        assert s.findings_count == 0
        assert s.duration_ms == 10.0

    def test_findings_status_with_findings(self) -> None:
        tracker = EngineTracker()
        f = _finding(severity=Severity.CRITICAL, engine="security_headers")
        tracker.record_run("security_headers", [f], 20.0, _NOW, _LATER)
        statuses = tracker.build_statuses()
        s = statuses[0]
        assert s.status == EngineRunStatus.FINDINGS
        assert s.findings_count == 1
        assert s.severity_counts["critical"] == 1
        assert s.severity_counts["high"] == 0

    def test_severity_counts_aggregated_correctly(self) -> None:
        tracker = EngineTracker()
        f1 = _finding(severity=Severity.HIGH, engine="security_headers")
        f2 = _finding(severity=Severity.MEDIUM, engine="security_headers")
        f3 = _finding(severity=Severity.MEDIUM, engine="security_headers")
        tracker.record_run("security_headers", [f1, f2, f3], 15.0, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.findings_count == 3
        assert s.severity_counts["high"] == 1
        assert s.severity_counts["medium"] == 2

    def test_duration_accumulates_across_pages(self) -> None:
        tracker = EngineTracker()
        tracker.record_run("technology", [], 5.0, _NOW, _LATER)
        tracker.record_run("technology", [], 7.5, _NOW, _LATER)
        tracker.record_run("technology", [], 2.5, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.duration_ms == pytest.approx(15.0)

    def test_findings_accumulate_across_pages(self) -> None:
        tracker = EngineTracker()
        f1 = _finding(engine="technology")
        f2 = _finding(engine="technology")
        tracker.record_run("technology", [f1], 5.0, _NOW, _LATER)
        tracker.record_run("technology", [f2], 5.0, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.findings_count == 2
        assert s.status == EngineRunStatus.FINDINGS

    def test_started_at_is_first_page(self) -> None:
        first = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        second = datetime(2025, 1, 1, 10, 0, 5, tzinfo=timezone.utc)
        tracker = EngineTracker()
        tracker.record_run("cors", [], 1.0, first, second)
        tracker.record_run("cors", [], 1.0, second, second)
        s = tracker.build_statuses()[0]
        assert s.started_at == first

    def test_finished_at_is_last_page(self) -> None:
        t1 = datetime(2025, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2025, 1, 1, 10, 0, 3, tzinfo=timezone.utc)
        t3 = datetime(2025, 1, 1, 10, 0, 6, tzinfo=timezone.utc)
        tracker = EngineTracker()
        tracker.record_run("cors", [], 1.0, t1, t2)
        tracker.record_run("cors", [], 1.0, t2, t3)
        s = tracker.build_statuses()[0]
        assert s.finished_at == t3

    def test_category_resolved_from_map(self) -> None:
        tracker = EngineTracker()
        tracker.record_run("tls_checker", [], 5.0, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.category == "tls_dns"

    def test_unknown_engine_category_is_unknown(self) -> None:
        tracker = EngineTracker()
        tracker.record_run("mystery_engine", [], 1.0, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.category == "unknown"

    def test_is_passive_default_true(self) -> None:
        tracker = EngineTracker()
        tracker.record_run("form_risk", [], 1.0, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.is_passive is True


class TestEngineTrackerRecordError:
    def test_failed_status(self) -> None:
        tracker = EngineTracker()
        tracker.record_error("form_risk", "TimeoutError: timed out", 5.0, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.status == EngineRunStatus.FAILED
        assert s.error_message == "TimeoutError: timed out"
        assert s.name == "form_risk"

    def test_duration_included_on_error(self) -> None:
        tracker = EngineTracker()
        tracker.record_error("cors", "err", 12.3, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.duration_ms == pytest.approx(12.3)

    def test_failed_overrides_passed(self) -> None:
        # An engine that ran once (passed) then errored on a later page
        tracker = EngineTracker()
        tracker.record_run("cors", [], 5.0, _NOW, _LATER)
        tracker.record_error("cors", "crash", 2.0, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.status == EngineRunStatus.FAILED

    def test_first_error_message_preserved(self) -> None:
        tracker = EngineTracker()
        tracker.record_error("cors", "first error", 1.0, _NOW, _LATER)
        tracker.record_error("cors", "second error", 1.0, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.error_message == "first error"


class TestEngineTrackerRecordSkip:
    def test_skipped_status(self) -> None:
        tracker = EngineTracker()
        tracker.record_skip("js_analyzer", "no JavaScript found")
        s = tracker.build_statuses()[0]
        assert s.status == EngineRunStatus.SKIPPED
        assert s.skipped_reason == "no JavaScript found"
        assert s.findings_count == 0

    def test_skipped_reason_preserved(self) -> None:
        reason = "API key not configured"
        tracker = EngineTracker()
        tracker.record_skip("threat_intel", reason)
        s = tracker.build_statuses()[0]
        assert s.skipped_reason == reason


class TestEngineTrackerBuildStatuses:
    def test_multiple_engines_produce_one_record_each(self) -> None:
        tracker = EngineTracker()
        tracker.record_run("cors", [], 5.0, _NOW, _LATER)
        tracker.record_run("security_headers", [], 8.0, _NOW, _LATER)
        tracker.record_skip("js_analyzer", "no JS")
        tracker.record_error("form_risk", "oops", 1.0, _NOW, _LATER)
        statuses = tracker.build_statuses()
        assert len(statuses) == 4
        names = {s.name for s in statuses}
        assert names == {"cors", "security_headers", "js_analyzer", "form_risk"}

    def test_empty_tracker_returns_empty_list(self) -> None:
        tracker = EngineTracker()
        assert tracker.build_statuses() == []


# ---------------------------------------------------------------------------
# EngineStatus model — unit tests
# ---------------------------------------------------------------------------


class TestEngineStatusModel:
    def test_is_healthy_for_passed(self) -> None:
        s = EngineStatus(name="cors", category="headers", status=EngineRunStatus.PASSED)
        assert s.is_healthy is True

    def test_is_healthy_for_findings(self) -> None:
        s = EngineStatus(name="cors", category="headers", status=EngineRunStatus.FINDINGS)
        assert s.is_healthy is True

    def test_is_healthy_for_skipped(self) -> None:
        s = EngineStatus(name="cors", category="headers", status=EngineRunStatus.SKIPPED)
        assert s.is_healthy is True

    def test_is_healthy_false_for_failed(self) -> None:
        s = EngineStatus(name="cors", category="headers", status=EngineRunStatus.FAILED)
        assert s.is_healthy is False

    def test_ran_true_for_passed_and_findings(self) -> None:
        for st in (EngineRunStatus.PASSED, EngineRunStatus.FINDINGS):
            s = EngineStatus(name="cors", category="headers", status=st)
            assert s.ran is True

    def test_ran_false_for_skipped_and_failed(self) -> None:
        for st in (EngineRunStatus.SKIPPED, EngineRunStatus.FAILED):
            s = EngineStatus(name="cors", category="headers", status=st)
            assert s.ran is False

    def test_default_severity_counts_all_zero(self) -> None:
        s = EngineStatus(name="cors", category="headers", status=EngineRunStatus.PASSED)
        for k in ("critical", "high", "medium", "low", "info"):
            assert s.severity_counts[k] == 0


# ---------------------------------------------------------------------------
# Duration tracking — wall-clock accuracy
# ---------------------------------------------------------------------------


class TestDurationTracking:
    def test_duration_positive_for_real_call(self) -> None:
        tracker = EngineTracker()
        t0 = time.perf_counter()
        started = datetime.now(timezone.utc)
        time.sleep(0.01)
        dur = (time.perf_counter() - t0) * 1000
        finished = datetime.now(timezone.utc)
        tracker.record_run("cors", [], dur, started, finished)
        s = tracker.build_statuses()[0]
        assert s.duration_ms >= 5.0  # at least 5 ms even under load

    def test_duration_zero_acceptable_for_fast_engine(self) -> None:
        tracker = EngineTracker()
        tracker.record_run("cors", [], 0.0, _NOW, _LATER)
        s = tracker.build_statuses()[0]
        assert s.duration_ms == 0.0


# ---------------------------------------------------------------------------
# Integration: Scanner produces engine_diagnostics
# ---------------------------------------------------------------------------


@pytest.mark.anyio
class TestScannerEngineDiagnosticsIntegration:
    async def test_engine_diagnostics_populated_after_scan(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        target = _target()
        scanner = Scanner(target, _transport=_mock_transport())
        result = await scanner.scan()

        assert result.engine_diagnostics, "engine_diagnostics should not be empty"
        names = {d.name for d in result.engine_diagnostics}
        # Core engines that always run on a page
        for expected in ("security_headers", "cors", "cookie_scanner"):
            assert expected in names, f"{expected} missing from diagnostics"

    async def test_all_diagnostics_have_valid_status(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        target = _target()
        scanner = Scanner(target, _transport=_mock_transport())
        result = await scanner.scan()

        valid = set(EngineRunStatus)
        for d in result.engine_diagnostics:
            assert d.status in valid, f"{d.name} has invalid status {d.status!r}"

    async def test_engine_diagnostics_duration_non_negative(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        target = _target()
        scanner = Scanner(target, _transport=_mock_transport())
        result = await scanner.scan()

        for d in result.engine_diagnostics:
            assert d.duration_ms >= 0.0, f"{d.name} has negative duration"

    async def test_failed_engine_appears_in_diagnostics(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        from webhound.engines.headers.security_headers import SecurityHeadersEngine

        monkeypatch.setattr(
            SecurityHeadersEngine,
            "analyze",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        )

        target = _target()
        scanner = Scanner(target, _transport=_mock_transport())
        result = await scanner.scan()

        diag = {d.name: d for d in result.engine_diagnostics}
        assert "security_headers" in diag
        assert diag["security_headers"].status == EngineRunStatus.FAILED
        assert "RuntimeError" in (diag["security_headers"].error_message or "")

    async def test_js_collector_appears_in_diagnostics(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_tls_dns(monkeypatch)
        target = _target()
        scanner = Scanner(target, _transport=_mock_transport())
        result = await scanner.scan()

        names = {d.name for d in result.engine_diagnostics}
        assert "js_collector" in names

    async def test_tls_error_appears_in_diagnostics(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from webhound.engines.tls_dns import dns_checker as _dns, tls_checker as _tls

        monkeypatch.setattr(_dns, "resolve_dns",
                            lambda *a, **k: DnsRecords(domain="x.com", a=[]))
        monkeypatch.setattr(
            _tls, "probe_tls", lambda *a, **k: (_ for _ in ()).throw(OSError("refused"))
        )

        target = _target()
        scanner = Scanner(target, _transport=_mock_transport())
        result = await scanner.scan()

        diag = {d.name: d for d in result.engine_diagnostics}
        assert "tls_checker" in diag
        assert diag["tls_checker"].status == EngineRunStatus.FAILED

    async def test_dns_error_appears_in_diagnostics(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from webhound.engines.tls_dns import dns_checker as _dns, tls_checker as _tls

        monkeypatch.setattr(
            _tls, "probe_tls",
            lambda *a, **k: TlsCertInfo(domain="x.com", connection_failed=True),
        )
        monkeypatch.setattr(
            _dns, "resolve_dns", lambda *a, **k: (_ for _ in ()).throw(OSError("refused"))
        )

        target = _target()
        scanner = Scanner(target, _transport=_mock_transport())
        result = await scanner.scan()

        diag = {d.name: d for d in result.engine_diagnostics}
        assert "dns_checker" in diag
        assert diag["dns_checker"].status == EngineRunStatus.FAILED


# ---------------------------------------------------------------------------
# JSON report output
# ---------------------------------------------------------------------------


class TestJsonReportEngineDiagnostics:
    def test_engine_diagnostics_key_present(self) -> None:
        result = _make_completed_result_with_diagnostics()
        data = JsonReport().build(result)
        assert "engine_diagnostics" in data

    def test_engine_diagnostics_is_list(self) -> None:
        result = _make_completed_result_with_diagnostics()
        data = JsonReport().build(result)
        assert isinstance(data["engine_diagnostics"], list)

    def test_engine_diagnostics_length_matches(self) -> None:
        result = _make_completed_result_with_diagnostics()
        data = JsonReport().build(result)
        assert len(data["engine_diagnostics"]) == len(result.engine_diagnostics)

    def test_engine_diagnostic_entry_structure(self) -> None:
        result = _make_completed_result_with_diagnostics()
        data = JsonReport().build(result)
        expected_keys = {
            "name", "category", "status", "findings_count", "severity_counts",
            "skipped_reason", "error_message", "duration_ms", "affected_target",
            "is_passive", "started_at", "finished_at",
        }
        for entry in data["engine_diagnostics"]:
            assert expected_keys == set(entry.keys())

    def test_passed_engine_status_string(self) -> None:
        result = _make_completed_result_with_diagnostics()
        data = JsonReport().build(result)
        by_name = {e["name"]: e for e in data["engine_diagnostics"]}
        assert by_name["cors"]["status"] == "passed"

    def test_findings_engine_status_string(self) -> None:
        result = _make_completed_result_with_diagnostics()
        data = JsonReport().build(result)
        by_name = {e["name"]: e for e in data["engine_diagnostics"]}
        assert by_name["security_headers"]["status"] == "findings"
        assert by_name["security_headers"]["findings_count"] == 1

    def test_skipped_engine_status_and_reason(self) -> None:
        result = _make_completed_result_with_diagnostics()
        data = JsonReport().build(result)
        by_name = {e["name"]: e for e in data["engine_diagnostics"]}
        assert by_name["js_analyzer"]["status"] == "skipped"
        assert by_name["js_analyzer"]["skipped_reason"] == "no JavaScript on page"

    def test_failed_engine_status_and_message(self) -> None:
        result = _make_completed_result_with_diagnostics()
        data = JsonReport().build(result)
        by_name = {e["name"]: e for e in data["engine_diagnostics"]}
        assert by_name["form_risk"]["status"] == "failed"
        assert "TimeoutError" in by_name["form_risk"]["error_message"]

    def test_duration_ms_in_output(self) -> None:
        result = _make_completed_result_with_diagnostics()
        data = JsonReport().build(result)
        by_name = {e["name"]: e for e in data["engine_diagnostics"]}
        assert by_name["security_headers"]["duration_ms"] == pytest.approx(12.5)

    def test_empty_diagnostics_returns_empty_list(self) -> None:
        target = _target()
        result = ScanResult(
            target=target,
            status=ScanStatus.COMPLETED,
            started_at=_NOW,
            completed_at=_LATER,
        )
        result.metadata["risk_score"] = 100
        result.metadata["risk_level"] = "low"
        result.metadata["external_domains"] = []
        result.metadata["external_domain_count"] = 0
        data = JsonReport().build(result)
        assert data["engine_diagnostics"] == []


# ---------------------------------------------------------------------------
# Summary report output
# ---------------------------------------------------------------------------


class TestSummaryBuilderEngineDiagnostics:
    def test_engine_diagnostics_header_present(self) -> None:
        result = _make_completed_result_with_diagnostics()
        summary = SummaryBuilder().build(result)
        assert "Engine Diagnostics" in summary

    def test_engine_names_appear_in_table(self) -> None:
        result = _make_completed_result_with_diagnostics()
        summary = SummaryBuilder().build(result)
        for name in ("security_headers", "cors", "js_analyzer", "form_risk"):
            assert name in summary

    def test_status_badges_appear(self) -> None:
        result = _make_completed_result_with_diagnostics()
        summary = SummaryBuilder().build(result)
        assert "PASSED" in summary
        assert "FINDINGS" in summary
        assert "SKIPPED" in summary
        assert "FAILED" in summary

    def test_fallback_to_engines_run_when_no_diagnostics(self) -> None:
        target = _target()
        result = ScanResult(
            target=target,
            status=ScanStatus.COMPLETED,
            engines_run=["cors", "security_headers"],
            started_at=_NOW,
            completed_at=_LATER,
        )
        result.recompute_aggregates()
        result.metadata["risk_score"] = 100
        result.metadata["risk_level"] = "low"
        result.metadata["external_domains"] = []
        result.metadata["external_domain_count"] = 0
        summary = SummaryBuilder().build(result)
        assert "Engines" in summary
        assert "cors" in summary

    def test_no_diagnostics_section_when_both_empty(self) -> None:
        target = _target()
        result = ScanResult(
            target=target,
            status=ScanStatus.COMPLETED,
            started_at=_NOW,
            completed_at=_LATER,
        )
        result.recompute_aggregates()
        result.metadata["risk_score"] = 100
        result.metadata["risk_level"] = "low"
        result.metadata["external_domains"] = []
        result.metadata["external_domain_count"] = 0
        summary = SummaryBuilder().build(result)
        assert "Engine Diagnostics" not in summary
        assert "Engines" not in summary

    def test_table_has_column_headers(self) -> None:
        result = _make_completed_result_with_diagnostics()
        summary = SummaryBuilder().build(result)
        assert "Engine" in summary
        assert "Category" in summary
        assert "Status" in summary
        assert "Findings" in summary


# ---------------------------------------------------------------------------
# _ENGINE_CATEGORIES completeness
# ---------------------------------------------------------------------------


class TestEngineCategoriesMap:
    _KNOWN_ENGINES = {
        "security_headers", "cors", "cookie_scanner",
        "tls_checker", "dns_checker",
        "js_collector", "js_analyzer", "obfuscation_detector", "third_party_domains",
        "technology",
        "sensitive_paths", "robots_sitemap",
        "form_risk", "input_analysis",
        "injected_js", "hidden_iframes", "seo_spam", "suspicious_redirects",
        "wade",
    }

    def test_all_19_engines_in_map(self) -> None:
        assert self._KNOWN_ENGINES == set(_ENGINE_CATEGORIES.keys())

    def test_no_engine_has_empty_category(self) -> None:
        for name, cat in _ENGINE_CATEGORIES.items():
            assert cat, f"Engine '{name}' has empty category"
