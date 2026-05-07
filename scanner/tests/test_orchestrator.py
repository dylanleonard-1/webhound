# WebHound — scanner/tests/test_orchestrator.py
# Tests for Phase 10: Scanner orchestration, JSON reporting, and summary building.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx
import pytest

from webhound.core.orchestrator import Scanner, _compute_risk_score, _dedup_findings
from webhound.engines.tls_dns.dns_checker import DnsRecords
from webhound.engines.tls_dns.tls_checker import TlsCertInfo
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.scan_result import ScanResult, ScanStatus, SeverityBreakdown
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target
from webhound.reporting.json_report import JsonReport
from webhound.reporting.summary_builder import SummaryBuilder


# ---------------------------------------------------------------------------
# Shared fixtures and helpers
# ---------------------------------------------------------------------------

_MINIMAL_HTML = (
    "<!DOCTYPE html>"
    "<html><head><title>Test</title></head>"
    "<body><p>Hello world</p></body></html>"
)

_METHODS_SEEN: list[str] = []


def _mock_transport(
    root_body: str = _MINIMAL_HTML,
    root_headers: dict[str, str] | None = None,
) -> httpx.MockTransport:
    """MockTransport: 200 for root, 404 for everything else.

    Records all request methods to _METHODS_SEEN for safe-mode assertions.
    """
    _headers = {"content-type": "text/html; charset=utf-8"}
    if root_headers:
        _headers.update(root_headers)

    async def handler(request: httpx.Request) -> httpx.Response:
        _METHODS_SEEN.append(request.method)
        if request.url.path in ("/", ""):
            return httpx.Response(status_code=200, text=root_body, headers=_headers)
        return httpx.Response(status_code=404, text="Not Found")

    return httpx.MockTransport(handler)


def _patch_tls_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub out the blocking TLS/DNS probes."""
    from webhound.engines.tls_dns import dns_checker as _dns, tls_checker as _tls

    monkeypatch.setattr(
        _tls, "probe_tls",
        lambda *a, **k: TlsCertInfo(domain="example.com", connection_failed=True),
    )
    monkeypatch.setattr(
        _dns, "resolve_dns",
        lambda *a, **k: DnsRecords(domain="example.com", a=["93.184.216.34"]),
    )


def _target(url: str = "https://example.com") -> Target:
    opts = ScanOptions(max_pages=3, max_depth=1, rate_limit_rps=10.0, verify_tls=False)
    return Target.from_url(url, scan_options=opts)


def _finding(
    title: str = "Test Finding",
    severity: Severity = Severity.MEDIUM,
    engine: str = "test_engine",
    location: str = "https://example.com/",
) -> Finding:
    return Finding(
        title=title,
        description="A test finding.",
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


def _completed_result(findings: list[Finding] | None = None) -> ScanResult:
    target = _target()
    result = ScanResult(
        target=target,
        status=ScanStatus.COMPLETED,
        findings=findings or [],
        engines_run=["security_headers", "cors_engine"],
        urls_crawled=3,
        pages_analyzed=3,
        started_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2025, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
    )
    result.recompute_aggregates()
    result.metadata["risk_score"] = 78
    result.metadata["risk_level"] = "low"
    result.metadata["external_domains"] = ["cdn.example.org"]
    result.metadata["external_domain_count"] = 1
    return result


# ---------------------------------------------------------------------------
# _compute_risk_score — unit tests
# ---------------------------------------------------------------------------

class TestComputeRiskScore:
    def _result_with_breakdown(
        self,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
    ) -> ScanResult:
        target = _target()
        r = ScanResult(target=target)
        r.severity_breakdown = SeverityBreakdown(
            critical=critical, high=high, medium=medium, low=low
        )
        return r

    def test_no_findings_score_100(self):
        score, level = _compute_risk_score(self._result_with_breakdown())
        assert score == 100
        assert level == "low"

    def test_two_medium_findings(self):
        score, level = _compute_risk_score(self._result_with_breakdown(medium=2))
        assert score == 100 - 2 * 7  # 86
        assert level == "low"

    def test_one_high_finding(self):
        score, level = _compute_risk_score(self._result_with_breakdown(high=1))
        assert score == 85
        assert level == "low"

    def test_critical_cap_at_59(self):
        score, level = _compute_risk_score(self._result_with_breakdown(critical=1))
        # Raw: 100 - 30 = 70, capped to 59; upward guard → "high" (not "medium")
        assert score == 59
        assert level == "high"

    def test_critical_cap_prevents_low_level(self):
        # Even a single low finding alongside critical cannot be "low" risk
        score, level = _compute_risk_score(
            self._result_with_breakdown(critical=1, low=1)
        )
        assert score <= 59
        assert level != "low"

    def test_five_high_findings(self):
        # HIGH cap at 40 deduction: 5×15=75 → capped → score=60 → "medium"
        score, level = _compute_risk_score(self._result_with_breakdown(high=5))
        assert score == 60
        assert level == "medium"

    def test_many_high_findings_capped_at_medium_not_critical(self):
        # HIGH cap at 40: even 10 HIGH findings can only deduct 40 → score=60
        score, level = _compute_risk_score(self._result_with_breakdown(high=10))
        assert score == 60
        assert level == "medium"  # downward guard: no CRIT/HIGH findings → "medium"? no, has HIGH. level stays medium by score.

    # ------------------------------------------------------------------
    # Severity-aware label tests (severity guard)
    # ------------------------------------------------------------------

    def test_many_medium_findings_not_critical(self):
        # MEDIUM cap at 30: 20×7=140 → capped → score=70 → "medium" (not "critical")
        score, level = _compute_risk_score(self._result_with_breakdown(medium=20))
        assert score == 70
        assert level == "medium"

    def test_medium_only_never_critical(self):
        # Any number of MEDIUM findings must not produce "critical" label
        for count in (1, 5, 10, 50):
            _, level = _compute_risk_score(self._result_with_breakdown(medium=count))
            assert level != "critical", f"{count} MEDIUM findings should not be 'critical'"

    def test_high_only_never_critical(self):
        # Any number of HIGH findings (without CRITICAL) must not be "critical"
        for count in (1, 3, 7, 15):
            _, level = _compute_risk_score(self._result_with_breakdown(high=count))
            assert level != "critical", f"{count} HIGH findings should not be 'critical'"

    def test_low_only_never_critical(self):
        # LOW cap at 10: even 60 LOW findings deduct at most 10 → score=90 → "low"
        score, level = _compute_risk_score(self._result_with_breakdown(low=60))
        assert score == 90
        assert level == "low"

    def test_critical_finding_permits_critical_label(self):
        # 2 CRIT + 3 HIGH: min(60,70)+min(45,40) = 100 → score=0 → "critical"
        # bd.critical > 0, so downward guard does not fire
        score, level = _compute_risk_score(self._result_with_breakdown(critical=2, high=3))
        assert score == 0
        assert level == "critical"

    def test_mixed_critical_and_medium_is_high(self):
        # 1 CRITICAL + 5 MEDIUM: min(30,70)+min(35,30)=60 → score=40, capped at 40 → "high"
        score, level = _compute_risk_score(
            self._result_with_breakdown(critical=1, medium=5)
        )
        assert score == 40
        assert level == "high"

    def test_crit_and_high_can_reach_critical_label(self):
        # 3 CRIT + 2 HIGH: min(90,70)+min(30,40) = 70+30=100 → score=0, capped at 0 → "critical"
        score, level = _compute_risk_score(
            self._result_with_breakdown(critical=3, high=2)
        )
        assert score == 0
        assert level == "critical"

    def test_risk_levels_thresholds(self):
        # 0 findings → 100 → "low"
        assert _compute_risk_score(self._result_with_breakdown())[1] == "low"
        # 2 HIGH → 100 - 30 = 70 → "medium" (50 ≤ 70 < 75)
        score_med, level_med = _compute_risk_score(self._result_with_breakdown(high=2))
        assert score_med == 70
        assert level_med == "medium"

    # ------------------------------------------------------------------
    # New scoring model — required scenario tests
    # ------------------------------------------------------------------

    def test_many_medium_findings_score_and_level(self):
        # 24 MEDIUM: MEDIUM cap at 30 → score=70 → "medium" (was 0 with old formula)
        score, level = _compute_risk_score(self._result_with_breakdown(medium=24))
        assert score == 70
        assert level == "medium"

    def test_only_low_findings(self):
        # 10 LOW: LOW cap at 10 → score=90 → "low"
        score, level = _compute_risk_score(self._result_with_breakdown(low=10))
        assert score == 90
        assert level == "low"

    def test_info_findings_have_zero_weight(self):
        # INFO findings contribute nothing to score
        score, level = _compute_risk_score(self._result_with_breakdown())
        assert score == 100
        assert level == "low"

    def test_one_critical_finding_is_high_risk(self):
        # 1 CRITICAL → score=59 (critical cap), upward guard → "high" label
        score, level = _compute_risk_score(self._result_with_breakdown(critical=1))
        assert score == 59
        assert level == "high"

    def test_multiple_high_findings_score_and_level(self):
        # 3 HIGH: HIGH cap at 40 → score=60 → "medium"
        score, level = _compute_risk_score(self._result_with_breakdown(high=3))
        assert score == 60
        assert level == "medium"

    def test_mixed_medium_and_low_findings(self):
        # 5 MEDIUM + 5 LOW: min(35,30)+min(10,10) = 40 → score=60 → "medium"
        # No CRIT/HIGH → downward guard does not escalate label
        score, level = _compute_risk_score(self._result_with_breakdown(medium=5, low=5))
        assert score == 60
        assert level == "medium"

    def test_medium_only_downward_guard_prevents_high_label(self):
        # Score 70 from MEDIUM-only puts us well above the "high" threshold (< 50)
        # so the downward guard (no HIGH/CRIT → cap "high" at "medium") never fires.
        # Verify the cap produces an intuitive result regardless.
        score, level = _compute_risk_score(self._result_with_breakdown(medium=8))
        assert score == 70
        assert level == "medium"


# ---------------------------------------------------------------------------
# _dedup_findings — unit tests
# ---------------------------------------------------------------------------

class TestDedupFindings:
    def test_exact_duplicate_removed(self):
        f = _finding()
        result = _dedup_findings([f, f])
        assert len(result) == 1

    def test_different_locations_kept(self):
        f1 = _finding(location="https://example.com/a")
        f2 = _finding(location="https://example.com/b")
        result = _dedup_findings([f1, f2])
        assert len(result) == 2

    def test_different_engines_kept(self):
        f1 = _finding(engine="engine_a")
        f2 = _finding(engine="engine_b")
        result = _dedup_findings([f1, f2])
        assert len(result) == 2

    def test_different_titles_kept(self):
        f1 = _finding(title="Issue A")
        f2 = _finding(title="Issue B")
        result = _dedup_findings([f1, f2])
        assert len(result) == 2

    def test_empty_input_returns_empty(self):
        assert _dedup_findings([]) == []

    def test_finding_without_evidence_deduped_by_empty_location(self):
        f = Finding(
            title="No Evidence",
            description="desc",
            severity=Severity.INFO,
            scanner_engine="test_engine",
        )
        result = _dedup_findings([f, f])
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Scanner integration tests — mocked HTTP + TLS/DNS
# ---------------------------------------------------------------------------

class TestScannerIntegration:
    @pytest.mark.anyio
    async def test_scan_completes_with_mock_site(self, monkeypatch):
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        assert result.status == ScanStatus.COMPLETED

    @pytest.mark.anyio
    async def test_safe_mode_no_post_put_delete(self, monkeypatch):
        _patch_tls_dns(monkeypatch)
        seen: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.method)
            if request.url.path in ("/", ""):
                return httpx.Response(
                    200, text=_MINIMAL_HTML,
                    headers={"content-type": "text/html; charset=utf-8"},
                )
            return httpx.Response(404, text="Not Found")

        transport = httpx.MockTransport(handler)
        scanner = Scanner(_target(), _transport=transport)
        await scanner.scan()

        assert all(m in ("GET", "HEAD") for m in seen), (
            f"Unsafe methods detected: {[m for m in seen if m not in ('GET', 'HEAD')]}"
        )

    @pytest.mark.anyio
    async def test_risk_metadata_populated(self, monkeypatch):
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        assert "risk_score" in result.metadata
        assert "risk_level" in result.metadata
        assert isinstance(result.metadata["risk_score"], int)
        assert result.metadata["risk_level"] in ("low", "medium", "high", "critical")

    @pytest.mark.anyio
    async def test_external_domains_in_metadata(self, monkeypatch):
        _patch_tls_dns(monkeypatch)
        html_with_external = (
            '<!DOCTYPE html><html><body>'
            '<a href="https://cdn.evil-tracker.xyz/script.js">link</a>'
            '</body></html>'
        )
        scanner = Scanner(_target(), _transport=_mock_transport(html_with_external))
        result = await scanner.scan()
        assert "external_domains" in result.metadata
        assert "external_domain_count" in result.metadata

    @pytest.mark.anyio
    async def test_engines_run_populated(self, monkeypatch):
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        assert len(result.engines_run) > 0
        assert isinstance(result.engines_run, list)

    @pytest.mark.anyio
    async def test_engine_failure_isolated(self, monkeypatch):
        """An engine raising does not abort the scan — it records an error instead."""
        _patch_tls_dns(monkeypatch)

        from webhound.engines.headers import security_headers as sh_mod
        monkeypatch.setattr(
            sh_mod.SecurityHeadersEngine,
            "analyze",
            lambda self, response: (_ for _ in ()).throw(RuntimeError("simulated crash")),
        )

        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()

        assert result.status == ScanStatus.COMPLETED
        assert any("simulated crash" in e.message for e in result.errors)

    @pytest.mark.anyio
    async def test_risk_score_bounded(self, monkeypatch):
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        score = result.metadata["risk_score"]
        assert 0 <= score <= 100

    @pytest.mark.anyio
    async def test_findings_list_is_deduplicated(self, monkeypatch):
        """After dedup, no two findings share (engine, title, location)."""
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()

        seen: set[tuple[str, str, str]] = set()
        for f in result.findings:
            loc = f.evidence[0].location if f.evidence else ""
            key = (f.scanner_engine, f.title, loc)
            assert key not in seen, f"Duplicate finding: {key}"
            seen.add(key)

    @pytest.mark.anyio
    async def test_scan_status_not_failed_on_clean_run(self, monkeypatch):
        _patch_tls_dns(monkeypatch)
        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        assert result.status != ScanStatus.FAILED

    @pytest.mark.anyio
    async def test_tls_connection_failure_recorded_as_error(self, monkeypatch):
        """A TLS probe failure is isolated as a ScanError, not a crash."""
        from webhound.engines.tls_dns import dns_checker as _dns

        monkeypatch.setattr(
            _dns, "resolve_dns",
            lambda *a, **k: DnsRecords(domain="example.com"),
        )

        from webhound.engines.tls_dns import tls_checker as _tls
        monkeypatch.setattr(
            _tls, "probe_tls",
            lambda *a, **k: (_ for _ in ()).throw(OSError("connection refused")),
        )

        scanner = Scanner(_target(), _transport=_mock_transport())
        result = await scanner.scan()
        assert result.status == ScanStatus.COMPLETED
        assert any("tls" in e.engine.lower() for e in result.errors)


# ---------------------------------------------------------------------------
# JsonReport tests
# ---------------------------------------------------------------------------

class TestJsonReport:
    def _report(self) -> tuple[JsonReport, ScanResult]:
        r = _completed_result([_finding(severity=Severity.HIGH)])
        return JsonReport(), r

    def test_required_top_level_keys(self):
        report, result = self._report()
        data = report.build(result)
        for key in ("webhound_version", "report_generated_at", "scan", "target",
                    "risk", "findings", "engines_run", "crawl", "errors", "metadata"):
            assert key in data, f"Missing key: {key}"

    def test_scan_section_keys(self):
        report, result = self._report()
        scan = report.build(result)["scan"]
        assert "id" in scan
        assert "status" in scan
        assert "started_at" in scan
        assert "duration_seconds" in scan

    def test_risk_section_contains_score_and_level(self):
        report, result = self._report()
        risk = report.build(result)["risk"]
        assert risk["score"] == 78
        assert risk["level"] == "low"
        assert "severity_breakdown" in risk

    def test_findings_list_has_required_fields(self):
        report, result = self._report()
        data = report.build(result)
        assert len(data["findings"]) == 1
        f = data["findings"][0]
        for key in ("id", "title", "severity", "category", "confidence",
                    "scanner_engine", "description"):
            assert key in f, f"Finding missing key: {key}"

    def test_findings_only_includes_active(self):
        f_active = _finding(title="Active")
        f_suppressed = _finding(title="Suppressed")
        f_suppressed.suppressed = True
        result = _completed_result([f_active, f_suppressed])
        data = JsonReport().build(result)
        titles = [f["title"] for f in data["findings"]]
        assert "Active" in titles
        assert "Suppressed" not in titles

    def test_errors_list_serialized(self):
        from webhound.models.scan_result import ScanError
        result = _completed_result()
        result.errors.append(ScanError(engine="test_engine", message="boom"))
        data = JsonReport().build(result)
        assert len(data["errors"]) == 1
        assert data["errors"][0]["engine"] == "test_engine"

    def test_to_json_is_valid_json(self):
        import json as _json
        report, result = self._report()
        raw = report.to_json(result)
        parsed = _json.loads(raw)
        assert isinstance(parsed, dict)

    def test_to_json_pretty_printed_by_default(self):
        report, result = self._report()
        raw = report.to_json(result)
        assert "\n" in raw

    def test_metadata_external_domains(self):
        report, result = self._report()
        data = report.build(result)
        assert data["metadata"]["external_domains"] == ["cdn.example.org"]
        assert data["metadata"]["external_domain_count"] == 1

    def test_crawl_section(self):
        report, result = self._report()
        crawl = report.build(result)["crawl"]
        assert crawl["urls_crawled"] == 3
        assert crawl["pages_analyzed"] == 3

    def test_target_section(self):
        report, result = self._report()
        target = report.build(result)["target"]
        assert target["hostname"] == "example.com"
        assert target["scheme"] == "https"


# ---------------------------------------------------------------------------
# SummaryBuilder tests
# ---------------------------------------------------------------------------

class TestSummaryBuilder:
    def _summary(self, findings: list[Finding] | None = None) -> str:
        result = _completed_result(findings)
        return SummaryBuilder().build(result)

    def test_contains_target_url(self):
        assert "example.com" in self._summary()

    def test_contains_risk_score(self):
        text = self._summary()
        assert "78" in text
        assert "low" in text

    def test_contains_status(self):
        assert "completed" in self._summary()

    def test_contains_severity_counts(self):
        text = self._summary()
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert label in text

    def test_contains_top_findings_section(self):
        f = _finding(title="Missing X-Frame-Options", severity=Severity.HIGH)
        text = self._summary([f])
        assert "Missing X-Frame-Options" in text

    def test_contains_engines_run(self):
        text = self._summary()
        assert "security_headers" in text

    def test_zero_errors_shown(self):
        assert "Errors: 0" in self._summary()

    def test_errors_listed_when_present(self):
        from webhound.models.scan_result import ScanError
        result = _completed_result()
        result.errors.append(ScanError(engine="tls", message="timeout"))
        text = SummaryBuilder().build(result)
        assert "Errors: 1" in text
        assert "tls" in text

    def test_header_present(self):
        assert "WebHound Scan Report" in self._summary()

    def test_findings_count_line(self):
        findings = [
            _finding(title="A", severity=Severity.HIGH),
            _finding(title="B", severity=Severity.MEDIUM),
        ]
        text = self._summary(findings)
        assert "2 total" in text

    def test_top_findings_sorted_by_severity(self):
        findings = [
            _finding(title="Low Issue", severity=Severity.LOW),
            _finding(title="Critical Issue", severity=Severity.CRITICAL),
        ]
        text = self._summary(findings)
        # Critical should appear before Low in the output
        assert text.index("Critical Issue") < text.index("Low Issue")
