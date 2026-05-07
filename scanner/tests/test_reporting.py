# WebHound — scanner/tests/test_reporting.py
# Tests for Phase 16: CLI output formatting and report polish.
#
# Covers: cli_formatter helpers, SummaryBuilder improvements (banner, risk
# description, recommended actions, error suppression), JsonReport schema
# additions (report_schema_version, scanner_version, profile, baseline,
# report_metadata), grouped/WADE display, and diagnostics formatting.

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from webhound.models.engine_status import EngineRunStatus, EngineStatus
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult, ScanStatus, SeverityBreakdown
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target
from webhound.reporting.cli_formatter import (
    bold_divider,
    col,
    divider,
    fmt_duration,
    fmt_risk,
    fmt_risk_description,
    fmt_severity,
    fmt_url,
    thin_divider,
)
from webhound.reporting.json_report import JsonReport, _REPORT_SCHEMA_VERSION
from webhound.reporting.summary_builder import SummaryBuilder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _target(url: str = "https://example.com") -> Target:
    opts = ScanOptions(max_pages=3, max_depth=1, rate_limit_rps=10.0, verify_tls=False)
    return Target.from_url(url, scan_options=opts)


def _finding(
    title: str = "Missing CSP",
    severity: Severity = Severity.MEDIUM,
    engine: str = "security_headers",
    category: FindingCategory = FindingCategory.SECURITY_HEADER,
    location: str = "https://example.com/",
    remediation: str | None = "Add Content-Security-Policy header.",
) -> Finding:
    return Finding(
        title=title,
        description=f"{title} detected.",
        severity=severity,
        category=category,
        scanner_engine=engine,
        remediation=remediation,
        framework=FrameworkAlignment(owasp_top10=["A05:2021"]),
        evidence=[
            Evidence(
                evidence_type=EvidenceType.HEADER,
                content="missing",
                location=location,
                source_engine=engine,
            )
        ],
    )


def _grouped(
    title: str = "Missing CSP",
    severity: Severity = Severity.MEDIUM,
    category: FindingCategory = FindingCategory.SECURITY_HEADER,
    affected_url_count: int = 1,
    remediation: str | None = "Add Content-Security-Policy header.",
) -> GroupedFinding:
    return GroupedFinding(
        title=title,
        severity=severity,
        category=category,
        scanner_engine="security_headers",
        description=f"{title} detected.",
        remediation=remediation,
        affected_url_count=affected_url_count,
        affected_urls=[f"https://example.com/p{i}" for i in range(min(affected_url_count, 3))],
        evidence_count=affected_url_count,
        framework=FrameworkAlignment(owasp_top10=["A05:2021"]),
    )


def _completed_result(
    findings: list[Finding] | None = None,
    grouped: list[GroupedFinding] | None = None,
) -> ScanResult:
    f = findings or []
    result = ScanResult(
        target=_target(),
        status=ScanStatus.COMPLETED,
        findings=f,
        engines_run=["security_headers"],
        urls_crawled=3,
        pages_analyzed=3,
        started_at=datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2025, 1, 1, 12, 0, 5, tzinfo=timezone.utc),
    )
    result.recompute_aggregates()
    result.metadata["risk_score"] = 80
    result.metadata["risk_level"] = "low"
    result.metadata["external_domains"] = []
    result.metadata["external_domain_count"] = 0
    if grouped is not None:
        result.grouped_findings = grouped
    return result


# ---------------------------------------------------------------------------
# cli_formatter — fmt_severity
# ---------------------------------------------------------------------------


class TestFmtSeverity:
    def test_critical_label(self) -> None:
        s = fmt_severity("critical")
        assert "CRITICAL" in s

    def test_bracketed(self) -> None:
        s = fmt_severity("high")
        assert s.startswith("[")
        assert s.endswith("]")

    def test_consistent_width(self) -> None:
        widths = {len(fmt_severity(sev)) for sev in ("critical", "high", "medium", "low", "info")}
        assert len(widths) == 1

    def test_upper_cased(self) -> None:
        assert fmt_severity("medium") == fmt_severity("MEDIUM")


# ---------------------------------------------------------------------------
# cli_formatter — fmt_risk
# ---------------------------------------------------------------------------


class TestFmtRisk:
    def test_contains_score(self) -> None:
        assert "93" in fmt_risk(93, "low")

    def test_contains_max(self) -> None:
        assert "100" in fmt_risk(93, "low")

    def test_low_risk_label(self) -> None:
        assert "Low Risk" in fmt_risk(93, "low")

    def test_critical_risk_label(self) -> None:
        assert "Critical Risk" in fmt_risk(10, "critical")

    def test_high_risk_label(self) -> None:
        assert "High Risk" in fmt_risk(30, "high")

    def test_medium_risk_label(self) -> None:
        assert "Medium Risk" in fmt_risk(60, "medium")


# ---------------------------------------------------------------------------
# cli_formatter — fmt_risk_description
# ---------------------------------------------------------------------------


class TestFmtRiskDescription:
    def test_low_returns_string(self) -> None:
        assert isinstance(fmt_risk_description("low"), str)

    def test_each_level_has_description(self) -> None:
        for level in ("low", "medium", "high", "critical"):
            desc = fmt_risk_description(level)
            assert desc, f"Empty description for {level}"

    def test_unknown_level_returns_string(self) -> None:
        assert isinstance(fmt_risk_description("unknown_level"), str)


# ---------------------------------------------------------------------------
# cli_formatter — fmt_url
# ---------------------------------------------------------------------------


class TestFmtUrl:
    def test_short_url_unchanged(self) -> None:
        url = "https://example.com"
        assert fmt_url(url, max_len=100) == url

    def test_long_url_truncated(self) -> None:
        url = "https://example.com/" + "a" * 100
        result = fmt_url(url, max_len=50)
        assert len(result) == 50

    def test_truncated_ends_with_ellipsis(self) -> None:
        url = "https://example.com/" + "a" * 100
        result = fmt_url(url, max_len=50)
        assert result.endswith("…")

    def test_exact_length_url_unchanged(self) -> None:
        url = "a" * 50
        assert fmt_url(url, max_len=50) == url


# ---------------------------------------------------------------------------
# cli_formatter — fmt_duration
# ---------------------------------------------------------------------------


class TestFmtDuration:
    def test_seconds_below_60(self) -> None:
        assert fmt_duration(4.2) == "4.2s"

    def test_exactly_60_seconds(self) -> None:
        result = fmt_duration(60.0)
        assert "m" in result

    def test_minutes_format(self) -> None:
        result = fmt_duration(90.0)
        assert "1m" in result

    def test_zero_seconds(self) -> None:
        assert "0.0s" in fmt_duration(0.0)


# ---------------------------------------------------------------------------
# cli_formatter — dividers and col
# ---------------------------------------------------------------------------


class TestDividers:
    def test_divider_default_width(self) -> None:
        assert len(divider()) == 60

    def test_divider_custom_width(self) -> None:
        assert len(divider(width=44)) == 44

    def test_bold_divider_uses_equals(self) -> None:
        assert bold_divider(10) == "══════════"

    def test_thin_divider_uses_dash(self) -> None:
        assert thin_divider(10) == "──────────"


class TestCol:
    def test_left_pads_to_width(self) -> None:
        assert col("hi", 10) == "hi        "

    def test_right_pads_to_width(self) -> None:
        assert col("hi", 10, align="right") == "        hi"

    def test_truncates_long_text(self) -> None:
        result = col("hello world", 5)
        assert len(result) == 5


# ---------------------------------------------------------------------------
# SummaryBuilder — banner and header
# ---------------------------------------------------------------------------


class TestSummaryBuilderHeader:
    def test_webhound_scan_report_present(self) -> None:
        result = _completed_result()
        summary = SummaryBuilder().build(result)
        assert "WebHound Scan Report" in summary

    def test_target_url_present(self) -> None:
        result = _completed_result()
        summary = SummaryBuilder().build(result)
        assert "example.com" in summary

    def test_risk_score_present(self) -> None:
        result = _completed_result()
        summary = SummaryBuilder().build(result)
        assert "80" in summary

    def test_risk_level_present(self) -> None:
        result = _completed_result()
        summary = SummaryBuilder().build(result)
        assert "low" in summary

    def test_duration_present(self) -> None:
        result = _completed_result()
        summary = SummaryBuilder().build(result)
        assert "5.0s" in summary

    def test_pages_crawled_present(self) -> None:
        result = _completed_result()
        summary = SummaryBuilder().build(result)
        assert "crawled" in summary

    def test_grouped_count_shown_when_present(self) -> None:
        result = _completed_result(grouped=[_grouped()])
        summary = SummaryBuilder().build(result)
        assert "unique findings grouped" in summary

    def test_bold_divider_in_output(self) -> None:
        result = _completed_result()
        summary = SummaryBuilder().build(result)
        assert "═" in summary

    def test_risk_description_present(self) -> None:
        result = _completed_result()
        summary = SummaryBuilder().build(result)
        # Risk description should be a non-empty sentence
        assert any(
            phrase in summary
            for phrase in ("No critical", "Actionable", "Significant", "Critical vulnerabilities")
        )


# ---------------------------------------------------------------------------
# SummaryBuilder — findings breakdown (existing assertions preserved)
# ---------------------------------------------------------------------------


class TestSummaryBuilderFindings:
    def test_findings_total_shown(self) -> None:
        findings = [_finding(), _finding(title="B", remediation="Fix B")]
        result = _completed_result(findings)
        summary = SummaryBuilder().build(result)
        assert "2 total" in summary

    def test_severity_breakdown_shown(self) -> None:
        result = _completed_result([_finding(severity=Severity.HIGH, remediation="Fix H")])
        summary = SummaryBuilder().build(result)
        assert "HIGH" in summary

    def test_top_findings_section_present(self) -> None:
        result = _completed_result([_finding()])
        result.grouped_findings = []
        summary = SummaryBuilder().build(result)
        assert "Top Findings:" in summary

    def test_finding_title_in_summary(self) -> None:
        result = _completed_result([_finding(title="Missing X-Frame-Options", remediation="Fix")])
        summary = SummaryBuilder().build(result)
        assert "Missing X-Frame-Options" in summary


# ---------------------------------------------------------------------------
# SummaryBuilder — recommended actions section
# ---------------------------------------------------------------------------


class TestSummaryBuilderRecommendedActions:
    def test_recommended_actions_present_for_actionable(self) -> None:
        g = _grouped(severity=Severity.HIGH, remediation="Add X-Frame-Options header.")
        result = _completed_result(grouped=[g])
        summary = SummaryBuilder().build(result)
        assert "Recommended Actions:" in summary

    def test_remediation_text_shown(self) -> None:
        g = _grouped(severity=Severity.HIGH, remediation="Add X-Frame-Options header.")
        result = _completed_result(grouped=[g])
        summary = SummaryBuilder().build(result)
        assert "Add X-Frame-Options header." in summary

    def test_no_actions_for_info_findings(self) -> None:
        g = _grouped(severity=Severity.INFO, remediation="Consider adding X-Frame-Options.")
        result = _completed_result(grouped=[g])
        summary = SummaryBuilder().build(result)
        assert "Recommended Actions:" not in summary

    def test_no_actions_for_findings_without_remediation(self) -> None:
        g = _grouped(severity=Severity.HIGH, remediation=None)
        result = _completed_result(grouped=[g])
        summary = SummaryBuilder().build(result)
        assert "Recommended Actions:" not in summary

    def test_compromise_findings_excluded_from_actions(self) -> None:
        g = _grouped(
            title="Injected JS Detected",
            severity=Severity.HIGH,
            category=FindingCategory.COMPROMISE,
            remediation="Investigate source.",
        )
        result = _completed_result(grouped=[g])
        summary = SummaryBuilder().build(result)
        # The title may appear in Top Findings, but not in Recommended Actions
        assert "Recommended Actions:" not in summary

    def test_recon_findings_excluded_from_actions(self) -> None:
        g = _grouped(
            title="Exposed .env",
            severity=Severity.HIGH,
            category=FindingCategory.RECON,
            remediation="Block access.",
        )
        result = _completed_result(grouped=[g])
        summary = SummaryBuilder().build(result)
        assert "Recommended Actions:" not in summary

    def test_capped_at_five_recommendations(self) -> None:
        groups = [
            _grouped(title=f"Issue {i}", remediation=f"Fix {i}")
            for i in range(10)
        ]
        result = _completed_result(grouped=groups)
        summary = SummaryBuilder().build(result)
        # Count "Fix N" lines — should be at most 5
        fix_count = sum(1 for line in summary.splitlines() if line.strip().startswith("→ Fix"))
        assert fix_count <= 5


# ---------------------------------------------------------------------------
# SummaryBuilder — errors section
# ---------------------------------------------------------------------------


class TestSummaryBuilderErrors:
    def test_zero_errors_shown(self) -> None:
        result = _completed_result()
        summary = SummaryBuilder().build(result)
        assert "Errors: 0" in summary

    def test_error_count_shown_when_present(self) -> None:
        from webhound.models.scan_result import ScanError
        result = _completed_result()
        result.errors.append(ScanError(engine="tls", message="timeout"))
        summary = SummaryBuilder().build(result)
        assert "Errors: 1" in summary
        assert "tls" in summary

    def test_closing_divider_present(self) -> None:
        result = _completed_result()
        summary = SummaryBuilder().build(result)
        assert "─" in summary


# ---------------------------------------------------------------------------
# JsonReport — schema additions
# ---------------------------------------------------------------------------


class TestJsonReportSchema:
    def _report(self, **kwargs: object) -> dict:
        result = _completed_result([_finding()])
        return JsonReport().build(result, **kwargs)  # type: ignore[arg-type]

    def test_schema_version_present(self) -> None:
        assert "report_schema_version" in self._report()

    def test_schema_version_is_int(self) -> None:
        assert isinstance(self._report()["report_schema_version"], int)

    def test_schema_version_matches_constant(self) -> None:
        assert self._report()["report_schema_version"] == _REPORT_SCHEMA_VERSION

    def test_scanner_version_present(self) -> None:
        assert "scanner_version" in self._report()

    def test_webhound_version_still_present(self) -> None:
        assert "webhound_version" in self._report()

    def test_generated_at_present(self) -> None:
        assert "generated_at" in self._report()

    def test_report_generated_at_still_present(self) -> None:
        assert "report_generated_at" in self._report()

    def test_profile_section_present(self) -> None:
        assert "profile" in self._report()

    def test_baseline_section_present(self) -> None:
        assert "baseline" in self._report()

    def test_report_metadata_present(self) -> None:
        assert "report_metadata" in self._report()

    def test_report_metadata_keys(self) -> None:
        meta = self._report()["report_metadata"]
        for key in ("generated_at", "schema_version", "profile", "previous_baseline_id", "scan_id"):
            assert key in meta, f"Missing report_metadata key: {key}"

    def test_original_required_keys_intact(self) -> None:
        data = self._report()
        for key in ("webhound_version", "report_generated_at", "scan", "target",
                    "risk", "findings", "engines_run", "crawl", "errors", "metadata"):
            assert key in data, f"Missing key: {key}"


# ---------------------------------------------------------------------------
# JsonReport — profile and baseline kwargs
# ---------------------------------------------------------------------------


class TestJsonReportOptionalFields:
    def _build(self, profile_name: str | None = None, baseline_id: str | None = None) -> dict:
        result = _completed_result([_finding()])
        return JsonReport().build(result, profile_name=profile_name, baseline_id=baseline_id)

    def test_no_profile_gives_empty_profile(self) -> None:
        data = self._build()
        assert data["profile"] == {}

    def test_profile_name_stored(self) -> None:
        data = self._build(profile_name="standard")
        assert data["profile"]["name"] == "standard"

    def test_no_baseline_gives_empty_baseline(self) -> None:
        data = self._build()
        assert data["baseline"] == {}

    def test_baseline_id_stored(self) -> None:
        bid = str(uuid4())
        data = self._build(baseline_id=bid)
        assert data["baseline"]["previous_baseline_id"] == bid

    def test_report_metadata_profile_populated(self) -> None:
        data = self._build(profile_name="quick")
        assert data["report_metadata"]["profile"] == "quick"

    def test_report_metadata_baseline_populated(self) -> None:
        bid = str(uuid4())
        data = self._build(baseline_id=bid)
        assert data["report_metadata"]["previous_baseline_id"] == bid

    def test_backward_compat_no_kwargs(self) -> None:
        result = _completed_result()
        data = JsonReport().build(result)
        assert "scan" in data

    def test_to_json_accepts_profile_kwarg(self) -> None:
        result = _completed_result()
        json_str = JsonReport().to_json(result, profile_name="deep")
        assert "deep" in json_str


# ---------------------------------------------------------------------------
# JsonReport — grouped findings (existing schema preserved)
# ---------------------------------------------------------------------------


class TestJsonReportGroupedFindings:
    def test_grouped_findings_key_present(self) -> None:
        result = _completed_result()
        report = JsonReport().build(result)
        assert "grouped_findings" in report

    def test_grouped_finding_required_keys(self) -> None:
        result = _completed_result(grouped=[_grouped()])
        report = JsonReport().build(result)
        gf = report["grouped_findings"][0]
        for key in ("title", "severity", "category", "scanner_engine", "description",
                    "remediation", "affected_url_count", "affected_urls",
                    "evidence_count", "confidence", "anomaly_score",
                    "framework", "finding_ids"):
            assert key in gf, f"Missing grouped finding key: {key}"

    def test_affected_url_count_correct(self) -> None:
        result = _completed_result(grouped=[_grouped(affected_url_count=7)])
        report = JsonReport().build(result)
        assert report["grouped_findings"][0]["affected_url_count"] == 7


# ---------------------------------------------------------------------------
# JsonReport — WADE section (existing schema preserved)
# ---------------------------------------------------------------------------


class TestJsonReportWadeSection:
    def test_wade_key_present(self) -> None:
        result = _completed_result()
        report = JsonReport().build(result)
        assert "wade" in report

    def test_wade_required_keys(self) -> None:
        result = _completed_result()
        wade = JsonReport().build(result)["wade"]
        for key in ("baseline_generated", "baseline_version", "compared_to_previous_baseline",
                    "anomaly_count", "top_anomalies"):
            assert key in wade


# ---------------------------------------------------------------------------
# SummaryBuilder — WADE section (existing assertions preserved)
# ---------------------------------------------------------------------------


class TestSummaryBuilderWadeSection:
    def _result_with_wade(self, generated: bool = True, compared: bool = False, count: int = 0) -> ScanResult:
        result = _completed_result()
        result.metadata["wade_baseline_generated"] = generated
        result.metadata["wade_compared_to_previous"] = compared
        result.metadata["wade_anomaly_count"] = count
        return result

    def test_wade_not_shown_when_not_generated(self) -> None:
        result = self._result_with_wade(generated=False)
        summary = SummaryBuilder().build(result)
        assert "WADE" not in summary

    def test_wade_shown_when_generated(self) -> None:
        result = self._result_with_wade(generated=True)
        summary = SummaryBuilder().build(result)
        assert "WADE" in summary

    def test_baseline_generated_yes(self) -> None:
        result = self._result_with_wade(generated=True)
        summary = SummaryBuilder().build(result)
        assert "Baseline generated:   yes" in summary

    def test_compared_to_baseline_yes(self) -> None:
        result = self._result_with_wade(generated=True, compared=True, count=2)
        summary = SummaryBuilder().build(result)
        assert "Compared to baseline: yes" in summary

    def test_no_previous_baseline_message(self) -> None:
        result = self._result_with_wade(generated=True, compared=False)
        summary = SummaryBuilder().build(result)
        assert "no previous baseline" in summary
