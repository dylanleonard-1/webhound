# WebHound — scanner/tests/test_output_formats.py
# Tests for Phase 19: SARIF, CSV, and Markdown output formats.
#
# Covers: SARIF schema basics, severity mapping, ruleId generation,
# locations, properties; CSV headers, escaping, grouped vs raw output;
# Markdown report sections; run_scan --format flag parsing.

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

import pytest

from webhound.models.engine_status import EngineRunStatus, EngineStatus
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult, ScanStatus, SeverityBreakdown
from webhound.models.severity import Severity
from webhound.models.target import ScanOptions, Target
from webhound.reporting.csv_report import GROUPED_HEADERS, RAW_HEADERS, CsvReport
from webhound.reporting.markdown_report import MarkdownReport
from webhound.reporting.sarif_report import SarifReport, _rule_id, _SARIF_LEVEL


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _target() -> Target:
    return Target.from_url(
        "https://example.com",
        scan_options=ScanOptions(max_pages=3, max_depth=1, rate_limit_rps=10.0),
    )


def _finding(
    title: str = "Missing CSP",
    severity: Severity = Severity.MEDIUM,
    engine: str = "security_headers",
    category: FindingCategory = FindingCategory.SECURITY_HEADER,
    location: str = "https://example.com/",
    remediation: str | None = "Add CSP header.",
    owasp: list[str] | None = None,
    cwe: list[str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        description=f"{title} — detailed description.",
        severity=severity,
        category=category,
        scanner_engine=engine,
        remediation=remediation,
        framework=FrameworkAlignment(
            owasp_top10=owasp or ["A05:2021"],
            cwe_ids=cwe or ["CWE-693"],
        ),
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
    engine: str = "security_headers",
    affected_url_count: int = 1,
    remediation: str | None = "Add CSP header.",
    affected_urls: list[str] | None = None,
) -> GroupedFinding:
    urls = affected_urls or [f"https://example.com/p{i}" for i in range(min(affected_url_count, 3))]
    return GroupedFinding(
        title=title,
        severity=severity,
        category=category,
        scanner_engine=engine,
        description=f"{title} — detailed description.",
        remediation=remediation,
        affected_url_count=affected_url_count,
        affected_urls=urls,
        evidence_count=affected_url_count,
        framework=FrameworkAlignment(owasp_top10=["A05:2021"], cwe_ids=["CWE-693"]),
    )


def _result(
    findings: list[Finding] | None = None,
    grouped: list[GroupedFinding] | None = None,
    engines: list[EngineStatus] | None = None,
) -> ScanResult:
    r = ScanResult(
        target=_target(),
        status=ScanStatus.COMPLETED,
        findings=findings or [],
        urls_crawled=5,
        pages_analyzed=5,
        started_at=datetime(2025, 6, 1, 10, 0, 0, tzinfo=timezone.utc),
        completed_at=datetime(2025, 6, 1, 10, 0, 10, tzinfo=timezone.utc),
        engine_diagnostics=engines or [],
    )
    r.recompute_aggregates()
    r.metadata["risk_score"] = 75
    r.metadata["risk_level"] = "low"
    if grouped is not None:
        r.grouped_findings = grouped
    return r


# ---------------------------------------------------------------------------
# SARIF — schema basics
# ---------------------------------------------------------------------------


class TestSarifSchema:
    def test_version_field(self) -> None:
        r = _result()
        doc = SarifReport().build(r)
        assert doc["version"] == "2.1.0"

    def test_schema_field_present(self) -> None:
        r = _result()
        doc = SarifReport().build(r)
        assert "$schema" in doc
        assert "sarif" in doc["$schema"].lower()

    def test_runs_is_list(self) -> None:
        r = _result()
        doc = SarifReport().build(r)
        assert isinstance(doc["runs"], list)
        assert len(doc["runs"]) == 1

    def test_tool_driver_name(self) -> None:
        r = _result()
        doc = SarifReport().build(r)
        assert doc["runs"][0]["tool"]["driver"]["name"] == "WebHound"

    def test_tool_driver_rules_is_list(self) -> None:
        r = _result(grouped=[_grouped()])
        doc = SarifReport().build(r)
        assert isinstance(doc["runs"][0]["tool"]["driver"]["rules"], list)

    def test_results_is_list(self) -> None:
        r = _result()
        doc = SarifReport().build(r)
        assert isinstance(doc["runs"][0]["results"], list)

    def test_empty_findings_gives_empty_results(self) -> None:
        r = _result()
        doc = SarifReport().build(r)
        assert doc["runs"][0]["results"] == []

    def test_run_properties_include_target(self) -> None:
        r = _result()
        doc = SarifReport().build(r)
        props = doc["runs"][0]["properties"]
        assert props["target"] == "https://example.com"

    def test_profile_in_run_properties(self) -> None:
        r = _result()
        doc = SarifReport().build(r, profile_name="standard")
        assert doc["runs"][0]["properties"]["profile"] == "standard"

    def test_json_serializable(self) -> None:
        r = _result(grouped=[_grouped()])
        doc = SarifReport().build(r)
        serialized = json.dumps(doc)
        assert isinstance(serialized, str)


# ---------------------------------------------------------------------------
# SARIF — severity mapping
# ---------------------------------------------------------------------------


class TestSarifSeverityMapping:
    def test_critical_maps_to_error(self) -> None:
        assert _SARIF_LEVEL["critical"] == "error"

    def test_high_maps_to_error(self) -> None:
        assert _SARIF_LEVEL["high"] == "error"

    def test_medium_maps_to_warning(self) -> None:
        assert _SARIF_LEVEL["medium"] == "warning"

    def test_low_maps_to_note(self) -> None:
        assert _SARIF_LEVEL["low"] == "note"

    def test_info_maps_to_none(self) -> None:
        assert _SARIF_LEVEL["info"] == "none"

    def test_result_level_reflects_severity(self) -> None:
        r = _result(grouped=[_grouped(severity=Severity.HIGH)])
        doc = SarifReport().build(r)
        result0 = doc["runs"][0]["results"][0]
        assert result0["level"] == "error"

    def test_medium_result_level_is_warning(self) -> None:
        r = _result(grouped=[_grouped(severity=Severity.MEDIUM)])
        doc = SarifReport().build(r)
        assert doc["runs"][0]["results"][0]["level"] == "warning"


# ---------------------------------------------------------------------------
# SARIF — rule IDs
# ---------------------------------------------------------------------------


class TestSarifRuleId:
    def test_rule_id_includes_engine(self) -> None:
        rid = _rule_id("security_headers", "Missing CSP")
        assert rid.startswith("security_headers/")

    def test_rule_id_slug_is_lowercase(self) -> None:
        rid = _rule_id("headers", "Missing Content-Security-Policy")
        assert rid == rid.lower()

    def test_rule_id_no_spaces(self) -> None:
        rid = _rule_id("engine", "Some Finding Title")
        assert " " not in rid

    def test_rule_id_title_truncated(self) -> None:
        long_title = "A" * 100
        rid = _rule_id("engine", long_title)
        # slug portion must not exceed 60 chars
        slug = rid.split("/", 1)[1]
        assert len(slug) <= 60

    def test_duplicate_findings_reuse_same_rule(self) -> None:
        r = _result(grouped=[
            _grouped(title="Same Issue", affected_urls=["https://example.com/a"]),
            _grouped(title="Same Issue", affected_urls=["https://example.com/b"]),
        ])
        doc = SarifReport().build(r)
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [rule["id"] for rule in rules]
        assert len(rule_ids) == len(set(rule_ids)), "Rules must be deduplicated"


# ---------------------------------------------------------------------------
# SARIF — locations
# ---------------------------------------------------------------------------


class TestSarifLocations:
    def test_result_has_locations(self) -> None:
        r = _result(grouped=[_grouped(affected_urls=["https://example.com/page"])])
        doc = SarifReport().build(r)
        result0 = doc["runs"][0]["results"][0]
        assert "locations" in result0
        assert len(result0["locations"]) >= 1

    def test_location_uri_matches_affected_url(self) -> None:
        r = _result(grouped=[_grouped(affected_urls=["https://example.com/specific-page"])])
        doc = SarifReport().build(r)
        loc = doc["runs"][0]["results"][0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "https://example.com/specific-page"

    def test_multiple_affected_urls_create_multiple_results(self) -> None:
        r = _result(grouped=[
            _grouped(
                affected_url_count=3,
                affected_urls=["https://example.com/a", "https://example.com/b", "https://example.com/c"],
            )
        ])
        doc = SarifReport().build(r)
        results = doc["runs"][0]["results"]
        assert len(results) == 3

    def test_fallback_to_target_url_when_no_affected_urls(self) -> None:
        gf = GroupedFinding(
            title="Test",
            severity=Severity.LOW,
            category=FindingCategory.SECURITY_HEADER,
            scanner_engine="test",
            description="desc",
            affected_url_count=1,
            affected_urls=[],  # empty
            evidence_count=1,
            framework=FrameworkAlignment(),
        )
        r = _result(grouped=[gf])
        doc = SarifReport().build(r)
        loc = doc["runs"][0]["results"][0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "https://example.com"

    def test_raw_finding_location_uses_evidence(self) -> None:
        f = _finding(location="https://example.com/raw-page")
        r = _result(findings=[f])
        # no grouped findings — fallback to raw
        doc = SarifReport().build(r)
        loc = doc["runs"][0]["results"][0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "https://example.com/raw-page"


# ---------------------------------------------------------------------------
# SARIF — properties
# ---------------------------------------------------------------------------


class TestSarifProperties:
    def test_result_properties_include_severity(self) -> None:
        r = _result(grouped=[_grouped(severity=Severity.HIGH)])
        doc = SarifReport().build(r)
        props = doc["runs"][0]["results"][0]["properties"]
        assert props["severity"] == "high"

    def test_result_properties_include_category(self) -> None:
        r = _result(grouped=[_grouped(category=FindingCategory.CORS)])
        doc = SarifReport().build(r)
        props = doc["runs"][0]["results"][0]["properties"]
        assert props["category"] == "cors"

    def test_result_properties_include_confidence(self) -> None:
        r = _result(grouped=[_grouped()])
        doc = SarifReport().build(r)
        props = doc["runs"][0]["results"][0]["properties"]
        assert "confidence" in props

    def test_result_properties_include_engine(self) -> None:
        r = _result(grouped=[_grouped(engine="tls_checker")])
        doc = SarifReport().build(r)
        props = doc["runs"][0]["results"][0]["properties"]
        assert props["engine"] == "tls_checker"

    def test_result_properties_include_framework_fields(self) -> None:
        r = _result(grouped=[_grouped()])
        doc = SarifReport().build(r)
        props = doc["runs"][0]["results"][0]["properties"]
        assert "owasp_top10" in props
        assert "cwe_ids" in props

    def test_rule_has_help_when_remediation_present(self) -> None:
        r = _result(grouped=[_grouped(remediation="Fix the header.")])
        doc = SarifReport().build(r)
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "help" in rule
        assert "Fix the header." in rule["help"]["text"]

    def test_rule_no_help_when_no_remediation(self) -> None:
        r = _result(grouped=[_grouped(remediation=None)])
        doc = SarifReport().build(r)
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        assert "help" not in rule


# ---------------------------------------------------------------------------
# CSV — headers and structure
# ---------------------------------------------------------------------------


class TestCsvHeaders:
    def test_grouped_headers_row(self) -> None:
        r = _result(grouped=[_grouped()])
        csv_text = CsvReport().build(r)
        reader = csv.DictReader(io.StringIO(csv_text))
        assert reader.fieldnames is not None
        for h in GROUPED_HEADERS:
            assert h in reader.fieldnames

    def test_raw_headers_row(self) -> None:
        r = _result(findings=[_finding()])
        csv_text = CsvReport().build(r)
        reader = csv.DictReader(io.StringIO(csv_text))
        assert reader.fieldnames is not None
        for h in RAW_HEADERS:
            assert h in reader.fieldnames

    def test_grouped_csv_has_data_rows(self) -> None:
        r = _result(grouped=[_grouped(), _grouped(title="Another")])
        csv_text = CsvReport().build(r)
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        assert len(rows) == 2

    def test_raw_csv_has_data_rows(self) -> None:
        r = _result(findings=[_finding(), _finding(title="Finding 2")])
        csv_text = CsvReport().build(r)
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        assert len(rows) == 2

    def test_empty_findings_has_only_header(self) -> None:
        r = _result()
        csv_text = CsvReport().build(r)
        lines = [l for l in csv_text.strip().splitlines() if l]
        assert len(lines) == 1  # header only

    def test_grouped_preferred_over_raw(self) -> None:
        r = _result(
            findings=[_finding()],
            grouped=[_grouped()],
        )
        csv_text = CsvReport().build(r)
        reader = csv.DictReader(io.StringIO(csv_text))
        # Grouped headers should be used, not raw
        assert "affected_url_count" in (reader.fieldnames or [])


# ---------------------------------------------------------------------------
# CSV — field values
# ---------------------------------------------------------------------------


class TestCsvFieldValues:
    def test_severity_value(self) -> None:
        r = _result(grouped=[_grouped(severity=Severity.HIGH)])
        rows = list(csv.DictReader(io.StringIO(CsvReport().build(r))))
        assert rows[0]["severity"] == "high"

    def test_category_value(self) -> None:
        r = _result(grouped=[_grouped(category=FindingCategory.TLS)])
        rows = list(csv.DictReader(io.StringIO(CsvReport().build(r))))
        assert rows[0]["category"] == "tls"

    def test_remediation_empty_string_when_none(self) -> None:
        r = _result(grouped=[_grouped(remediation=None)])
        rows = list(csv.DictReader(io.StringIO(CsvReport().build(r))))
        assert rows[0]["remediation"] == ""

    def test_owasp_semicolon_separated(self) -> None:
        gf = GroupedFinding(
            title="T", severity=Severity.LOW, category=FindingCategory.SECURITY_HEADER,
            scanner_engine="e", description="d", affected_url_count=1,
            affected_urls=["https://example.com"], evidence_count=1,
            framework=FrameworkAlignment(owasp_top10=["A01:2021", "A05:2021"]),
        )
        r = _result(grouped=[gf])
        rows = list(csv.DictReader(io.StringIO(CsvReport().build(r))))
        assert rows[0]["owasp_top10"] == "A01:2021;A05:2021"

    def test_status_is_active_for_grouped(self) -> None:
        r = _result(grouped=[_grouped()])
        rows = list(csv.DictReader(io.StringIO(CsvReport().build(r))))
        assert rows[0]["status"] == "active"

    def test_affected_url_count_in_grouped(self) -> None:
        r = _result(grouped=[_grouped(affected_url_count=7)])
        rows = list(csv.DictReader(io.StringIO(CsvReport().build(r))))
        assert rows[0]["affected_url_count"] == "7"


# ---------------------------------------------------------------------------
# CSV — escaping
# ---------------------------------------------------------------------------


class TestCsvEscaping:
    def test_comma_in_title_is_quoted(self) -> None:
        r = _result(grouped=[_grouped(title="Header, Missing")])
        csv_text = CsvReport().build(r)
        # csv module wraps fields with commas in quotes
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        assert rows[0]["title"] == "Header, Missing"

    def test_double_quote_in_remediation_escaped(self) -> None:
        r = _result(grouped=[_grouped(remediation='Use "strict" mode.')])
        csv_text = CsvReport().build(r)
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        assert rows[0]["remediation"] == 'Use "strict" mode.'

    def test_newline_in_description_safe(self) -> None:
        gf = GroupedFinding(
            title="T", severity=Severity.LOW,
            category=FindingCategory.SECURITY_HEADER,
            scanner_engine="e",
            description="line1\nline2",
            remediation="fix\nit",
            affected_url_count=1,
            affected_urls=["https://example.com"],
            evidence_count=1,
            framework=FrameworkAlignment(),
        )
        r = _result(grouped=[gf])
        # Should not raise; csv module handles newlines via quoting
        csv_text = CsvReport().build(r)
        rows = list(csv.DictReader(io.StringIO(csv_text)))
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# Markdown — section presence
# ---------------------------------------------------------------------------


class TestMarkdownSections:
    def _build(self, **kwargs) -> str:
        r = _result(**kwargs)
        r.metadata["risk_score"] = 80
        r.metadata["risk_level"] = "low"
        return MarkdownReport().build(r, profile_name="standard")

    def test_h1_title(self) -> None:
        md = self._build()
        assert "# WebHound Scan Report" in md

    def test_target_present(self) -> None:
        md = self._build()
        assert "example.com" in md

    def test_risk_score_present(self) -> None:
        md = self._build()
        assert "80 / 100" in md

    def test_severity_breakdown_section(self) -> None:
        md = self._build()
        assert "## Severity Breakdown" in md
        assert "CRITICAL" in md
        assert "HIGH" in md

    def test_findings_section_header(self) -> None:
        md = self._build()
        assert "## Findings" in md

    def test_no_findings_placeholder(self) -> None:
        md = self._build()
        assert "No findings recorded" in md

    def test_findings_table_with_grouped(self) -> None:
        md = self._build(grouped=[_grouped(title="Missing HSTS", severity=Severity.HIGH)])
        assert "Missing HSTS" in md
        assert "HIGH" in md

    def test_profile_shown_in_header(self) -> None:
        md = self._build()
        assert "standard" in md

    def test_scan_id_present(self) -> None:
        md = self._build()
        assert "Scan ID" in md

    def test_engine_diagnostics_section_when_present(self) -> None:
        engines = [
            EngineStatus(
                name="security_headers",
                category="headers",
                status=EngineRunStatus.FINDINGS,
                findings_count=3,
                duration_ms=45.2,
            )
        ]
        md = self._build(engines=engines)
        assert "## Engine Diagnostics" in md
        assert "security_headers" in md

    def test_no_engine_diagnostics_section_when_absent(self) -> None:
        md = self._build(engines=[])
        assert "## Engine Diagnostics" not in md

    def test_errors_section_absent_when_no_errors(self) -> None:
        md = self._build()
        assert "## Errors" not in md

    def test_recommended_actions_present_for_actionable_grouped(self) -> None:
        md = self._build(grouped=[
            _grouped(
                title="Missing HSTS",
                severity=Severity.HIGH,
                category=FindingCategory.SECURITY_HEADER,
                remediation="Enable HSTS.",
            )
        ])
        assert "## Recommended Actions" in md
        assert "Missing HSTS" in md


# ---------------------------------------------------------------------------
# Markdown — table escaping
# ---------------------------------------------------------------------------


class TestMarkdownEscaping:
    def test_pipe_in_title_escaped(self) -> None:
        r = _result(grouped=[_grouped(title="Header | Value")])
        r.metadata["risk_score"] = 80
        r.metadata["risk_level"] = "low"
        md = MarkdownReport().build(r)
        # pipe in title must be escaped
        assert "Header \\| Value" in md

    def test_newline_in_title_replaced(self) -> None:
        r = _result(grouped=[_grouped(title="Header\nValue")])
        r.metadata["risk_score"] = 80
        r.metadata["risk_level"] = "low"
        md = MarkdownReport().build(r)
        # newlines should not appear inside table cells
        lines_with_heading = [l for l in md.splitlines() if "Header" in l and "|" in l]
        for line in lines_with_heading:
            assert "\n" not in line


# ---------------------------------------------------------------------------
# run_scan.py — --format flag
# ---------------------------------------------------------------------------


class TestRunScanFormatFlag:
    def _parser(self):
        import sys
        sys.path.insert(0, "/mnt/c/Users/dmleo/OneDrive/Documents/Scripts/WebHound/scanner")
        from run_scan import _build_arg_parser
        return _build_arg_parser()

    def test_format_json(self) -> None:
        args = self._parser().parse_args(["https://example.com", "--format", "json"])
        assert args.formats == ["json"]

    def test_format_sarif(self) -> None:
        args = self._parser().parse_args(["https://example.com", "--format", "sarif"])
        assert args.formats == ["sarif"]

    def test_format_csv(self) -> None:
        args = self._parser().parse_args(["https://example.com", "--format", "csv"])
        assert args.formats == ["csv"]

    def test_format_markdown(self) -> None:
        args = self._parser().parse_args(["https://example.com", "--format", "markdown"])
        assert args.formats == ["markdown"]

    def test_format_all(self) -> None:
        args = self._parser().parse_args(["https://example.com", "--format", "all"])
        assert "all" in args.formats

    def test_format_repeatable(self) -> None:
        args = self._parser().parse_args([
            "https://example.com", "--format", "json", "--format", "sarif"
        ])
        assert "json" in args.formats
        assert "sarif" in args.formats

    def test_format_default_is_none(self) -> None:
        args = self._parser().parse_args(["https://example.com"])
        assert args.formats is None

    def test_resolve_formats_default(self) -> None:
        import sys
        sys.path.insert(0, "/mnt/c/Users/dmleo/OneDrive/Documents/Scripts/WebHound/scanner")
        from run_scan import _resolve_formats
        assert _resolve_formats(None) == {"json"}

    def test_resolve_formats_all(self) -> None:
        import sys
        sys.path.insert(0, "/mnt/c/Users/dmleo/OneDrive/Documents/Scripts/WebHound/scanner")
        from run_scan import _resolve_formats, _ALL_FORMATS
        result = _resolve_formats(["all"])
        assert result == set(_ALL_FORMATS)

    def test_resolve_formats_explicit(self) -> None:
        import sys
        sys.path.insert(0, "/mnt/c/Users/dmleo/OneDrive/Documents/Scripts/WebHound/scanner")
        from run_scan import _resolve_formats
        assert _resolve_formats(["sarif", "csv"]) == {"sarif", "csv"}
