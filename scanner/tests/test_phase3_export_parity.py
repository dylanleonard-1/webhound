# WebHound — scanner/tests/test_phase3_export_parity.py
# Phase-3 D/E/F: compliance rollup + evidence graph + export parity.
#
# Validates that the new shared compliance helper produces consistent
# numbers, the evidence graph is content-addressed and stable, and
# every reporter (JSON, CSV, SARIF, markdown) surfaces the v3/v4
# additions (tags, quality_label, corroborated_by, chain_name).

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult, ScanStatus
from webhound.models.severity import Severity
from webhound.models.target import Target
from webhound.reporting.compliance import (
    build_compliance_rollup,
)
from webhound.reporting.csv_report import CsvReport, GROUPED_HEADERS, RAW_HEADERS
from webhound.reporting.evidence_graph import build_evidence_graph
from webhound.reporting.json_report import JsonReport
from webhound.reporting.markdown_report import MarkdownReport
from webhound.reporting.sarif_report import SarifReport


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _f(**overrides) -> Finding:
    base = dict(
        title="Missing CSP",
        description="No Content-Security-Policy header set.",
        severity=Severity.HIGH,
        category=FindingCategory.SECURITY_HEADER,
        confidence=0.95,
        scanner_engine="security_headers",
        framework=FrameworkAlignment(
            owasp_top10=["A05:2021"], cwe_ids=["CWE-693"],
            nist_controls=["SI-10"], soc2=["CC6.7"],
        ),
        evidence=[Evidence(
            evidence_type=EvidenceType.HEADER,
            content="missing",
            location="https://target.example/",
            source_engine="security_headers",
        )],
        tags=["confirmed"],
        metadata={},
    )
    base.update(overrides)
    return Finding(**base)


def _gf(*, severity=Severity.HIGH, framework=None,
        tags=None, confidence=0.95, metadata=None,
        title="Missing CSP") -> GroupedFinding:
    return GroupedFinding(
        title=title,
        severity=severity,
        category=FindingCategory.SECURITY_HEADER,
        scanner_engine="security_headers",
        description="x",
        remediation="x",
        affected_url_count=1,
        affected_urls=["https://target.example/"],
        evidence_count=1,
        confidence=confidence,
        framework=framework or FrameworkAlignment(
            soc2=["CC6.7"], pci_dss=["6.5.10"],
        ),
        tags=list(tags or []),
        metadata=dict(metadata or {}),
        finding_ids=["abc"],
    )


def _result(findings=None, grouped=None) -> ScanResult:
    r = ScanResult(
        target=Target.from_url("https://target.example/"),
        status=ScanStatus.COMPLETED,
        findings=findings or [],
        engines_run=["security_headers"],
        urls_crawled=1,
        pages_analyzed=1,
        started_at=datetime(2026, 5, 28, tzinfo=timezone.utc),
        completed_at=datetime(2026, 5, 28, tzinfo=timezone.utc),
    )
    r.recompute_aggregates()
    r.grouped_findings = grouped or []
    r.metadata["risk_score"] = 80
    r.metadata["risk_level"] = "high"
    r.metadata["external_domains"] = []
    r.metadata["external_domain_count"] = 0
    return r


# ---------------------------------------------------------------------------
# Compliance rollup
# ---------------------------------------------------------------------------


def test_compliance_rollup_separates_controls_from_findings() -> None:
    """20 advisory findings touching ONE SOC 2 control = 1 control
    impacted, not 20. The classic inflation bug the rollup fixes."""
    grouped = [
        _gf(framework=FrameworkAlignment(soc2=["CC6.7"]),
            tags=["heuristic"], confidence=0.4)
        for _ in range(20)
    ]
    r = _result(grouped=grouped)
    rollup = build_compliance_rollup(r)
    soc = next(fr for fr in rollup.frameworks if fr.field_name == "soc2")
    assert soc.controls_impacted == 1
    assert soc.findings_mapped == 20


def test_confirmed_violations_only_count_high_plus_quality() -> None:
    """An advisory + a HIGH+confirmed finding both touch the same
    control. Confirmed_violations should be 1, advisory_controls 0."""
    grouped = [
        _gf(severity=Severity.INFO, framework=FrameworkAlignment(soc2=["CC6.7"]),
            tags=["advisory"], confidence=1.0),
        _gf(severity=Severity.HIGH, framework=FrameworkAlignment(soc2=["CC6.7"]),
            tags=["confirmed"], confidence=0.95),
    ]
    rollup = build_compliance_rollup(_result(grouped=grouped))
    soc = next(fr for fr in rollup.frameworks if fr.field_name == "soc2")
    assert soc.confirmed_violations == 1
    assert soc.advisory_controls == 0


def test_advisory_only_controls_isolated_from_confirmed() -> None:
    grouped = [
        _gf(severity=Severity.INFO,
            framework=FrameworkAlignment(soc2=["CC6.7"]),
            tags=["advisory"], confidence=1.0),
    ]
    rollup = build_compliance_rollup(_result(grouped=grouped))
    soc = next(fr for fr in rollup.frameworks if fr.field_name == "soc2")
    assert soc.advisory_controls == 1
    assert soc.confirmed_violations == 0


def test_compliance_rollup_known_exploited_count() -> None:
    grouped = [
        _gf(framework=FrameworkAlignment(
            soc2=["CC6.7"],
            exploitability=Exploitability.KNOWN_EXPLOITED,
        )),
        _gf(framework=FrameworkAlignment(
            soc2=["CC6.6"],
            exploitability=Exploitability.PRACTICAL,
        )),
    ]
    rollup = build_compliance_rollup(_result(grouped=grouped))
    assert rollup.known_exploited_finding_count == 1


# ---------------------------------------------------------------------------
# Evidence graph
# ---------------------------------------------------------------------------


def test_evidence_graph_has_scan_root() -> None:
    g = build_evidence_graph(_result())
    assert any(n.kind == "scan" for n in g.nodes)


def test_evidence_graph_links_finding_to_evidence_to_page() -> None:
    f = _f()
    g = build_evidence_graph(_result(findings=[f]))
    # Pull node ids by kind.
    fnode = next(n for n in g.nodes if n.kind == "finding")
    enode = next(n for n in g.nodes if n.kind == "evidence")
    pnode = next(n for n in g.nodes if n.kind == "page")
    # Required edge chain.
    edges = {(e.src, e.dst, e.kind) for e in g.edges}
    assert (fnode.id, enode.id, "finding_cites_evidence") in edges
    assert (enode.id, pnode.id, "evidence_observed_on_page") in edges


def test_evidence_graph_node_ids_deterministic() -> None:
    """Given the SAME ScanResult instance, two consecutive builds
    must produce identical node ids — the graph is content-addressed,
    so re-rendering doesn't change ids. (Different ScanResult
    instances DO get different scan-root ids because the scan UUID
    differs by construction; that's correct.)"""
    f = _f()
    r = _result(findings=[f])
    g1 = build_evidence_graph(r)
    g2 = build_evidence_graph(r)
    assert [n.id for n in g1.nodes] == [n.id for n in g2.nodes]
    assert [(e.src, e.dst, e.kind) for e in g1.edges] \
        == [(e.src, e.dst, e.kind) for e in g2.edges]


def test_evidence_graph_chain_corroborates_constituents() -> None:
    constituent = _f(title="signal A")
    cluster = _f(
        title="Correlated threat chain: supply chain compromise risk",
        scanner_engine="correlation",
        tags=["correlated", "cluster"],
        metadata={
            "chain_name": "supply_chain_compromise_risk",
            "signal_count": 2,
            "constituent_finding_ids": [str(constituent.id)],
        },
    )
    g = build_evidence_graph(_result(findings=[constituent, cluster]))
    edges = {(e.src, e.dst, e.kind) for e in g.edges}
    # The cluster→constituent edge must exist.
    assert any(kind == "chain_corroborated_finding"
                for (_, _, kind) in edges)


# ---------------------------------------------------------------------------
# JSON report v4 — top-level compliance + evidence_graph keys
# ---------------------------------------------------------------------------


def test_json_report_has_compliance_section() -> None:
    grouped = [_gf(framework=FrameworkAlignment(soc2=["CC6.7"]))]
    rep = JsonReport().build(_result(grouped=grouped))
    assert "compliance" in rep
    c = rep["compliance"]
    assert "frameworks" in c
    assert "total_controls_impacted" in c


def test_json_report_has_evidence_graph_section() -> None:
    rep = JsonReport().build(_result(findings=[_f()]))
    assert "evidence_graph" in rep
    g = rep["evidence_graph"]
    assert "nodes" in g
    assert "edges" in g


# ---------------------------------------------------------------------------
# CSV export parity (v4 headers)
# ---------------------------------------------------------------------------


def test_csv_grouped_headers_include_v4_fields() -> None:
    for col in ("quality_label", "tags", "corroborated_by", "chain_name"):
        assert col in GROUPED_HEADERS, f"missing {col}"


def test_csv_raw_headers_include_v4_fields() -> None:
    for col in ("quality_label", "tags", "corroborated_by", "chain_name"):
        assert col in RAW_HEADERS


def test_csv_grouped_row_surfaces_correlation_metadata() -> None:
    gf = _gf(
        tags=["correlated", "confirmed"],
        metadata={
            "chain_name": "supply_chain_compromise_risk",
            "corroborated_by": ["supply_chain_compromise_risk"],
        },
    )
    txt = CsvReport().build(_result(grouped=[gf]))
    # The v4 fields appear in the second (data) row.
    line = txt.splitlines()[1]
    assert "supply_chain_compromise_risk" in line
    assert "correlated" in line


# ---------------------------------------------------------------------------
# SARIF v4 parity
# ---------------------------------------------------------------------------


def test_sarif_grouped_result_includes_corroborated_by() -> None:
    gf = _gf(
        tags=["correlated"],
        metadata={
            "chain_name": "supply_chain_compromise_risk",
            "corroborated_by": ["supply_chain_compromise_risk"],
        },
    )
    rep = SarifReport().build(_result(grouped=[gf]))
    # Pull the first result and check properties.
    sarif_result = rep["runs"][0]["results"][0]
    props = sarif_result["properties"]
    assert props.get("chain_name") == "supply_chain_compromise_risk"
    assert "supply_chain_compromise_risk" in props.get("corroborated_by", [])


def test_sarif_grouped_result_includes_quality_label() -> None:
    gf = _gf(tags=["confirmed"])
    rep = SarifReport().build(_result(grouped=[gf]))
    props = rep["runs"][0]["results"][0]["properties"]
    assert props.get("quality_label") in ("confirmed", "likely")


# ---------------------------------------------------------------------------
# Markdown rendered uses the new four-column rollup table
# ---------------------------------------------------------------------------


def test_markdown_compliance_table_uses_four_column_format() -> None:
    grouped = [_gf(framework=FrameworkAlignment(soc2=["CC6.7"]))]
    md_text = MarkdownReport().build(_result(grouped=grouped))
    assert "Controls impacted" in md_text
    assert "Findings mapped" in md_text
    assert "Confirmed violations" in md_text
    assert "Advisory only" in md_text
