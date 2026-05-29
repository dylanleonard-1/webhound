# WebHound — scanner/webhound/reporting/csv_report.py
# CSV report builder: flat finding rows suitable for spreadsheets and
# SIEM ingestion.
#
# Design decisions:
#   - Uses Python's stdlib csv module for correct quoting and escaping.
#   - Prefers grouped findings (one row per group) when available;
#     falls back to one row per active finding.
#   - Multi-value fields (OWASP IDs, CWE IDs) are semicolon-separated
#     within a single column so the row count stays predictable.
#   - All output is UTF-8 encoded.

from __future__ import annotations

import csv
import io
from typing import Any

from webhound.models.scan_result import ScanResult

# Column order for grouped-findings CSV
# Phase-3 / Phase-4 export-parity additions (v4 schema):
#   quality_label, tags, corroborated_by, chain_name — surfaced so
#   downstream SIEM ingestion can see the same scrub-able fields
#   the dashboard renders.
GROUPED_HEADERS: list[str] = [
    "title",
    "severity",
    "category",
    "engine",
    "affected_url",
    "affected_url_count",
    "confidence",
    "quality_label",
    "tags",
    "corroborated_by",
    "chain_name",
    "remediation",
    "evidence_count",
    # OWASP / CWE / NIST
    "owasp_top10",
    "cwe_ids",
    "nist_controls",
    # Compliance framework refs
    "pci_dss",
    "iso_27001",
    "soc2",
    "hipaa",
    # CVSS + exploitability
    "cvss_score",
    "cvss_vector",
    "exploitability",
    "status",
]

# Column order for raw-findings CSV (no url-count or status column)
RAW_HEADERS: list[str] = [
    "title",
    "severity",
    "category",
    "engine",
    "affected_url",
    "confidence",
    "quality_label",
    "tags",
    "corroborated_by",
    "chain_name",
    "remediation",
    "evidence_count",
    "owasp_top10",
    "cwe_ids",
    "nist_controls",
    "pci_dss",
    "iso_27001",
    "soc2",
    "hipaa",
    "cvss_score",
    "cvss_vector",
    "exploitability",
    # Phase-5D — every finding explains WHY it fired.
    "severity_rationale",
    "confidence_rationale",
]


class CsvReport:
    """Serialises findings from a completed ScanResult into CSV text.

    Grouped findings (when available) are exported as one row per group
    with the first sample URL in the ``affected_url`` column.  Raw active
    findings are exported one row per finding.

    Usage::

        csv_text = CsvReport().build(result)
        Path("report.csv").write_text(csv_text, encoding="utf-8")
    """

    def build(self, result: ScanResult) -> str:
        """Return a CSV string representing all findings in *result*."""
        output = io.StringIO()

        if result.grouped_findings:
            self._write_grouped(result, output)
        else:
            self._write_raw(result, output)

        return output.getvalue()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_grouped(self, result: ScanResult, out: io.StringIO) -> None:
        writer = csv.DictWriter(
            out,
            fieldnames=GROUPED_HEADERS,
            lineterminator="\n",
            extrasaction="ignore",
        )
        writer.writeheader()
        for gf in result.grouped_findings:
            first_url = gf.affected_urls[0] if gf.affected_urls else ""
            fa = gf.framework
            tags = list(getattr(gf, "tags", None) or [])
            corroborated_by = (getattr(gf, "metadata", None) or {}).get(
                "corroborated_by", []
            ) or []
            chain_name = (getattr(gf, "metadata", None) or {}).get(
                "chain_name", ""
            ) or ""
            writer.writerow({
                "title": gf.title,
                "severity": gf.severity.value,
                "category": gf.category.value,
                "engine": gf.scanner_engine,
                "affected_url": first_url,
                "affected_url_count": gf.affected_url_count,
                "confidence": round(gf.confidence, 4),
                "quality_label": getattr(gf, "quality_label", "") or "",
                "tags": ";".join(tags),
                "corroborated_by": ";".join(corroborated_by),
                "chain_name": chain_name,
                "remediation": gf.remediation or "",
                "evidence_count": gf.evidence_count,
                "owasp_top10": ";".join(fa.owasp_top10),
                "cwe_ids": ";".join(fa.cwe_ids),
                "nist_controls": ";".join(fa.nist_controls),
                "pci_dss": ";".join(fa.pci_dss),
                "iso_27001": ";".join(fa.iso_27001),
                "soc2": ";".join(fa.soc2),
                "hipaa": ";".join(fa.hipaa),
                "cvss_score": fa.cvss_score if fa.cvss_score is not None else "",
                "cvss_vector": fa.cvss_vector or "",
                "exploitability": fa.exploitability.value if fa.exploitability else "",
                "status": "active",
            })

    def _write_raw(self, result: ScanResult, out: io.StringIO) -> None:
        writer = csv.DictWriter(
            out,
            fieldnames=RAW_HEADERS,
            lineterminator="\n",
            extrasaction="ignore",
        )
        writer.writeheader()
        for f in result.active_findings:
            loc = f.evidence[0].location if f.evidence else ""
            fa = f.framework
            tags = list(getattr(f, "tags", None) or [])
            corroborated_by = (getattr(f, "metadata", None) or {}).get(
                "corroborated_by", []
            ) or []
            chain_name = (getattr(f, "metadata", None) or {}).get(
                "chain_name", ""
            ) or ""
            writer.writerow({
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "engine": f.scanner_engine,
                "affected_url": loc,
                "confidence": round(f.confidence, 4),
                "quality_label": getattr(f, "quality_label", "") or "",
                "tags": ";".join(tags),
                "corroborated_by": ";".join(corroborated_by),
                "chain_name": chain_name,
                "remediation": f.remediation or "",
                "evidence_count": f.evidence_count,
                "owasp_top10": ";".join(fa.owasp_top10),
                "cwe_ids": ";".join(fa.cwe_ids),
                "nist_controls": ";".join(fa.nist_controls),
                "pci_dss": ";".join(fa.pci_dss),
                "iso_27001": ";".join(fa.iso_27001),
                "soc2": ";".join(fa.soc2),
                "hipaa": ";".join(fa.hipaa),
                "cvss_score": fa.cvss_score if fa.cvss_score is not None else "",
                "cvss_vector": fa.cvss_vector or "",
                "exploitability": fa.exploitability.value if fa.exploitability else "",
                "severity_rationale": getattr(f, "severity_rationale", "") or "",
                "confidence_rationale": getattr(f, "confidence_rationale", "") or "",
            })
