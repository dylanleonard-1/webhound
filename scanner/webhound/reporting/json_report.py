# WebHound — scanner/webhound/reporting/json_report.py
# Structured JSON report builder for completed scan results.
#
# Schema version history:
#   v1 — initial structured report
#   v2 — added report_schema_version, scanner_version, profile, baseline_metadata,
#         generated_at alias, report_metadata section

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from webhound.core.performance import ScanTelemetry
from webhound.models.scan_result import ScanResult

_REPORT_SCHEMA_VERSION = 2


def _wade_section(result: ScanResult) -> dict[str, Any]:
    """Build the WADE sub-dict for the JSON report."""
    wade_findings = sorted(
        [f for f in result.active_findings if f.scanner_engine == "wade"],
        key=lambda f: (f.anomaly_score or 0.0),
        reverse=True,
    )
    top_anomalies = [
        {
            "title": f.title,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "anomaly_score": f.anomaly_score,
            "evidence_location": f.evidence[0].location if f.evidence else None,
            "description": f.description,
        }
        for f in wade_findings[:5]
    ]
    return {
        "baseline_generated": result.metadata.get("wade_baseline_generated", False),
        "baseline_version": result.metadata.get("wade_baseline_version"),
        "compared_to_previous_baseline": result.metadata.get("wade_compared_to_previous", False),
        "anomaly_count": result.metadata.get("wade_anomaly_count", 0),
        "top_anomalies": top_anomalies,
    }


class JsonReport:
    """Serialises a completed ScanResult into a structured JSON report dict.

    Optional keyword arguments allow enriching the report with scan profile
    and baseline provenance metadata without breaking callers that omit them.

    Usage::

        report = JsonReport()
        data = report.build(result)                              # dict
        data = report.build(result, profile_name="standard")    # with profile
        json_str = report.to_json(result)                        # pretty JSON
    """

    def build(
        self,
        result: ScanResult,
        *,
        profile_name: str | None = None,
        baseline_id: str | None = None,
    ) -> dict[str, Any]:
        """Build and return the full report as a plain Python dict.

        Parameters
        ----------
        result:
            Completed scan result.
        profile_name:
            Name of the scan profile used (e.g. ``"standard"``).
        baseline_id:
            Scan UUID of the previous WADE baseline that was compared against,
            if any.
        """
        now = datetime.now(timezone.utc).isoformat()
        risk_score = result.metadata.get("risk_score", 100)
        risk_level = result.metadata.get("risk_level", "low")
        bd = result.severity_breakdown

        findings_out: list[dict[str, Any]] = []
        for f in result.active_findings:
            item: dict[str, Any] = {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "confidence": f.confidence,
                "scanner_engine": f.scanner_engine,
                "description": f.description,
            }
            if f.remediation:
                item["remediation"] = f.remediation
            # Full framework alignment (OWASP/CWE/NIST + PCI/ISO/SOC/HIPAA
            # + CVSS vector + score + exploitability). Pydantic emits empty
            # lists and None for unset fields; the full dump is included so
            # downstream SIEM ingestion never has to guess at schema.
            item["framework"] = f.framework.model_dump(mode="json")
            if f.evidence:
                item["evidence_location"] = f.evidence[0].location
            findings_out.append(item)

        profile_section: dict[str, Any] = (
            {"name": profile_name} if profile_name else {}
        )

        baseline_section: dict[str, Any] = (
            {"previous_baseline_id": baseline_id} if baseline_id else {}
        )

        return {
            # --- Schema / version ---
            "report_schema_version": _REPORT_SCHEMA_VERSION,
            "webhound_version": result.scanner_version,    # kept for back-compat
            "scanner_version": result.scanner_version,
            "report_generated_at": now,                    # kept for back-compat
            "generated_at": now,
            # --- Scan provenance ---
            "scan": {
                "id": str(result.id),
                "status": result.status.value,
                "started_at": result.started_at.isoformat(),
                "completed_at": (
                    result.completed_at.isoformat() if result.completed_at else None
                ),
                "duration_seconds": result.duration_seconds,
            },
            "target": {
                "url": result.target.base_url,
                "hostname": result.target.hostname,
                "scheme": result.target.scheme,
            },
            "profile": profile_section,
            "baseline": baseline_section,
            # --- Risk summary ---
            "risk": {
                "score": risk_score,
                "level": risk_level,
                "overall_risk_score": result.overall_risk_score,
                "severity_breakdown": {
                    "critical": bd.critical,
                    "high": bd.high,
                    "medium": bd.medium,
                    "low": bd.low,
                    "info": bd.info,
                    "total": bd.total,
                    "actionable": bd.actionable,
                },
            },
            # --- Findings ---
            "grouped_findings": [
                {
                    "title": gf.title,
                    "severity": gf.severity.value,
                    "category": gf.category.value,
                    "scanner_engine": gf.scanner_engine,
                    "description": gf.description,
                    "remediation": gf.remediation,
                    "affected_url_count": gf.affected_url_count,
                    "affected_urls": gf.affected_urls,
                    "evidence_count": gf.evidence_count,
                    "confidence": gf.confidence,
                    "anomaly_score": gf.anomaly_score,
                    "framework": gf.framework.model_dump(mode="json"),
                    "finding_ids": gf.finding_ids,
                }
                for gf in result.grouped_findings
            ],
            "findings": findings_out,
            # --- Engine provenance ---
            "engines_run": result.engines_run,
            "engine_diagnostics": [
                {
                    "name": d.name,
                    "category": d.category,
                    "status": d.status.value,
                    "findings_count": d.findings_count,
                    "severity_counts": d.severity_counts,
                    "skipped_reason": d.skipped_reason,
                    "error_message": d.error_message,
                    "duration_ms": d.duration_ms,
                    "affected_target": d.affected_target,
                    "is_passive": d.is_passive,
                    "started_at": d.started_at.isoformat() if d.started_at else None,
                    "finished_at": d.finished_at.isoformat() if d.finished_at else None,
                }
                for d in result.engine_diagnostics
            ],
            # --- WADE ---
            "wade": _wade_section(result),
            # --- Crawl / infrastructure ---
            "crawl": {
                "urls_crawled": result.urls_crawled,
                "pages_analyzed": result.pages_analyzed,
                "retry_count": result.retry_count,
                "skip_count": result.skip_count,
            },
            # --- Performance telemetry ---
            "performance": ScanTelemetry.from_result(result).to_dict(),
            "errors": [
                {
                    "engine": e.engine,
                    "message": e.message,
                    "url": e.url,
                }
                for e in result.errors
            ],
            # --- Metadata ---
            "metadata": {
                "external_domains": result.metadata.get("external_domains", []),
                "external_domain_count": result.metadata.get("external_domain_count", 0),
            },
            "report_metadata": {
                "generated_at": now,
                "schema_version": _REPORT_SCHEMA_VERSION,
                "profile": profile_name,
                "previous_baseline_id": baseline_id,
                "scan_id": str(result.id),
            },
        }

    def to_json(self, result: ScanResult, *, indent: int | None = 2, **kwargs: Any) -> str:
        """Build the report and return it as a JSON string."""
        return json.dumps(self.build(result, **kwargs), indent=indent, default=str)
