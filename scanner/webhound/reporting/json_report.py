# WebHound — scanner/webhound/reporting/json_report.py
# Structured JSON report builder for completed scan results.

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from webhound.models.scan_result import ScanResult


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

    Usage::

        report = JsonReport()
        data = report.build(result)          # dict
        json_str = report.to_json(result)    # pretty-printed JSON string
    """

    def build(self, result: ScanResult) -> dict[str, Any]:
        """Build and return the full report as a plain Python dict."""
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
            if f.framework.owasp_top10:
                item["owasp_top10"] = f.framework.owasp_top10
            if f.framework.cwe_ids:
                item["cwe_ids"] = f.framework.cwe_ids
            if f.evidence:
                item["evidence_location"] = f.evidence[0].location
            findings_out.append(item)

        return {
            "webhound_version": result.scanner_version,
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
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
            "findings": findings_out,
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
            "wade": _wade_section(result),
            "crawl": {
                "urls_crawled": result.urls_crawled,
                "pages_analyzed": result.pages_analyzed,
            },
            "errors": [
                {
                    "engine": e.engine,
                    "message": e.message,
                    "url": e.url,
                }
                for e in result.errors
            ],
            "metadata": {
                "external_domains": result.metadata.get("external_domains", []),
                "external_domain_count": result.metadata.get("external_domain_count", 0),
            },
        }

    def to_json(self, result: ScanResult, *, indent: int | None = 2) -> str:
        """Build the report and return it as a JSON string."""
        return json.dumps(self.build(result), indent=indent, default=str)
