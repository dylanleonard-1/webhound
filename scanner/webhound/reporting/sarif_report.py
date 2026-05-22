# WebHound — scanner/webhound/reporting/sarif_report.py
# SARIF 2.1.0 report builder for integration with code-scanning workflows.
#
# SARIF (Static Analysis Results Interchange Format) is an OASIS standard
# designed to allow static-analysis tools to share results with development
# environments, CI/CD pipelines, and security dashboards.
#
# Schema reference:
#   https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
#
# Design decisions:
#   - One SARIF result per (grouped_finding × affected_url) so each page
#     occurrence is independently addressable in GitHub code-scanning style.
#   - Falls back to raw active findings when no grouped findings exist.
#   - Rule IDs are human-readable: "{engine}/{title-slug}".
#   - Severity → SARIF level: CRITICAL/HIGH → error, MEDIUM → warning,
#     LOW → note, INFO → none.

from __future__ import annotations

import re
from typing import Any

from webhound.models.finding import Finding
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
_SARIF_VERSION = "2.1.0"

_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}


def _rule_id(engine: str, title: str) -> str:
    """Build a human-readable, stable ruleId from engine name and title."""
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:60]
    return f"{engine}/{slug}"


def _pascal(title: str) -> str:
    """Convert a finding title to PascalCase for SARIF rule names."""
    return "".join(word.capitalize() for word in re.split(r"[\s_\-/]+", title) if word)


def _location(url: str) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": url},
            "region": {"startLine": 1},
        }
    }


def _rule_from_grouped(rule_id: str, gf: GroupedFinding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": _pascal(gf.title),
        "shortDescription": {"text": gf.title},
        "fullDescription": {"text": gf.description},
        "properties": {
            "category": gf.category.value,
            "tags": ["security", gf.category.value],
        },
    }
    if gf.remediation:
        rule["help"] = {"text": gf.remediation, "markdown": gf.remediation}
    return rule


def _rule_from_finding(rule_id: str, f: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": _pascal(f.title),
        "shortDescription": {"text": f.title},
        "fullDescription": {"text": f.description},
        "properties": {
            "category": f.category.value,
            "tags": ["security", f.category.value],
        },
    }
    if f.remediation:
        rule["help"] = {"text": f.remediation, "markdown": f.remediation}
    return rule


def _result_from_grouped(
    rule_id: str, gf: GroupedFinding, url: str
) -> dict[str, Any]:
    level = _SARIF_LEVEL.get(gf.severity.value.lower(), "warning")
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": gf.description},
        "locations": [_location(url)],
        "properties": {
            "severity": gf.severity.value,
            "category": gf.category.value,
            "confidence": gf.confidence,
            "engine": gf.scanner_engine,
            "owasp_top10": gf.framework.owasp_top10,
            "cwe_ids": gf.framework.cwe_ids,
            "evidence_count": gf.evidence_count,
            "affected_url_count": gf.affected_url_count,
        },
    }


def _result_from_finding(rule_id: str, f: Finding, url: str) -> dict[str, Any]:
    level = _SARIF_LEVEL.get(f.severity.value.lower(), "warning")
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": f.description},
        "locations": [_location(url)],
        "properties": {
            "severity": f.severity.value,
            "category": f.category.value,
            "confidence": f.confidence,
            "engine": f.scanner_engine,
            "owasp_top10": f.framework.owasp_top10,
            "cwe_ids": f.framework.cwe_ids,
            "evidence_count": f.evidence_count,
        },
    }


class SarifReport:
    """Serialises a completed ScanResult into a SARIF 2.1.0 compatible dict.

    Usage::

        report = SarifReport()
        data = report.build(result)
        json_str = report.to_json(result)
    """

    def build(
        self,
        result: ScanResult,
        *,
        profile_name: str | None = None,
    ) -> dict[str, Any]:
        """Build and return the full SARIF report as a plain Python dict."""
        rules: dict[str, dict[str, Any]] = {}
        sarif_results: list[dict[str, Any]] = []

        if result.grouped_findings:
            for gf in result.grouped_findings:
                rid = _rule_id(gf.scanner_engine, gf.title)
                if rid not in rules:
                    rules[rid] = _rule_from_grouped(rid, gf)
                urls = gf.affected_urls if gf.affected_urls else [result.target.base_url]
                for url in urls:
                    sarif_results.append(_result_from_grouped(rid, gf, url))
        else:
            for f in result.active_findings:
                rid = _rule_id(f.scanner_engine, f.title)
                if rid not in rules:
                    rules[rid] = _rule_from_finding(rid, f)
                url = f.evidence[0].location if f.evidence else result.target.base_url
                sarif_results.append(_result_from_finding(rid, f, url))

        run_properties: dict[str, Any] = {
            "target": result.target.base_url,
            "risk_score": result.metadata.get("risk_score"),
            "risk_level": result.metadata.get("risk_level"),
            "scan_id": str(result.id),
        }
        if profile_name:
            run_properties["profile"] = profile_name

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "WebHound",
                            "version": result.scanner_version,
                            "informationUri": "https://webhoundsecurity.com",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": sarif_results,
                    "properties": run_properties,
                }
            ],
        }

    def to_json(self, result: ScanResult, *, indent: int | None = 2, **kwargs: Any) -> str:
        import json
        return json.dumps(self.build(result, **kwargs), indent=indent, default=str)
