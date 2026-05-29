# WebHound — scanner/webhound/reporting/json_report.py
# Structured JSON report builder for completed scan results.
#
# Schema version history:
#   v1 — initial structured report
#   v2 — added report_schema_version, scanner_version, profile, baseline_metadata,
#         generated_at alias, report_metadata section
#   v3 — added per-finding tags, quality_label, finding id, and
#         metadata.corroborated_by; added top-level correlated_chains
#         section listing every threat-chain cluster + its constituents
#   v4 — added top-level compliance rollup (controls_impacted vs
#         findings_mapped vs advisory_controls vs confirmed_violations
#         per framework), evidence_graph (nodes + edges with stable
#         content-addressed ids), and asset_map carry-through (set by
#         the orchestrator's ASM pass on the ENTERPRISE profile)

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from webhound.core.performance import ScanTelemetry
from webhound.models.scan_result import ScanResult

_REPORT_SCHEMA_VERSION = 4

# Engine name used by the post-engine correlation pass (see
# webhound/core/correlation.py). Findings with this engine are threat-chain
# *cluster* findings — they aggregate multiple per-engine signals into one
# corroborated story rather than describing a single observation.
_CORRELATION_ENGINE = "correlation"


def _compliance_section(result: ScanResult) -> dict[str, Any]:
    """Phase-3 reformed compliance rollup — separates controls
    impacted from findings mapped from confirmed violations."""
    # Lazy import keeps json_report importable when reporting/
    # is being introspected during package init.
    from webhound.reporting.compliance import build_compliance_rollup
    return build_compliance_rollup(result).to_dict()


def _evidence_graph_section(result: ScanResult) -> dict[str, Any]:
    """Phase-3 evidence graph."""
    from webhound.reporting.evidence_graph import build_evidence_graph
    return build_evidence_graph(result).to_dict()


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
        correlated_chains: list[dict[str, Any]] = []
        for f in result.active_findings:
            item: dict[str, Any] = {
                "id": str(f.id),
                "title": f.title,
                "severity": f.severity.value,
                "category": f.category.value,
                "confidence": f.confidence,
                # quality_label is severity+confidence+tags collapsed into one
                # qualitative string the dashboard renders next to the finding
                # ("confirmed" / "likely" / "heuristic" / "advisory" /
                # "informational"). Exposed so SIEM ingestion / external
                # consumers don't have to re-derive the mapping.
                "quality_label": f.quality_label,
                "scanner_engine": f.scanner_engine,
                "description": f.description,
                # Tags drive the dashboard's filter chips and "corroborated"
                # badge — always emit, even when empty, so consumers can rely
                # on the field's presence.
                "tags": list(f.tags or []),
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

            # Correlation transparency: when the post-engine correlation
            # pass raised this finding's confidence, expose *which* chain(s)
            # corroborated it. UI can render "Strengthened by:
            # supply_chain_compromise_risk" next to the confidence figure.
            corroborated_by = (f.metadata or {}).get("corroborated_by") or []
            if corroborated_by:
                item["corroborated_by"] = list(corroborated_by)

            # Cluster findings emitted by the correlation pass get their own
            # transparency block + are also recorded in a top-level
            # `correlated_chains` array for clients that want to render a
            # dedicated "Threat chains" panel rather than walking every
            # finding looking for engine="correlation".
            if f.scanner_engine == _CORRELATION_ENGINE:
                chain_name = (f.metadata or {}).get("chain_name")
                constituents = (f.metadata or {}).get("constituents") or []
                constituent_ids = (
                    (f.metadata or {}).get("constituent_finding_ids") or []
                )
                item["chain_name"] = chain_name
                item["constituent_finding_ids"] = list(constituent_ids)
                item["constituents"] = list(constituents)
                correlated_chains.append({
                    "chain_name": chain_name,
                    "cluster_finding_id": str(f.id),
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "signal_count": (f.metadata or {}).get("signal_count")
                                     or len(constituents),
                    "constituent_finding_ids": list(constituent_ids),
                    "constituents": list(constituents),
                    "remediation": f.remediation,
                })

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
            # --- Cross-engine correlation ---
            # One entry per threat-chain cluster the correlation pass
            # produced this scan. Empty when no chains fired. Each entry
            # holds the chain name, cluster confidence/severity, and the
            # IDs of the per-engine findings that corroborated it — so
            # consumers can render a dedicated "Threat chains" panel that
            # backlinks into the findings list.
            "correlated_chains": correlated_chains,
            # --- ASM-lite asset discovery (Phase-4) ---
            # Present only when the active scan profile had asm_enabled.
            # When the ENTERPRISE profile ran a discovery pass, the
            # orchestrator stores the asset map under
            # ``metadata.asset_map``; surface it here verbatim so the
            # dashboard can render the attack-surface panel without
            # rummaging through scan_metadata.
            "asset_map": result.metadata.get("asset_map"),
            # Phase-5C threat-intel coverage report — None when the
            # orchestrator skipped the audit (zero hosts in inventory).
            "threat_intel_coverage": result.metadata.get(
                "threat_intel_coverage",
            ),
            # Phase-5A browser-pass summary — None when the profile
            # didn't opt in.
            "browser_pass": result.metadata.get("browser_pass"),
            # Phase-5D evidence-quality audit report. None when the
            # orchestrator skipped the audit. Consumed by the
            # dashboard's "evidence complete" badges + the
            # production-readiness score.
            "evidence_quality": result.metadata.get("evidence_quality"),
            # --- Compliance rollup (Phase-3 reform) ---
            # Structured breakdown: per-framework controls_impacted vs
            # findings_mapped vs advisory_controls vs confirmed_violations
            # so the dashboard can render a posture grid that doesn't
            # conflate "30 low-confidence advisory findings touching a
            # control" with "1 confirmed violation against the same
            # control". See reporting/compliance.py for the rules.
            "compliance": _compliance_section(result),
            # --- Evidence graph (Phase-3) ---
            # Stable, content-addressed graph of scan→engine→finding→
            # evidence→page (+ corroboration edges + asset host nodes).
            # Designed so the dashboard can render a network or
            # explorer view without recomputing relationships per
            # request.
            "evidence_graph": _evidence_graph_section(result),
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
