from __future__ import annotations

import logging
import os
import uuid
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.finding import FindingRecord
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.scan_result import ScanResultRecord

if TYPE_CHECKING:
    from webhound.models.scan_result import ScanResult

logger = logging.getLogger(__name__)

# Per-scan cap on persisted DiscoveredUrl rows (keeps the table bounded).
_DISCOVERED_URL_ROW_CAP = 2000


def _persist_visibility_enabled() -> bool:
    """Operator opt-in for the dedicated visibility tables. OFF by default so
    deployments where migration 0043 has not run are completely unaffected —
    the report still lives in scan_results.scanner_metadata regardless."""
    return os.getenv("WEBHOUND_PERSIST_VISIBILITY", "").strip() in ("1", "true", "yes")


async def _persist_visibility_report(
    db: AsyncSession, scan_result_id: uuid.UUID, metadata: dict
) -> None:
    """Best-effort write of the visibility report + discovered URLs into the
    dedicated tables. Isolated in a SAVEPOINT so a missing table / any failure
    rolls back ONLY this section and never aborts the scan-result save."""
    report = (metadata or {}).get("visibility_report")
    if not report:
        return
    try:
        from apps.api.models.visibility_report import (
            DiscoveredUrlRecord,
            VisibilityReportRecord,
        )

        def _count(section: str) -> int:
            return int(((report.get(section) or {}).get("count", 0)) or 0)

        async with db.begin_nested():
            vr = VisibilityReportRecord(
                scan_result_id=scan_result_id,
                domain=report.get("domain"),
                crawl_mode=report.get("crawl_mode"),
                pages_found=int(report.get("pages_found", 0) or 0),
                pages_crawled=int(report.get("pages_crawled", 0) or 0),
                visibility_score=report.get("visibility_score"),
                forms_count=_count("forms"),
                api_count=_count("api"),
                js_routes_count=int(report.get("js_routes", 0) or 0),
                assets_count=_count("assets"),
                third_party_count=_count("third_party"),
                site_graph_generated=bool(report.get("site_graph_generated")),
                report=report,
                limitations=report.get("limitations") or [],
            )
            db.add(vr)
            await db.flush()
            for u in (report.get("discovered_urls") or [])[:_DISCOVERED_URL_ROW_CAP]:
                db.add(DiscoveredUrlRecord(
                    visibility_report_id=vr.id,
                    url=u.get("url") or "",
                    normalized=u.get("normalized"),
                    discovered_via=u.get("discovered_via"),
                    sources=u.get("sources"),
                    tags=u.get("tags"),
                    depth=int(u.get("depth", 0) or 0),
                    parent=u.get("parent"),
                    status=u.get("status"),
                    skip_reason=u.get("skip_reason"),
                    in_scope=bool(u.get("in_scope", True)),
                    status_code=u.get("status_code"),
                    content_type=u.get("content_type"),
                ))
    except Exception:  # noqa: BLE001 — never break the scan-result save
        logger.warning(
            "visibility report persistence skipped (table missing or write "
            "failed); report remains in scanner_metadata", exc_info=True)


async def persist_scan_result(
    db: AsyncSession,
    scan_job_id: uuid.UUID,
    result: "ScanResult",
) -> ScanResultRecord:
    """Map a scanner ScanResult into DB records and flush them."""
    risk_score: int = int(result.metadata.get("risk_score", 0))
    risk_level: str = str(result.metadata.get("risk_level", "unknown"))

    # Headline = DISTINCT issues (grouped site-wide), not the raw per-page list. The
    # same site-wide header/CSP/CORS issue fires once per crawled page; the grouped view
    # (one row + affected_url_count) is the honest count a security engineer expects. The
    # raw per-URL FindingRecords are still persisted below for the expandable detail.
    grouped = result.grouped_findings
    grouped_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for gf in grouped:
        sv = gf.severity.value
        grouped_breakdown[sv] = grouped_breakdown.get(sv, 0) + 1
    actionable_grouped = sum(1 for gf in grouped if gf.severity.value != "info")

    record = ScanResultRecord(
        scan_job_id=scan_job_id,
        scan_id=str(result.id),
        risk_score=risk_score,
        risk_level=risk_level,
        duration_seconds=result.duration_seconds,
        pages_crawled=result.urls_crawled,
        total_findings=len(grouped),            # DISTINCT issues (was raw per-page count)
        actionable_findings=actionable_grouped,  # distinct, non-info
        severity_breakdown=grouped_breakdown,    # per distinct issue (was per-page-inflated)
        scanner_metadata={
            **{k: v for k, v in result.metadata.items() if k not in ("risk_score", "risk_level")},
            # Keep the raw per-page totals available for the expandable detail view.
            "raw_findings_count": len(result.findings),
            "raw_actionable_findings": len(result.active_findings),
            "raw_severity_breakdown": result.severity_breakdown.model_dump(),
        },
    )
    db.add(record)
    await db.flush()

    for f in result.findings:
        affected_url = f.evidence[0].location if f.evidence else None
        db.add(
            FindingRecord(
                scan_result_id=record.id,
                scanner_finding_id=str(f.id),
                title=f.title,
                severity=f.severity.value,
                category=f.category.value,
                scanner_engine=f.scanner_engine,
                affected_url=affected_url,
                confidence=f.confidence,
                description=f.description,
                remediation=f.remediation,
                evidence=[e.model_dump(mode="json") for e in f.evidence],
                framework=f.framework.model_dump(mode="json"),
            )
        )

    for gf in result.grouped_findings:
        db.add(
            GroupedFindingRecord(
                scan_result_id=record.id,
                title=gf.title,
                severity=gf.severity.value,
                category=gf.category.value,
                scanner_engine=gf.scanner_engine,
                affected_url_count=gf.affected_url_count,
                affected_urls=gf.affected_urls,
                evidence_count=gf.evidence_count,
                confidence=gf.confidence,
                description=gf.description,
                remediation=gf.remediation,
                framework=gf.framework.model_dump(mode="json"),
                finding_ids=gf.finding_ids,
            )
        )

    for diag in result.engine_diagnostics:
        db.add(
            EngineDiagnosticRecord(
                scan_result_id=record.id,
                engine_name=diag.name,
                category=diag.category,
                status=diag.status.value,
                findings_count=diag.findings_count,
                severity_counts=diag.severity_counts,
                duration_ms=diag.duration_ms,
                skipped_reason=diag.skipped_reason,
                error_message=diag.error_message,
            )
        )

    # Dedicated visibility tables — opt-in (operator sets WEBHOUND_PERSIST_
    # VISIBILITY=1 after migration 0043 is applied). Savepoint-isolated so it
    # can never break the scan-result save; the report is in scanner_metadata
    # regardless.
    if _persist_visibility_enabled():
        await _persist_visibility_report(db, record.id, result.metadata)

    await db.flush()
    await db.refresh(record)
    return record
