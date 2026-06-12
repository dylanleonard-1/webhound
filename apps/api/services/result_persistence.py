from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.finding import FindingRecord
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.scan_result import ScanResultRecord

if TYPE_CHECKING:
    from webhound.models.scan_result import ScanResult


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

    await db.flush()
    await db.refresh(record)
    return record
