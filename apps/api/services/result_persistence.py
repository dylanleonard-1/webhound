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

    record = ScanResultRecord(
        scan_job_id=scan_job_id,
        scan_id=str(result.id),
        risk_score=risk_score,
        risk_level=risk_level,
        duration_seconds=result.duration_seconds,
        pages_crawled=result.urls_crawled,
        total_findings=len(result.findings),
        actionable_findings=len(result.active_findings),
        severity_breakdown=result.severity_breakdown.model_dump(),
        scanner_metadata={
            k: v
            for k, v in result.metadata.items()
            if k not in ("risk_score", "risk_level")
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
