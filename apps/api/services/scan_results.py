from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.finding import FindingRecord
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.report import ReportRecord
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.website import Website

# Severity rank for ORDER BY (critical first)
_SEVERITY_RANK = sa.case(
    {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
    value=GroupedFindingRecord.severity,
    else_=5,
)


async def get_scan_result(
    db: AsyncSession,
    scan_result_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> ScanResultRecord | None:
    if user_id is None:
        return await db.get(ScanResultRecord, scan_result_id)
    return await db.scalar(
        sa.select(ScanResultRecord)
        .join(ScanJob, ScanResultRecord.scan_job_id == ScanJob.id)
        .join(Website, ScanJob.website_id == Website.id)
        .where(ScanResultRecord.id == scan_result_id, Website.user_id == user_id)
    )


async def get_scan_result_detail(
    db: AsyncSession,
    scan_result_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> ScanResultRecord | None:
    stmt = (
        sa.select(ScanResultRecord)
        .where(ScanResultRecord.id == scan_result_id)
        .options(
            selectinload(ScanResultRecord.scan_job).selectinload(ScanJob.website)
        )
    )
    if user_id is not None:
        stmt = (
            stmt.join(ScanJob, ScanResultRecord.scan_job_id == ScanJob.id)
            .join(Website, ScanJob.website_id == Website.id)
            .where(Website.user_id == user_id)
        )
    return await db.scalar(stmt)


async def list_scan_results(
    db: AsyncSession,
    *,
    limit: int = 20,
    offset: int = 0,
    website_id: uuid.UUID | None = None,
    scan_job_id: uuid.UUID | None = None,
    risk_level: str | None = None,
    min_risk_score: int | None = None,
    max_risk_score: int | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    user_id: uuid.UUID | None = None,
    active_org_id: uuid.UUID | None = None,
) -> tuple[list[ScanResultRecord], int]:
    from apps.api.services.tenant import apply_org_scope

    base = sa.select(ScanResultRecord).options(
        selectinload(ScanResultRecord.scan_job).selectinload(ScanJob.website)
    )
    count_base = sa.select(sa.func.count()).select_from(ScanResultRecord)

    if user_id is not None or website_id is not None or active_org_id is not None:
        base = base.join(ScanJob, ScanResultRecord.scan_job_id == ScanJob.id)
        count_base = count_base.join(
            ScanJob, ScanResultRecord.scan_job_id == ScanJob.id
        )

    # Phase-4 tenancy scope on the parent ScanJob.org_id.
    if active_org_id is not None:
        base = apply_org_scope(base, ScanJob.org_id, active_org_id)
        count_base = apply_org_scope(count_base, ScanJob.org_id, active_org_id)

    if user_id is not None:
        base = base.join(Website, ScanJob.website_id == Website.id).where(
            Website.user_id == user_id
        )
        count_base = count_base.join(
            Website, ScanJob.website_id == Website.id
        ).where(Website.user_id == user_id)

    if website_id is not None:
        base = base.where(ScanJob.website_id == website_id)
        count_base = count_base.where(ScanJob.website_id == website_id)

    if scan_job_id is not None:
        base = base.where(ScanResultRecord.scan_job_id == scan_job_id)
        count_base = count_base.where(ScanResultRecord.scan_job_id == scan_job_id)

    if risk_level is not None:
        base = base.where(ScanResultRecord.risk_level == risk_level)
        count_base = count_base.where(ScanResultRecord.risk_level == risk_level)

    if min_risk_score is not None:
        base = base.where(ScanResultRecord.risk_score >= min_risk_score)
        count_base = count_base.where(ScanResultRecord.risk_score >= min_risk_score)

    if max_risk_score is not None:
        base = base.where(ScanResultRecord.risk_score <= max_risk_score)
        count_base = count_base.where(ScanResultRecord.risk_score <= max_risk_score)

    if created_from is not None:
        base = base.where(ScanResultRecord.created_at >= created_from)
        count_base = count_base.where(ScanResultRecord.created_at >= created_from)

    if created_to is not None:
        base = base.where(ScanResultRecord.created_at <= created_to)
        count_base = count_base.where(ScanResultRecord.created_at <= created_to)

    total: int = (await db.scalar(count_base)) or 0
    rows = await db.scalars(
        base.order_by(ScanResultRecord.created_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), total


async def get_grouped_finding_detail(
    db: AsyncSession,
    scan_result_id: uuid.UUID,
    grouped_finding_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> tuple[GroupedFindingRecord, list[FindingRecord]] | None:
    if await get_scan_result(db, scan_result_id, user_id=user_id) is None:
        return None
    gf = await db.scalar(
        sa.select(GroupedFindingRecord).where(
            GroupedFindingRecord.id == grouped_finding_id,
            GroupedFindingRecord.scan_result_id == scan_result_id,
        )
    )
    if gf is None:
        return None

    sample_findings: list[FindingRecord] = []
    raw_ids = gf.finding_ids or []
    if raw_ids:
        try:
            ids = [uuid.UUID(fid) for fid in raw_ids[:8]]
            rows = await db.scalars(
                sa.select(FindingRecord)
                .where(FindingRecord.id.in_(ids))
                .limit(8)
            )
            sample_findings = list(rows.all())
        except (ValueError, AttributeError):
            pass

    return gf, sample_findings


async def list_grouped_findings(
    db: AsyncSession,
    scan_result_id: uuid.UUID,
    *,
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    category: str | None = None,
    scanner_engine: str | None = None,
    min_confidence: float | None = None,
) -> tuple[list[GroupedFindingRecord], int]:
    base = sa.select(GroupedFindingRecord).where(
        GroupedFindingRecord.scan_result_id == scan_result_id
    )
    count_base = (
        sa.select(sa.func.count())
        .select_from(GroupedFindingRecord)
        .where(GroupedFindingRecord.scan_result_id == scan_result_id)
    )

    if severity is not None:
        base = base.where(GroupedFindingRecord.severity == severity)
        count_base = count_base.where(GroupedFindingRecord.severity == severity)

    if category is not None:
        base = base.where(GroupedFindingRecord.category == category)
        count_base = count_base.where(GroupedFindingRecord.category == category)

    if scanner_engine is not None:
        base = base.where(GroupedFindingRecord.scanner_engine == scanner_engine)
        count_base = count_base.where(
            GroupedFindingRecord.scanner_engine == scanner_engine
        )

    if min_confidence is not None:
        base = base.where(GroupedFindingRecord.confidence >= min_confidence)
        count_base = count_base.where(GroupedFindingRecord.confidence >= min_confidence)

    total: int = (await db.scalar(count_base)) or 0
    rows = await db.scalars(
        base.order_by(_SEVERITY_RANK, GroupedFindingRecord.affected_url_count.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(rows.all()), total


async def list_findings(
    db: AsyncSession,
    scan_result_id: uuid.UUID,
    *,
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    category: str | None = None,
    scanner_engine: str | None = None,
    affected_url: str | None = None,
    min_confidence: float | None = None,
) -> tuple[list[FindingRecord], int]:
    base = sa.select(FindingRecord).where(
        FindingRecord.scan_result_id == scan_result_id
    )
    count_base = (
        sa.select(sa.func.count())
        .select_from(FindingRecord)
        .where(FindingRecord.scan_result_id == scan_result_id)
    )

    if severity is not None:
        base = base.where(FindingRecord.severity == severity)
        count_base = count_base.where(FindingRecord.severity == severity)

    if category is not None:
        base = base.where(FindingRecord.category == category)
        count_base = count_base.where(FindingRecord.category == category)

    if scanner_engine is not None:
        base = base.where(FindingRecord.scanner_engine == scanner_engine)
        count_base = count_base.where(FindingRecord.scanner_engine == scanner_engine)

    if affected_url is not None:
        base = base.where(FindingRecord.affected_url.contains(affected_url))
        count_base = count_base.where(FindingRecord.affected_url.contains(affected_url))

    if min_confidence is not None:
        base = base.where(FindingRecord.confidence >= min_confidence)
        count_base = count_base.where(FindingRecord.confidence >= min_confidence)

    total: int = (await db.scalar(count_base)) or 0
    rows = await db.scalars(
        base.order_by(FindingRecord.created_at.asc()).limit(limit).offset(offset)
    )
    return list(rows.all()), total


async def list_engine_diagnostics(
    db: AsyncSession,
    scan_result_id: uuid.UUID,
    *,
    status: str | None = None,
    category: str | None = None,
    engine_name: str | None = None,
) -> list[EngineDiagnosticRecord]:
    base = sa.select(EngineDiagnosticRecord).where(
        EngineDiagnosticRecord.scan_result_id == scan_result_id
    )

    if status is not None:
        base = base.where(EngineDiagnosticRecord.status == status)

    if category is not None:
        base = base.where(EngineDiagnosticRecord.category == category)

    if engine_name is not None:
        base = base.where(EngineDiagnosticRecord.engine_name == engine_name)

    rows = await db.scalars(base.order_by(EngineDiagnosticRecord.engine_name.asc()))
    return list(rows.all())


async def list_reports(
    db: AsyncSession, scan_result_id: uuid.UUID
) -> list[ReportRecord]:
    rows = await db.scalars(
        sa.select(ReportRecord)
        .where(ReportRecord.scan_result_id == scan_result_id)
        .order_by(ReportRecord.format.asc())
    )
    return list(rows.all())


async def get_report_by_format(
    db: AsyncSession, scan_result_id: uuid.UUID, fmt: str
) -> ReportRecord | None:
    return await db.scalar(
        sa.select(ReportRecord).where(
            ReportRecord.scan_result_id == scan_result_id,
            ReportRecord.format == fmt,
        )
    )
