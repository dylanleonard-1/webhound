from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from apps.api.models.baseline import BaselineRecord
from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.grouped_finding import GroupedFindingRecord
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.website import Website


async def website_exists(
    db: AsyncSession, website_id: uuid.UUID, user_id: uuid.UUID | None = None
) -> bool:
    if user_id is None:
        return await db.get(Website, website_id) is not None
    row = await db.scalar(
        sa.select(Website).where(
            Website.id == website_id, Website.user_id == user_id
        )
    )
    return row is not None


async def list_baselines(
    db: AsyncSession,
    website_id: uuid.UUID,
    *,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[BaselineRecord], int]:
    base = sa.select(BaselineRecord).where(BaselineRecord.website_id == website_id)
    count_base = (
        sa.select(sa.func.count())
        .select_from(BaselineRecord)
        .where(BaselineRecord.website_id == website_id)
    )
    total: int = (await db.scalar(count_base)) or 0
    rows = await db.scalars(
        base.order_by(BaselineRecord.created_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), total


async def get_latest_baseline(
    db: AsyncSession, website_id: uuid.UUID
) -> BaselineRecord | None:
    return await db.scalar(
        sa.select(BaselineRecord)
        .where(BaselineRecord.website_id == website_id)
        .order_by(BaselineRecord.created_at.desc())
        .limit(1)
    )


async def get_baseline(
    db: AsyncSession,
    baseline_record_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> BaselineRecord | None:
    if user_id is None:
        return await db.get(BaselineRecord, baseline_record_id)
    return await db.scalar(
        sa.select(BaselineRecord)
        .join(Website, BaselineRecord.website_id == Website.id)
        .where(
            BaselineRecord.id == baseline_record_id, Website.user_id == user_id
        )
    )


async def delete_baseline(
    db: AsyncSession,
    baseline_record_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> bool:
    record = await get_baseline(db, baseline_record_id, user_id)
    if record is None:
        return False
    await db.delete(record)
    return True


async def get_wade_data(
    db: AsyncSession,
    scan_result_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> tuple[
    ScanResultRecord | None,
    list[GroupedFindingRecord],
    EngineDiagnosticRecord | None,
]:
    """Return (scan_result, wade_grouped_findings, wade_diagnostic)."""
    if user_id is None:
        sr = await db.get(ScanResultRecord, scan_result_id)
    else:
        sr = await db.scalar(
            sa.select(ScanResultRecord)
            .join(ScanJob, ScanResultRecord.scan_job_id == ScanJob.id)
            .join(Website, ScanJob.website_id == Website.id)
            .where(
                ScanResultRecord.id == scan_result_id, Website.user_id == user_id
            )
        )
    if sr is None:
        return None, [], None

    wade_findings = list(
        (
            await db.scalars(
                sa.select(GroupedFindingRecord)
                .where(
                    GroupedFindingRecord.scan_result_id == scan_result_id,
                    GroupedFindingRecord.scanner_engine == "wade",
                )
                .order_by(GroupedFindingRecord.affected_url_count.desc())
            )
        ).all()
    )

    wade_diag = await db.scalar(
        sa.select(EngineDiagnosticRecord).where(
            EngineDiagnosticRecord.scan_result_id == scan_result_id,
            EngineDiagnosticRecord.engine_name == "wade",
        )
    )

    return sr, wade_findings, wade_diag


async def get_wade_history(
    db: AsyncSession,
    website_id: uuid.UUID,
    *,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[ScanResultRecord], int]:
    base = (
        sa.select(ScanResultRecord)
        .join(ScanJob, ScanResultRecord.scan_job_id == ScanJob.id)
        .where(ScanJob.website_id == website_id)
        .options(selectinload(ScanResultRecord.grouped_findings))
    )
    count_base = (
        sa.select(sa.func.count())
        .select_from(ScanResultRecord)
        .join(ScanJob, ScanResultRecord.scan_job_id == ScanJob.id)
        .where(ScanJob.website_id == website_id)
    )
    total: int = (await db.scalar(count_base)) or 0
    rows = await db.scalars(
        base.order_by(ScanResultRecord.created_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), total
