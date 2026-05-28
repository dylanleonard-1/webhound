# WebHound — apps/api/services/infra_metrics.py
# Infrastructure trend storage. The worker beat task `sample_infra` writes
# one row every 5 min so /control can render history charts.

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.infrastructure_sample import InfrastructureSample


async def store_sample(
    db: AsyncSession, *,
    queue_depth: int | None,
    worker_alive: bool,
    worker_heartbeat_age_s: float | None,
    redis_used_memory_mb: float | None,
    active_scans: int | None,
) -> InfrastructureSample:
    row = InfrastructureSample(
        taken_at=datetime.now(timezone.utc),
        queue_depth=queue_depth,
        worker_alive=worker_alive,
        worker_heartbeat_age_s=worker_heartbeat_age_s,
        redis_used_memory_mb=redis_used_memory_mb,
        active_scans=active_scans,
    )
    db.add(row)
    await db.flush()
    return row


async def history(db: AsyncSession, hours: int = 24,
                  limit: int = 600) -> list[dict]:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = await db.scalars(
        select(InfrastructureSample)
        .where(InfrastructureSample.taken_at >= since)
        .order_by(InfrastructureSample.taken_at).limit(limit)
    )
    return [
        {
            "taken_at": r.taken_at.isoformat() if r.taken_at else None,
            "queue_depth": r.queue_depth,
            "worker_alive": r.worker_alive,
            "worker_heartbeat_age_s": r.worker_heartbeat_age_s,
            "redis_used_memory_mb": r.redis_used_memory_mb,
            "active_scans": r.active_scans,
        }
        for r in rows.all()
    ]


async def prune_older_than(db: AsyncSession, days: int = 30) -> int:
    """Keep the table from growing forever — the worker can call this nightly
    or once a week. Returns the number of rows deleted."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        sa.delete(InfrastructureSample).where(InfrastructureSample.taken_at < cutoff)
    )
    return int(result.rowcount or 0)
