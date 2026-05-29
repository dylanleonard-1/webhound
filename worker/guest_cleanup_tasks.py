# WebHound — worker/guest_cleanup_tasks.py
# Slice 4.A follow-up — R2 mitigation. Daily GC of guest scans
# older than 24 hours that haven't been claimed.
#
# A guest scan is identified by ScanJob.guest_token NOT NULL AND
# Website.user_id IS NULL. Once a visitor claims the scan
# (Slice 4.C), Website.user_id is set and the GC leaves it alone.
#
# Safe-by-design:
#   * Only deletes Website rows whose user_id IS NULL (never
#     touches authenticated customers' data).
#   * Only deletes when ScanJob.created_at > 24h ago.
#   * Cascade deletes follow the existing ScanJob ON DELETE rules.

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa

from worker.celery_app import celery
from worker._db import get_async_db_url

logger = logging.getLogger(__name__)


_RETENTION_HOURS = int(os.getenv("WEBHOUND_GUEST_RETENTION_HOURS", "24"))


@celery.task(name="worker.guest_cleanup_tasks.cleanup_expired_guest_scans")
def cleanup_expired_guest_scans() -> dict:
    """Daily entry point — runs via the Celery beat schedule."""
    return asyncio.run(_cleanup())


async def _cleanup() -> dict:
    import apps.api.models  # noqa: F401 — registers all models

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from apps.api.models.scan_job import ScanJob
    from apps.api.models.website import Website

    cutoff = datetime.now(timezone.utc) - timedelta(hours=_RETENTION_HOURS)
    engine = create_async_engine(get_async_db_url(), pool_pre_ping=True)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    deleted_websites = 0
    try:
        async with factory() as db:
            # Candidate websites: user_id IS NULL AND there exists a
            # scan_job tied to it with guest_token NOT NULL AND
            # created_at < cutoff. We delete via the Website row;
            # the scan_job cascades by FK ON DELETE CASCADE.
            stmt = sa.select(Website.id).join(
                ScanJob, ScanJob.website_id == Website.id,
            ).where(
                Website.user_id.is_(None),
                ScanJob.guest_token.is_not(None),
                ScanJob.created_at < cutoff,
            ).distinct()
            rows = (await db.execute(stmt)).scalars().all()
            for wid in rows:
                site = await db.get(Website, wid)
                if site is None or site.user_id is not None:
                    continue
                await db.delete(site)
                deleted_websites += 1
            await db.commit()
    finally:
        await engine.dispose()

    logger.info(
        "guest cleanup: deleted %s websites older than %sh",
        deleted_websites, _RETENTION_HOURS,
    )
    return {
        "deleted_websites": deleted_websites,
        "cutoff": cutoff.isoformat(),
        "retention_hours": _RETENTION_HOURS,
    }
