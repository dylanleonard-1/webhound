from __future__ import annotations

import asyncio
import logging
import os

from worker.celery_app import celery

logger = logging.getLogger(__name__)


@celery.task(name="worker.monitoring_tasks.heartbeat")
def heartbeat() -> dict:
    """Periodic liveness ping — scheduled via celery beat in a future phase."""
    logger.debug("worker heartbeat")
    return {"status": "alive"}


@celery.task(name="worker.monitoring_tasks.dispatch_scheduled_scans")
def dispatch_scheduled_scans() -> dict:
    """Find all due scan schedules, create ScanJobs, and enqueue scan tasks."""
    try:
        result = asyncio.run(_dispatch())
        return result
    except Exception:
        logger.exception("dispatch_scheduled_scans failed")
        raise


async def _dispatch() -> dict:
    from datetime import datetime, timezone

    import apps.api.models  # noqa: F401 — register all models
    from apps.api.services.scan_schedules import dispatch_due_schedules
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from worker.scan_tasks import run_scan

    db_url = os.environ["DATABASE_URL"]
    engine = create_async_engine(db_url)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    now = datetime.now(timezone.utc)
    try:
        async with factory() as db:
            job_ids = await dispatch_due_schedules(db, now=now)
            await db.commit()
    finally:
        await engine.dispose()

    for job_id in job_ids:
        try:
            run_scan.delay(str(job_id), "", "standard")
        except Exception:
            logger.warning("failed to enqueue scan task for job %s", job_id)

    logger.info("dispatched %d scheduled scans", len(job_ids))
    return {"dispatched": len(job_ids), "job_ids": [str(j) for j in job_ids]}
