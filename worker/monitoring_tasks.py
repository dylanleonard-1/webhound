from __future__ import annotations

import asyncio
import logging

from worker._db import get_async_db_url
from worker.celery_app import celery

logger = logging.getLogger(__name__)


@celery.task(name="worker.monitoring_tasks.heartbeat")
def heartbeat() -> dict:
    """Periodic liveness ping — fires every 5 min via celery beat.

    Stamps a Redis key the command center reads to report worker liveness
    (key age < 10 min => "ok", else "stale"). Best-effort; never fails the task.
    """
    logger.debug("worker heartbeat")
    try:
        import os
        import time
        import redis as _redis
        client = _redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        client.set("webhound:worker:heartbeat", str(time.time()), ex=900)
    except Exception:  # noqa: BLE001
        pass
    return {"status": "alive"}


@celery.task(name="worker.monitoring_tasks.dispatch_scheduled_scans")
def dispatch_scheduled_scans() -> dict:
    """Find all due scan schedules, create ScanJobs, and enqueue scan tasks.

    Triggered every minute by celery beat. Returns a summary suitable for
    logging / metrics.
    """
    try:
        return asyncio.run(_dispatch())
    except Exception:
        logger.exception("dispatch_scheduled_scans failed")
        raise


async def _dispatch() -> dict:
    from datetime import datetime, timezone

    import apps.api.models  # noqa: F401 — register all models
    from apps.api.services.scan_schedules import dispatch_due_schedules
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from worker.scan_tasks import run_scan

    engine = create_async_engine(get_async_db_url())
    factory = async_sessionmaker(engine, expire_on_commit=False)

    now = datetime.now(timezone.utc)
    try:
        async with factory() as db:
            dispatched = await dispatch_due_schedules(db, now=now)
            await db.commit()
    finally:
        await engine.dispose()

    enqueued = 0
    for entry in dispatched:
        try:
            run_scan.delay(entry["job_id"], entry["url"], entry["profile"])
            enqueued += 1
        except Exception:
            logger.warning(
                "failed to enqueue scan task for job %s (%s)",
                entry["job_id"], entry["url"],
            )

    if dispatched:
        logger.info(
            "scheduled scans: dispatched=%d enqueued=%d",
            len(dispatched), enqueued,
        )
    return {
        "dispatched": len(dispatched),
        "enqueued": enqueued,
        "jobs": [d["job_id"] for d in dispatched],
    }
