from __future__ import annotations

import asyncio
import logging
import os
import time

from worker._db import get_async_db_url
from worker.celery_app import celery

logger = logging.getLogger(__name__)


@celery.task(name="worker.infra_tasks.sample_infra")
def sample_infra() -> dict:
    """Snapshot operational metrics. Fires every 5 min via beat."""
    try:
        return asyncio.run(_sample())
    except Exception:
        logger.exception("sample_infra failed")
        raise


async def _sample() -> dict:
    import apps.api.models  # noqa: F401 — register models
    from sqlalchemy import select, func
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from apps.api.models.enums import ScanStatus
    from apps.api.models.scan_job import ScanJob
    from apps.api.services import infra_metrics as infra_svc

    queue_depth: int | None = None
    worker_alive = False
    hb_age: float | None = None
    redis_mem: float | None = None
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"),
                              socket_connect_timeout=2, decode_responses=True)
        try:
            await r.ping()
            queue_depth = int(await r.llen("celery"))
            hb = await r.get("webhound:worker:heartbeat")
            if hb:
                hb_age = max(0.0, time.time() - float(hb))
                worker_alive = hb_age < 600
            info = await r.info("memory")
            used_bytes = info.get("used_memory")
            if used_bytes is not None:
                redis_mem = round(float(used_bytes) / (1024 * 1024), 2)
        finally:
            await r.aclose()
    except Exception:  # noqa: BLE001
        # Sampling is best-effort — keep going with whatever we have.
        logger.debug("infra sample: redis unreachable", exc_info=True)

    active_scans: int | None = None
    engine = create_async_engine(get_async_db_url())
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            active_scans = int(await db.scalar(
                select(func.count()).select_from(ScanJob).where(
                    ScanJob.status.in_((ScanStatus.QUEUED, ScanStatus.RUNNING))
                )
            ) or 0)
            await infra_svc.store_sample(
                db,
                queue_depth=queue_depth, worker_alive=worker_alive,
                worker_heartbeat_age_s=hb_age, redis_used_memory_mb=redis_mem,
                active_scans=active_scans,
            )
            await db.commit()
    finally:
        await engine.dispose()
    return {
        "queue_depth": queue_depth, "worker_alive": worker_alive,
        "heartbeat_age_s": hb_age, "redis_used_memory_mb": redis_mem,
        "active_scans": active_scans,
    }
