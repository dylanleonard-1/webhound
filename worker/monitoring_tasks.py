from __future__ import annotations

import asyncio
import logging
import os

from worker._db import get_async_db_url
from worker.celery_app import celery

logger = logging.getLogger(__name__)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "") or default)
    except (TypeError, ValueError):
        return default


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


# ---------------------------------------------------------------------------
# FIX 9 — stale-job reaper
# ---------------------------------------------------------------------------


@celery.task(name="worker.monitoring_tasks.reap_stale_scan_jobs")
def reap_stale_scan_jobs() -> dict:
    """Detect and resolve scan jobs that got stuck — runs every 5 min via beat.

    Three stuck shapes are handled:

      * QUEUED too long (never picked up by a worker). Retry-if-safe: re-enqueue
        once while it's recoverable; mark FAILED once it's older than the hard
        cap (broker likely lost it for good).
      * RUNNING too long (worker hung past the time limit and couldn't report).
      * Missing heartbeat (worker died mid-scan; heartbeat_at stopped advancing).

    A re-enqueue is safe because run_scan's _execute skips any job that is no
    longer QUEUED — a duplicate task is a no-op. RUNNING-stale jobs are marked
    FAILED (not retried) and their Celery task is best-effort revoked to release
    the worker slot.
    """
    try:
        return asyncio.run(_reap())
    except Exception:
        logger.exception("reap_stale_scan_jobs failed")
        raise


def _revoke(task_id: str | None) -> None:
    """Best-effort revoke + terminate of a lost worker's task (release locks)."""
    if not task_id:
        return
    try:
        celery.control.revoke(task_id, terminate=True, signal="SIGKILL")
    except Exception:  # noqa: BLE001 — broker may be unreachable; never raise
        logger.debug("revoke of task %s failed (non-fatal)", task_id, exc_info=True)


async def _reap() -> dict:
    from datetime import datetime, timedelta, timezone

    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    import apps.api.models  # noqa: F401 — register all models
    from apps.api.models.enums import ScanStatus
    from apps.api.models.scan_job import ScanJob

    queued_secs = _int_env("SCAN_STALE_QUEUED_SECONDS", 900)       # 15 min
    running_secs = _int_env("SCAN_STALE_RUNNING_SECONDS", 1800)    # 30 min
    queued_hard_cap = queued_secs * 3                              # give up after 3x

    now = datetime.now(timezone.utc)
    queued_cutoff = now - timedelta(seconds=queued_secs)
    queued_dead_cutoff = now - timedelta(seconds=queued_hard_cap)
    running_cutoff = now - timedelta(seconds=running_secs)

    re_enqueued = 0
    failed = 0
    reasons: list[str] = []
    to_reenqueue: list[tuple[str, str, str]] = []

    engine = create_async_engine(get_async_db_url())
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        # --- RUNNING / heartbeat-stale -> FAILED + revoke ----------------
        async with factory() as db:
            running_rows = (await db.scalars(
                sa.select(ScanJob).where(
                    ScanJob.status == ScanStatus.RUNNING,
                    sa.or_(
                        # no progress since started
                        sa.and_(ScanJob.started_at.is_not(None),
                                ScanJob.started_at < running_cutoff),
                        # heartbeat stopped advancing (worker died mid-scan)
                        sa.and_(ScanJob.heartbeat_at.is_not(None),
                                ScanJob.heartbeat_at < running_cutoff),
                        # running with neither stamp but old row (defensive)
                        sa.and_(ScanJob.started_at.is_(None),
                                ScanJob.heartbeat_at.is_(None),
                                ScanJob.created_at < running_cutoff),
                    ),
                )
            )).all()
            for job in running_rows:
                _revoke(job.celery_task_id)
                job.status = ScanStatus.FAILED
                job.completed_at = now
                job.error_message = (
                    f"stale: no progress for >{running_secs}s "
                    "(worker lost or hung; reaped)"
                )
                failed += 1
                reasons.append(f"{job.id}:running-stale")
            if running_rows:
                await db.commit()

        # --- QUEUED stale: re-enqueue if recoverable, else FAIL ----------
        async with factory() as db:
            queued_rows = (await db.scalars(
                sa.select(ScanJob).where(
                    ScanJob.status == ScanStatus.QUEUED,
                    ScanJob.created_at < queued_cutoff,
                )
            )).all()

            for job in queued_rows:
                if job.created_at < queued_dead_cutoff:
                    job.status = ScanStatus.FAILED
                    job.completed_at = now
                    job.error_message = (
                        f"stale: never dispatched within {queued_hard_cap}s "
                        "(broker lost the task; reaped)"
                    )
                    failed += 1
                    reasons.append(f"{job.id}:queued-dead")
                else:
                    to_reenqueue.append(
                        (str(job.id), job.requested_url, job.profile.value)
                    )
                    reasons.append(f"{job.id}:queued-reenqueue")
            if queued_rows:
                await db.commit()
    finally:
        await engine.dispose()

    # Re-enqueue OUTSIDE the DB session. Safe: _execute skips non-QUEUED jobs,
    # so a stray duplicate is a no-op.
    if to_reenqueue:
        from worker.scan_tasks import run_scan
        for job_id, url, profile in to_reenqueue:
            try:
                run_scan.delay(job_id, url, profile)
                re_enqueued += 1
            except Exception:
                logger.warning("reaper failed to re-enqueue job %s", job_id)

    if failed or re_enqueued:
        logger.info(
            "reaper: failed=%d re_enqueued=%d details=%s",
            failed, re_enqueued, ",".join(reasons),
        )
    return {"failed": failed, "re_enqueued": re_enqueued, "reasons": reasons}
