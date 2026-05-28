from __future__ import annotations

import asyncio
import logging

from worker._db import get_async_db_url
from worker.celery_app import celery

logger = logging.getLogger(__name__)

# Thresholds — tuned to surface real operational problems without noise.
_FAILED_SCAN_WINDOW_MIN = 30      # alert on scans that failed in the last N min
_ENGINE_WINDOW_DAYS = 7           # reliability window
_ENGINE_MIN_RUNS = 5              # ignore engines with too little data
_ENGINE_FAIL_PCT = 50.0          # failure rate that warrants an alert
_QUEUE_WARN = 50                  # queue depth → medium
_QUEUE_CRIT = 200                 # queue depth → high
_WORKER_STALE_S = 900             # heartbeat older than this → worker down


@celery.task(name="worker.alert_tasks.evaluate_alerts")
def evaluate_alerts() -> dict:
    """Derive SOC alerts from current system state. Fires every 5 min via beat."""
    try:
        return asyncio.run(_evaluate())
    except Exception:
        logger.exception("evaluate_alerts failed")
        raise


async def _evaluate() -> dict:
    from datetime import datetime, timedelta, timezone

    import apps.api.models  # noqa: F401 — register models
    from sqlalchemy import func, select
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from apps.api.models.alert import Alert
    from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
    from apps.api.models.scan_job import ScanJob
    from apps.api.models.website import Website
    from apps.api.services import alerts as alert_svc

    now = datetime.now(timezone.utc)
    counts = {"opened": 0, "updated": 0, "resolved": 0}

    engine = create_async_engine(get_async_db_url())
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            # 1) Recently failed scans — one alert per job (point-in-time).
            since = now - timedelta(minutes=_FAILED_SCAN_WINDOW_MIN)
            rows = await db.execute(
                select(ScanJob, Website.hostname)
                .join(Website, ScanJob.website_id == Website.id)
                .where(ScanJob.status == "failed", ScanJob.completed_at >= since)
            )
            for job, hostname in rows.all():
                _, created = await alert_svc.upsert_alert(
                    db,
                    dedup_key=f"scan_failure:{job.id}",
                    source="scan_failure",
                    severity="high",
                    title=f"Scan failed: {hostname or job.requested_url}",
                    description=(job.error_message or "Scan job ended in failed state."),
                    target_type="scan_job", target_id=str(job.id),
                    detail={"profile": getattr(job.profile, "value", str(job.profile)),
                            "url": job.requested_url},
                )
                counts["opened" if created else "updated"] += 1

            # 2) Engine reliability degradation (rolling window).
            ewin = now - timedelta(days=_ENGINE_WINDOW_DAYS)
            erows = await db.execute(
                select(
                    EngineDiagnosticRecord.engine_name,
                    func.count().label("runs"),
                    func.sum(sa.case((EngineDiagnosticRecord.status == "failed", 1), else_=0)).label("failed"),
                )
                .where(EngineDiagnosticRecord.created_at >= ewin)
                .group_by(EngineDiagnosticRecord.engine_name)
            )
            degraded: set[str] = set()
            for name, runs, failed in erows.all():
                runs = int(runs or 0)
                failed = int(failed or 0)
                if runs < _ENGINE_MIN_RUNS:
                    continue
                fail_pct = round(100 * failed / runs, 1)
                if fail_pct >= _ENGINE_FAIL_PCT:
                    degraded.add(name)
                    _, created = await alert_svc.upsert_alert(
                        db,
                        dedup_key=f"engine_reliability:{name}",
                        source="engine_reliability",
                        severity="high" if fail_pct >= 80 else "medium",
                        title=f"Engine '{name}' failing {fail_pct}% of runs",
                        description=f"{failed}/{runs} runs failed over the last {_ENGINE_WINDOW_DAYS}d.",
                        target_type="engine", target_id=name,
                        detail={"runs": runs, "failed": failed, "fail_pct": fail_pct},
                    )
                    counts["opened" if created else "updated"] += 1
            # Auto-resolve engines that recovered.
            open_eng = await db.scalars(
                select(Alert).where(Alert.source == "engine_reliability",
                                    Alert.status.in_(("open", "acknowledged")))
            )
            for a in open_eng.all():
                if a.target_id not in degraded:
                    if await alert_svc.auto_resolve(db, a.dedup_key,
                                                    note="Engine reliability recovered."):
                        counts["resolved"] += 1

            # 3) Worker liveness + 4) queue depth (Redis).
            await _check_infra(db, now, counts, alert_svc)

            await db.commit()
    finally:
        await engine.dispose()

    await alert_svc.publish_alert_event({"type": "evaluated", **counts})
    if any(counts.values()):
        logger.info("alert evaluation: %s", counts)
    return counts


async def _check_infra(db, now, counts, alert_svc) -> None:
    import os
    import redis.asyncio as aioredis

    try:
        r = aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"),
                              socket_connect_timeout=2, decode_responses=True)
        await r.ping()
    except Exception:  # noqa: BLE001
        return  # no Redis → can't assess worker/queue; infra tile already shows it

    try:
        beat = await r.get("webhound:worker:heartbeat")
        age = (now.timestamp() - float(beat)) if beat else None
        if age is None or age > _WORKER_STALE_S:
            _, created = await alert_svc.upsert_alert(
                db, dedup_key="worker_down", source="worker_down", severity="critical",
                title="Celery worker heartbeat stale",
                description=("No worker heartbeat recorded." if age is None
                             else f"Last heartbeat {int(age)}s ago (threshold {_WORKER_STALE_S}s)."),
                detail={"age_s": age},
            )
            counts["opened" if created else "updated"] += 1
        else:
            if await alert_svc.auto_resolve(db, "worker_down", note="Worker heartbeat healthy."):
                counts["resolved"] += 1

        depth = int(await r.llen("celery"))
        if depth >= _QUEUE_WARN:
            _, created = await alert_svc.upsert_alert(
                db, dedup_key="queue_backup", source="queue_backup",
                severity="high" if depth >= _QUEUE_CRIT else "medium",
                title=f"Scan queue backed up ({depth} pending)",
                description=f"Celery queue depth {depth} (warn {_QUEUE_WARN}, crit {_QUEUE_CRIT}).",
                detail={"queue_depth": depth},
            )
            counts["opened" if created else "updated"] += 1
        else:
            if await alert_svc.auto_resolve(db, "queue_backup", note="Queue drained."):
                counts["resolved"] += 1
    finally:
        try:
            await r.aclose()
        except Exception:  # noqa: BLE001
            pass
