from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any

from webhound.core.orchestrator import Scanner
from webhound.core.scan_profiles import get_profile
from webhound.models.target import Target

from worker.celery_app import celery

logger = logging.getLogger(__name__)


@celery.task(name="worker.scan_tasks.run_scan", bind=True, max_retries=3)
def run_scan(self, job_id: str, target_url: str, profile: str = "standard") -> dict:
    """Execute a scan job: run Scanner, persist results, update job status."""
    try:
        return asyncio.run(_execute(job_id, target_url, profile))
    except Exception as exc:
        logger.exception("scan task failed for job %s", job_id)
        try:
            asyncio.run(_mark_failed(job_id, str(exc)))
        except Exception:
            logger.exception("could not mark job %s failed", job_id)
        raise self.retry(exc=exc, countdown=60)


def _make_factory(db_url: str) -> Any:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(db_url)
    return async_sessionmaker(engine, expire_on_commit=False), engine


async def _execute(
    job_id: str,
    target_url: str,
    profile: str,
    *,
    _session_factory: Any = None,
) -> dict:
    import apps.api.models  # noqa: F401 — registers all models with Base.metadata

    from apps.api.models.enums import ScanStatus
    from apps.api.models.scan_job import ScanJob
    from apps.api.schemas.scan_jobs import ScanJobStatusUpdate
    from apps.api.services import scan_jobs as sj_service
    from apps.api.services.result_persistence import persist_scan_result

    own_engine = None
    if _session_factory is None:
        db_url = os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://webhound:webhound@localhost:5432/webhound",
        )
        factory, own_engine = _make_factory(db_url)
    else:
        factory = _session_factory

    job_uuid = uuid.UUID(job_id)

    async with factory() as db:
        job = await db.get(ScanJob, job_uuid)
        if job is None:
            if own_engine:
                await own_engine.dispose()
            raise RuntimeError(f"scan job not found: {job_id}")
        if job.status != ScanStatus.QUEUED:
            logger.warning("job %s is %s, skipping", job_id, job.status)
            if own_engine:
                await own_engine.dispose()
            return {"job_id": job_id, "skipped": True}

        await sj_service.update_scan_job_status(
            db, job_uuid, ScanJobStatusUpdate(status=ScanStatus.RUNNING)
        )
        await db.commit()

    scan_options = get_profile(profile).to_scan_options()
    target = Target.from_url(target_url, scan_options=scan_options)
    scanner = Scanner(target)
    result = await scanner.scan()

    async with factory() as db:
        scanner_failed = result.status.value == "failed"
        if scanner_failed:
            error_msg = (
                result.errors[0].message
                if result.errors
                else "scanner reported failure"
            )
            await sj_service.update_scan_job_status(
                db,
                job_uuid,
                ScanJobStatusUpdate(status=ScanStatus.FAILED, error_message=error_msg),
            )
        else:
            await persist_scan_result(db, job_uuid, result)
            await sj_service.update_scan_job_status(
                db, job_uuid, ScanJobStatusUpdate(status=ScanStatus.COMPLETED)
            )
        await db.commit()

    if own_engine:
        await own_engine.dispose()

    return {
        "job_id": job_id,
        "risk_score": result.metadata.get("risk_score"),
        "risk_level": result.metadata.get("risk_level"),
    }


async def _mark_failed(
    job_id: str,
    error: str,
    *,
    _session_factory: Any = None,
) -> None:
    import apps.api.models  # noqa: F401

    from apps.api.models.enums import ScanStatus
    from apps.api.schemas.scan_jobs import ScanJobStatusUpdate
    from apps.api.services import scan_jobs as sj_service

    own_engine = None
    if _session_factory is None:
        db_url = os.getenv(
            "DATABASE_URL",
            "postgresql+asyncpg://webhound:webhound@localhost:5432/webhound",
        )
        factory, own_engine = _make_factory(db_url)
    else:
        factory = _session_factory

    job_uuid = uuid.UUID(job_id)
    async with factory() as db:
        try:
            await sj_service.update_scan_job_status(
                db,
                job_uuid,
                ScanJobStatusUpdate(status=ScanStatus.FAILED, error_message=error),
            )
            await db.commit()
        except Exception:
            logger.exception("failed to write failed status for job %s", job_id)

    if own_engine:
        await own_engine.dispose()
