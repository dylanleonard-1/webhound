from __future__ import annotations

import asyncio
import dataclasses
import logging
import uuid
from typing import Any

import sqlalchemy as sa
from webhound.core.orchestrator import Scanner
from webhound.core.scan_profiles import get_profile
from webhound.models.target import Target

from worker._db import get_async_db_url
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


def _deserialize_baseline(data: dict) -> Any:
    """Reconstruct a SiteBaseline dataclass from a JSON dict."""
    from webhound.wade.baseline_builder import PageSnapshot, SiteBaseline

    pages = {url: PageSnapshot(**snap) for url, snap in data.get("pages", {}).items()}
    return SiteBaseline(
        target_url=data["target_url"],
        scan_id=data["scan_id"],
        created_at=data["created_at"],
        pages=pages,
        all_script_sources=data.get("all_script_sources", []),
        all_external_domains=data.get("all_external_domains", []),
        page_count=data.get("page_count", 0),
    )


async def _save_baseline_record(db: Any, website_id: uuid.UUID, baseline: Any) -> None:
    """Persist a SiteBaseline as a BaselineRecord with auto-incremented version."""
    from apps.api.models.baseline import BaselineRecord

    existing_count = (
        await db.scalar(
            sa.select(sa.func.count())
            .select_from(BaselineRecord)
            .where(BaselineRecord.website_id == website_id)
        )
    ) or 0
    bl = BaselineRecord(
        website_id=website_id,
        baseline_id=baseline.scan_id,
        baseline_version=existing_count + 1,
        baseline_json=dataclasses.asdict(baseline),
    )
    db.add(bl)
    await db.flush()
    logger.info("saved baseline v%d for website %s", existing_count + 1, website_id)


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
        factory, own_engine = _make_factory(get_async_db_url())
    else:
        factory = _session_factory

    job_uuid = uuid.UUID(job_id)
    previous_baseline = None
    use_latest_baseline = False
    save_baseline_flag = False

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

        use_latest_baseline = job.use_latest_baseline
        save_baseline_flag = job.save_baseline

        if use_latest_baseline:
            from apps.api.services.baselines import get_latest_baseline

            bl_record = await get_latest_baseline(db, job.website_id)
            if bl_record is not None:
                try:
                    previous_baseline = _deserialize_baseline(bl_record.baseline_json)
                    logger.info(
                        "loaded baseline v%d for job %s", bl_record.baseline_version, job_id
                    )
                except Exception:
                    logger.warning("failed to deserialize baseline for job %s", job_id)

        await sj_service.update_scan_job_status(
            db, job_uuid, ScanJobStatusUpdate(status=ScanStatus.RUNNING)
        )
        await db.commit()

    scan_options = get_profile(profile).to_scan_options()
    target = Target.from_url(target_url, scan_options=scan_options)
    scanner = Scanner(target, previous_baseline=previous_baseline)
    result = await scanner.scan()

    async with factory() as db:
        from apps.api.models.website import Website
        from apps.api.services.notifications import generate_scan_notifications

        job = await db.get(ScanJob, job_uuid)
        website = await db.get(Website, job.website_id) if job else None
        user_id = website.user_id if website else None
        website_url = website.url if website else ""

        scanner_failed = result.status.value == "failed"
        result_record = None

        if scanner_failed:
            error_msg = (
                result.errors[0].message if result.errors else "scanner reported failure"
            )
            await sj_service.update_scan_job_status(
                db,
                job_uuid,
                ScanJobStatusUpdate(status=ScanStatus.FAILED, error_message=error_msg),
            )
        else:
            result_record = await persist_scan_result(db, job_uuid, result)
            await sj_service.update_scan_job_status(
                db, job_uuid, ScanJobStatusUpdate(status=ScanStatus.COMPLETED)
            )
            if save_baseline_flag and scanner.current_baseline is not None and job is not None:
                try:
                    await _save_baseline_record(db, job.website_id, scanner.current_baseline)
                except Exception:
                    logger.warning("failed to save baseline for job %s", job_id)

        if user_id is not None and job is not None:
            await generate_scan_notifications(
                db,
                user_id=user_id,
                website_id=job.website_id,
                scan_job_id=job_uuid,
                scan_result_id=result_record.id if result_record else None,
                scanner_status="failed" if scanner_failed else "completed",
                severity_breakdown=result_record.severity_breakdown if result_record else None,
                scanner_metadata=result_record.scanner_metadata if result_record else None,
                website_url=website_url,
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
        factory, own_engine = _make_factory(get_async_db_url())
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
