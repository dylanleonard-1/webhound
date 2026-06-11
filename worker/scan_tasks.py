from __future__ import annotations

import asyncio
import dataclasses
import logging
import uuid
from typing import Any

import sqlalchemy as sa
from celery.exceptions import SoftTimeLimitExceeded
from webhound.core.orchestrator import Scanner
from webhound.core.scan_profiles import get_profile
from webhound.models.target import Target

from worker._db import get_async_db_url
from worker.celery_app import (
    _SCAN_HARD_TIME_LIMIT,
    _SCAN_SOFT_TIME_LIMIT,
    celery,
)

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3


@celery.task(
    name="worker.scan_tasks.run_scan",
    bind=True,
    max_retries=_MAX_RETRIES,
    # FIX 8 — per-task limits (also the global defaults, set explicitly here so
    # they survive a global-config change). soft -> SoftTimeLimitExceeded inside
    # the task; hard -> SIGKILL backstop.
    soft_time_limit=_SCAN_SOFT_TIME_LIMIT,
    time_limit=_SCAN_HARD_TIME_LIMIT,
)
def run_scan(self, job_id: str, target_url: str, profile: str = "standard") -> dict:
    """Execute a scan job: run Scanner, persist results, update job status.

    FIX 8: a soft time-limit hit is terminal — the job is marked failed with a
    timeout message and is NOT retried (a scan that exhausted its budget will
    almost certainly do so again). Other transient failures retry with bounded
    exponential backoff (max_retries caps the total — never an infinite loop).
    FIX 10: a cancelled scan raises ScanCancelled (a BaseException, so it skips
    the generic handler); the job is marked cancelled and never retried.
    """
    from webhound.core.orchestrator import ScanCancelled

    try:
        return asyncio.run(_execute(job_id, target_url, profile))
    except SoftTimeLimitExceeded:
        logger.warning("scan job %s exceeded its time limit; marking timed out", job_id)
        msg = f"scan timed out (soft time limit {_SCAN_SOFT_TIME_LIMIT}s exceeded)"
        try:
            asyncio.run(_mark_failed(job_id, msg))
        except Exception:
            logger.exception("could not mark timed-out job %s failed", job_id)
        # Terminal: do not retry a timeout.
        return {"job_id": job_id, "timed_out": True}
    except ScanCancelled:
        logger.info("scan job %s cancelled mid-run", job_id)
        try:
            asyncio.run(_mark_cancelled(job_id))
        except Exception:
            logger.exception("could not mark cancelled job %s", job_id)
        return {"job_id": job_id, "cancelled": True}
    except Exception as exc:
        logger.exception("scan task failed for job %s", job_id)
        try:
            asyncio.run(_mark_failed(job_id, str(exc)))
        except Exception:
            logger.exception("could not mark job %s failed", job_id)
        if self.request.retries >= _MAX_RETRIES:
            logger.error("scan job %s failed permanently after %d retries",
                         job_id, self.request.retries)
            return {"job_id": job_id, "failed": True}
        # 60s, 120s, 240s bounded backoff.
        countdown = 60 * (2 ** self.request.retries)
        raise self.retry(exc=exc, countdown=countdown)


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
    bypass_headers: dict[str, str] = {}  # provider trusted-automation bypass (never logged)

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

        # Provider trusted-automation bypass: if the website has a stored Vercel
        # Protection-Bypass-for-Automation secret, inject the header on every scan
        # request so the scanner is let past Vercel's BotID/Security Checkpoint.
        # Decrypted in-process only; NEVER logged.
        try:
            from apps.api.services import vercel_scanner_access as _vsa
            _secret = await _vsa.load_protection_bypass(db, job.website_id)
            if _secret:
                bypass_headers = {"x-vercel-protection-bypass": _secret,
                                  "x-vercel-set-bypass-cookie": "true"}
        except Exception:  # noqa: BLE001 — bypass is best-effort; never break the scan
            logger.debug("protection-bypass load failed (non-fatal)", exc_info=True)

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
        # FIX 9 — stamp initial liveness + record the Celery task id so the
        # reaper can attribute (and best-effort revoke) a lost worker's job.
        from datetime import datetime as _dt, timezone as _tz
        job.heartbeat_at = _dt.now(_tz.utc)
        try:
            from celery import current_task
            if current_task is not None and current_task.request.id:
                job.celery_task_id = current_task.request.id
        except Exception:
            pass
        await db.commit()

    # Slice 4.B — publish scan.started event so the public SSE
    # endpoint can stream live progress to /scan/[token]/status.
    # Best-effort: a Redis pub-sub hiccup must not affect the
    # actual scan execution.
    try:
        from apps.api.telemetry import Event, EventKind, publish_event
        await publish_event(Event(
            kind=EventKind.SCAN_STARTED,
            source="worker",
            target_type="scan_job",
            target_id=job_id,
            detail={"target_url": target_url, "profile": profile},
        ))
    except Exception:
        logger.debug("publish scan.started failed (non-fatal)", exc_info=True)

    # FIX 10 — cancellation probe. Awaited by the scanner at each phase
    # boundary; opens a short-lived session, refreshes the job heartbeat
    # (FIX 9), and returns True when the API has flagged the scan for
    # cancellation. Probe failures are swallowed by the scanner (never abort a
    # healthy scan on a transient DB hiccup).
    async def _cancel_check() -> bool:
        from datetime import datetime as _dt, timezone as _tz

        from apps.api.models.scan_job import ScanJob as _ScanJob
        from apps.api.models.enums import ScanStatus as _Status

        async with factory() as cdb:
            row = await cdb.get(_ScanJob, job_uuid)
            if row is None:
                return False
            row.heartbeat_at = _dt.now(_tz.utc)
            cancelled = bool(getattr(row, "cancellation_requested", False)) or (
                row.status == _Status.CANCELLED
            )
            await cdb.commit()
            return cancelled

    scan_options = get_profile(profile).to_scan_options()
    if bypass_headers:
        scan_options.extra_http_headers = dict(bypass_headers)
    target = Target.from_url(target_url, scan_options=scan_options)
    scanner = Scanner(
        target, previous_baseline=previous_baseline, cancel_check=_cancel_check
    )
    try:
        result = await scanner.scan()
    except BaseException:
        # FIX 8 / FIX 10 — scanner raised, timed out (SoftTimeLimitExceeded),
        # or was cancelled (ScanCancelled). The Scanner tears down its own
        # browser/HTTP contexts via internal `async with` blocks as the
        # exception unwinds; here we additionally release the DB engine this
        # task owns before re-raising so run_scan can apply the terminal status.
        if own_engine:
            await own_engine.dispose()
        raise

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
            try:
                from apps.api.telemetry import Event, EventKind, publish_event, Severity
                await publish_event(Event(
                    kind=EventKind.SCAN_FAILED,
                    severity=Severity.HIGH,
                    source="worker",
                    target_type="scan_job",
                    target_id=job_id,
                    message=error_msg,
                    detail={"target_url": target_url},
                ))
            except Exception:
                logger.debug("publish scan.failed failed (non-fatal)", exc_info=True)
        else:
            result_record = await persist_scan_result(db, job_uuid, result)
            await sj_service.update_scan_job_status(
                db, job_uuid, ScanJobStatusUpdate(status=ScanStatus.COMPLETED)
            )
            try:
                from apps.api.telemetry import Event, EventKind, publish_event
                await publish_event(Event(
                    kind=EventKind.SCAN_COMPLETED,
                    source="worker",
                    target_type="scan_job",
                    target_id=job_id,
                    detail={
                        "target_url": target_url,
                        "risk_score": result_record.risk_score if result_record else None,
                        "total_findings": result_record.total_findings if result_record else 0,
                    },
                ))
            except Exception:
                logger.debug("publish scan.completed failed (non-fatal)", exc_info=True)
            if save_baseline_flag and scanner.current_baseline is not None and job is not None:
                try:
                    await _save_baseline_record(db, job.website_id, scanner.current_baseline)
                except Exception:
                    logger.warning("failed to save baseline for job %s", job_id)

            # Continuous-monitoring delta + drift-alert dispatch.
            # Best-effort and isolated — a failure here never marks the
            # scan failed. The scan is already COMPLETED at this point.
            if job is not None:
                try:
                    from apps.api.services.monitoring import (
                        handle_scan_completion,
                    )
                    await handle_scan_completion(
                        db, scan_job_id=job_uuid,
                        website_id=job.website_id,
                    )
                except Exception:
                    logger.warning(
                        "monitoring delta failed for job %s (non-fatal)",
                        job_id,
                    )

        created_notifications: list = []
        if user_id is not None and job is not None:
            created_notifications = await generate_scan_notifications(
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

        # FIX 6 — outbound email delivery. Feature-flagged + provider-gated:
        # eligible_for_email returns [] unless NOTIFICATIONS_ENABLED=1 and a
        # provider is configured, so by default nothing is enqueued and no
        # email is claimed. Best-effort — a queueing hiccup never affects the
        # already-committed scan result.
        try:
            from apps.api.config import get_settings
            from apps.api.services.notification_delivery import eligible_for_email

            user_email = None
            if user_id is not None:
                from apps.api.models.user import User as _User
                _user = await db.get(_User, user_id)
                user_email = getattr(_user, "email", None)

            if user_email and get_settings().notifications_enabled:
                from worker.notification_tasks import deliver_notification_email
                for n in eligible_for_email(created_notifications):
                    deliver_notification_email.delay(str(n.id), user_email)
        except Exception:
            logger.warning(
                "notification email enqueue failed for job %s (non-fatal)",
                job_id, exc_info=True,
            )

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


async def _mark_cancelled(
    job_id: str,
    *,
    _session_factory: Any = None,
) -> None:
    """FIX 10 — transition a cancelled scan to CANCELLED.

    The DB row may already be CANCELLED (the API flips it when the user clicks
    cancel); RUNNING -> CANCELLED is a valid transition, and an already-terminal
    row raises InvalidStatusTransitionError which we swallow (idempotent). A
    cancelled scan must never persist a success result — run_scan reaches this
    path only by catching ScanCancelled BEFORE any result is written.
    """
    import apps.api.models  # noqa: F401

    from apps.api.models.enums import ScanStatus
    from apps.api.models.scan_job import ScanJob

    own_engine = None
    if _session_factory is None:
        factory, own_engine = _make_factory(get_async_db_url())
    else:
        factory = _session_factory

    job_uuid = uuid.UUID(job_id)
    try:
        async with factory() as db:
            job = await db.get(ScanJob, job_uuid)
            if job is not None and job.status not in (
                ScanStatus.CANCELLED, ScanStatus.COMPLETED, ScanStatus.FAILED,
            ):
                from datetime import datetime, timezone
                job.status = ScanStatus.CANCELLED
                job.completed_at = datetime.now(timezone.utc)
                await db.commit()
    except Exception:
        logger.exception("failed to write cancelled status for job %s", job_id)
    finally:
        if own_engine:
            await own_engine.dispose()
