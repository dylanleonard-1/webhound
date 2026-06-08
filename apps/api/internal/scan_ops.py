# WebHound — apps/api/internal/scan_ops.py
# Phase 2: Scan Operations Center + Engine Monitoring (RBAC-gated, audited).

from __future__ import annotations

import logging
import uuid
from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
from apps.api.services.admin_scan import (
    ALLOWED_PROFILES,
    AdminScanError,
    read_scan_telemetry,
    run_admin_scan,
)
from apps.api.models.admin_audit_log import AdminAuditLog  # noqa: F401 (ensure registered)
from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.enums import AdminRole
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.user import User
from apps.api.models.website import Website
from apps.api.schemas.scan_jobs import ScanJobCreate
from apps.api.services import scan_jobs as sj_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_Op = Annotated[User, Depends(require_admin(AdminRole.ANALYST))]
_DB = Annotated[AsyncSession, Depends(get_db)]


def _duration(job: ScanJob) -> float | None:
    if job.started_at and job.completed_at:
        return round((job.completed_at - job.started_at).total_seconds(), 1)
    return None


def _audit_ctx(request: Request) -> dict:
    return {
        "ip_address": request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else None),
        "request_id": getattr(request.state, "request_id", None),
    }


@router.get("/scans")
async def list_scans(
    admin: _Read,
    db: _DB,
    status: str | None = None,
    profile: str | None = None,
    q: Annotated[str | None, Query(description="search requested URL or owner email")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    base = (
        select(ScanJob, Website.hostname, User.email)
        .join(Website, ScanJob.website_id == Website.id)
        .join(User, Website.user_id == User.id)
    )
    count_base = (
        select(func.count())
        .select_from(ScanJob)
        .join(Website, ScanJob.website_id == Website.id)
        .join(User, Website.user_id == User.id)
    )
    conds = []
    if status:
        conds.append(ScanJob.status == status)
    if profile:
        conds.append(ScanJob.profile == profile)
    if q:
        like = f"%{q.lower()}%"
        conds.append(sa.or_(
            sa.func.lower(ScanJob.requested_url).like(like),
            sa.func.lower(User.email).like(like),
        ))
    for c in conds:
        base = base.where(c)
        count_base = count_base.where(c)
    total = await db.scalar(count_base) or 0
    rows = await db.execute(
        base.order_by(ScanJob.created_at.desc()).limit(limit).offset(offset)
    )
    items = [
        {
            "id": str(j.id),
            "status": j.status.value if hasattr(j.status, "value") else str(j.status),
            "profile": j.profile.value if hasattr(j.profile, "value") else str(j.profile),
            "url": j.requested_url,
            "hostname": hostname,
            "owner": email,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "duration_s": _duration(j),
            "error": j.error_message,
        }
        for j, hostname, email in rows.all()
    ]
    return {"items": items, "total": int(total), "limit": limit, "offset": offset}


@router.get("/scans/{scan_id}")
async def scan_detail(scan_id: uuid.UUID, admin: _Read, db: _DB) -> dict:
    job = await db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    website = await db.get(Website, job.website_id)
    owner_email = None
    if website:
        u = await db.get(User, website.user_id)
        owner_email = u.email if u else None
    diagnostics: list[dict] = []
    result = await db.scalar(
        select(ScanResultRecord).where(ScanResultRecord.scan_job_id == scan_id)
    )
    if result is not None:
        diag_rows = await db.execute(
            select(EngineDiagnosticRecord)
            .where(EngineDiagnosticRecord.scan_result_id == result.id)
            .order_by(EngineDiagnosticRecord.duration_ms.desc().nulls_last())
        )
        diagnostics = [
            {
                "engine": d.engine_name,
                "category": d.category,
                "status": d.status,
                "findings": d.findings_count,
                "duration_ms": d.duration_ms,
                "skipped_reason": d.skipped_reason,
                "error": d.error_message,
            }
            for d in diag_rows.scalars().all()
        ]
    return {
        "id": str(job.id),
        "status": job.status.value if hasattr(job.status, "value") else str(job.status),
        "profile": job.profile.value if hasattr(job.profile, "value") else str(job.profile),
        "url": job.requested_url,
        "hostname": website.hostname if website else None,
        "owner": owner_email,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "duration_s": _duration(job),
        "error": job.error_message,
        "celery_task_id": job.celery_task_id,
        "engines": diagnostics,
    }


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: uuid.UUID, admin: _Op, db: _DB, request: Request) -> dict:
    job = await db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        await sj_service.cancel_scan_job(db, scan_id, user_id=None)  # admin scope
    except sj_service.InvalidStatusTransitionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    # Best-effort terminate the in-flight Celery task.
    if job.celery_task_id:
        try:
            from worker.celery_app import celery
            celery.control.revoke(job.celery_task_id, terminate=True)
        except Exception:  # noqa: BLE001
            logger.warning("could not revoke celery task %s", job.celery_task_id)
    await record_action(db, actor=admin, action="scan.cancel",
                        target_type="scan_job", target_id=str(scan_id), **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "id": str(scan_id), "status": "cancelled"}


@router.post("/scans/{scan_id}/rescan")
async def force_rescan(scan_id: uuid.UUID, admin: _Op, db: _DB, request: Request) -> dict:
    job = await db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    new = await sj_service.create_scan_job(
        db,
        ScanJobCreate(website_id=job.website_id, profile=job.profile),
        is_admin=True,  # staff-initiated; bypasses owner quota/verification gates
    )
    await db.commit()
    await db.refresh(new)
    try:
        from worker.scan_tasks import run_scan
        task = run_scan.delay(str(new.id), new.requested_url, new.profile.value)
        new.celery_task_id = task.id
        await db.commit()
    except Exception:  # noqa: BLE001
        logger.warning("failed to enqueue rescan for job %s", new.id)
    await record_action(db, actor=admin, action="scan.rescan",
                        target_type="scan_job", target_id=str(new.id),
                        detail={"origin_scan": str(scan_id)}, **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "new_scan_id": str(new.id), "origin": str(scan_id)}


class AdminRunScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    profile: str = Field(description="quick|standard|deep|enterprise|monitor|baseline")
    reason: str = Field(min_length=1, max_length=500)
    internal_test_mode: bool = False
    save_baseline: bool | None = None
    use_latest_baseline: bool = False


@router.post("/scans/run", status_code=201)
async def run_scan_on_demand(
    payload: AdminRunScanRequest, admin: _Op, db: _DB, request: Request,
) -> dict:
    """Internal/admin: run ANY scan profile on demand through the production
    pipeline. ANALYST+ only; every run is audited (actor + url + profile +
    reason). Same Website/ScanJob/worker path as customer scans — no parallel
    scanner, no scanner-behaviour change. Returns {job_id, scan_id, profile,
    status}."""
    if payload.profile.strip().lower() not in ALLOWED_PROFILES:
        raise HTTPException(
            status_code=400,
            detail=f"profile must be one of: {', '.join(ALLOWED_PROFILES)}")
    try:
        result = await run_admin_scan(
            db, url=payload.url, profile=payload.profile, reason=payload.reason,
            triggered_by=admin.email, actor=admin,
            internal_test_mode=payload.internal_test_mode,
            save_baseline=payload.save_baseline,
            use_latest_baseline=payload.use_latest_baseline,
            audit_ctx=_audit_ctx(request))
    except AdminScanError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    await db.commit()
    return result


@router.get("/scans/{job_id}/telemetry")
async def scan_telemetry(job_id: uuid.UUID, admin: _Read, db: _DB) -> dict:
    """Internal/admin: read the persisted telemetry + browser_pass for a scan
    job, folded into the browser-telemetry verification view. Read-only."""
    try:
        return await read_scan_telemetry(db, job_id)
    except AdminScanError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/engines")
async def engine_scorecards(admin: _Read, db: _DB) -> dict:
    """Per-engine reliability + operational state + maintenance/threshold
    overrides. Window: last 7 days. State machine: healthy / degraded /
    unstable / critical / maintenance — see services/engines.compute_state.

    Original Phase 2 fields (runs/failed/skipped/failure_rate/empty_rate/
    avg_ms/reliability) are preserved exactly; this endpoint just adds
    `state`, `maintenance_mode`, `auto_disable_at_failure_pct`, `max_ms`,
    and `notes`. The UI is free to ignore the new fields.
    """
    from apps.api.services import engines as engines_svc
    return {"engines": await engines_svc.health_scorecards(db)}
