# WebHound — apps/api/internal/scan_ops.py
# Phase 2: Scan Operations Center + Engine Monitoring (RBAC-gated, audited).

from __future__ import annotations

import logging
import uuid
from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
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
    q: str | None = Query(None, description="search requested URL or owner email"),
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


@router.get("/engines")
async def engine_scorecards(admin: _Read, db: _DB) -> dict:
    """Per-engine reliability from engine_diagnostics across all scans."""
    rows = await db.execute(
        select(
            EngineDiagnosticRecord.engine_name,
            func.count().label("runs"),
            func.sum(sa.case((EngineDiagnosticRecord.status == "failed", 1), else_=0)).label("failed"),
            func.sum(sa.case((EngineDiagnosticRecord.status == "skipped", 1), else_=0)).label("skipped"),
            func.sum(sa.case((EngineDiagnosticRecord.findings_count == 0, 1), else_=0)).label("empty"),
            func.avg(EngineDiagnosticRecord.duration_ms).label("avg_ms"),
        ).group_by(EngineDiagnosticRecord.engine_name)
    )
    engines = []
    for name, runs, failed, skipped, empty, avg_ms in rows.all():
        runs = int(runs or 0)
        failed = int(failed or 0)
        skipped = int(skipped or 0)
        ok_runs = runs - failed - skipped
        reliability = round(100 * ok_runs / runs, 1) if runs else None
        engines.append({
            "engine": name,
            "runs": runs,
            "failed": failed,
            "skipped": skipped,
            "failure_rate": round(100 * failed / runs, 1) if runs else 0,
            "empty_rate": round(100 * int(empty or 0) / runs, 1) if runs else 0,
            "avg_ms": round(float(avg_ms), 1) if avg_ms is not None else None,
            "reliability": reliability,
        })
    engines.sort(key=lambda e: (e["reliability"] if e["reliability"] is not None else 101))
    return {"engines": engines}
