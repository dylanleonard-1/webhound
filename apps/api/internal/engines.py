# WebHound — apps/api/internal/engines.py
# Phase 10: engine registry mutations (maintenance toggle, auto-disable
# threshold). ANALYST+ can toggle maintenance; ADMIN sets the auto-disable
# threshold (it's a sharper instrument).

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

import sqlalchemy as sa
from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
from apps.api.models.enums import AdminRole
from apps.api.models.scan_result import ScanResultRecord
from apps.api.models.user import User
from apps.api.services import engines as engines_svc
from apps.api.telemetry import Event, EventKind, Severity, publish_event

router = APIRouter(prefix="/internal/engines", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_Op = Annotated[User, Depends(require_admin(AdminRole.ANALYST))]
_Admin = Annotated[User, Depends(require_admin(AdminRole.ADMIN))]
_DB = Annotated[AsyncSession, Depends(get_db)]


class _MaintBody(BaseModel):
    on: bool
    notes: str | None = None


class _ThresholdBody(BaseModel):
    failure_pct: int | None = None


def _audit_ctx(request: Request) -> dict:
    return {
        "ip_address": (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                       or (request.client.host if request.client else None)),
        "request_id": getattr(request.state, "request_id", None),
    }


@router.post("/{name}/maintenance")
async def toggle_maintenance(name: str, body: _MaintBody, admin: _Op, db: _DB,
                             request: Request) -> dict:
    row = await engines_svc.set_maintenance(db, name, on=body.on,
                                            actor_email=admin.email)
    if body.notes is not None:
        row.notes = body.notes
    await record_action(db, actor=admin,
                        action="engine.maintenance",
                        target_type="engine", target_id=name,
                        detail={"on": body.on, "notes": body.notes},
                        **_audit_ctx(request))
    await db.commit()
    await publish_event(Event(
        kind=EventKind.ENGINE_MAINTENANCE,
        severity=Severity.MEDIUM if body.on else Severity.INFO,
        source="engine_registry",
        message=f"Engine '{name}' maintenance {'engaged' if body.on else 'cleared'}",
        target_type="engine", target_id=name, actor_email=admin.email,
    ))
    return {"ok": True, "maintenance_mode": body.on}


@router.post("/{name}/threshold")
async def set_threshold(name: str, body: _ThresholdBody, admin: _Admin, db: _DB,
                        request: Request) -> dict:
    await engines_svc.set_auto_disable_threshold(
        db, name, failure_pct=body.failure_pct, actor_email=admin.email,
    )
    await record_action(db, actor=admin,
                        action="engine.threshold",
                        target_type="engine", target_id=name,
                        detail={"failure_pct": body.failure_pct},
                        **_audit_ctx(request))
    await db.commit()
    return {"ok": True, "auto_disable_at_failure_pct": body.failure_pct}


def _percentile(values: list[float], p: float) -> float | None:
    """Linear-interpolation percentile. Returns None on empty input."""
    if not values:
        return None
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    if lo == hi:
        return s[lo]
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def _is_timeout(d: EngineDiagnosticRecord) -> bool:
    err = (d.error_message or "").lower()
    return ("timeout" in err
            or "timed out" in err
            or (d.duration_ms is not None and d.duration_ms >= 59_000))


@router.get("/{name}/diagnostics")
async def engine_diagnostics(
    name: str, admin: _Read, db: _DB,
    hours: Annotated[int, Query(ge=1, le=720)] = 168,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> dict:
    """Deep-dive for one engine: recent runs (with timeout markers), per-
    status counts, duration percentiles (p50/p90/p99), top error messages,
    and a small histogram. Use this to investigate degraded engines.

    `_is_timeout` flags rows whose error message mentions a timeout OR whose
    duration is within 1s of the worker's 60s engine timeout, since those
    are the same operational problem (engine ran out of time)."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = (await db.scalars(
        select(EngineDiagnosticRecord)
        .where(EngineDiagnosticRecord.engine_name == name,
               EngineDiagnosticRecord.created_at >= since)
        .order_by(EngineDiagnosticRecord.created_at.desc())
        .limit(limit)
    )).all()

    if not rows:
        return {
            "engine": name, "runs": 0, "window_hours": hours,
            "by_status": {}, "timeouts": 0, "duration": {}, "errors": [], "items": [],
        }

    by_status: dict[str, int] = {}
    timeout_count = 0
    durations: list[float] = []
    err_counts: dict[str, int] = {}
    items: list[dict] = []
    for d in rows:
        by_status[d.status] = by_status.get(d.status, 0) + 1
        if d.duration_ms is not None:
            durations.append(float(d.duration_ms))
        timeout = _is_timeout(d)
        if timeout:
            timeout_count += 1
        if d.error_message:
            # First line / first 80 chars — keeps the leaderboard tight.
            key = (d.error_message.splitlines()[0] if d.error_message else "")[:80]
            if key:
                err_counts[key] = err_counts.get(key, 0) + 1
        items.append({
            "id": str(d.id), "scan_result_id": str(d.scan_result_id),
            "status": d.status, "category": d.category,
            "findings": d.findings_count, "duration_ms": d.duration_ms,
            "skipped_reason": d.skipped_reason,
            "error": d.error_message[:200] if d.error_message else None,
            "timeout": timeout,
            "at": d.created_at.isoformat() if d.created_at else None,
        })

    top_errors = sorted(
        ({"message": k, "count": v} for k, v in err_counts.items()),
        key=lambda r: r["count"], reverse=True,
    )[:5]

    return {
        "engine": name,
        "runs": len(rows),
        "window_hours": hours,
        "by_status": by_status,
        "timeouts": timeout_count,
        "timeout_rate": round(100 * timeout_count / len(rows), 1),
        "duration": {
            "p50": _percentile(durations, 50),
            "p90": _percentile(durations, 90),
            "p99": _percentile(durations, 99),
            "avg": round(sum(durations) / len(durations), 1) if durations else None,
            "max": max(durations) if durations else None,
            "min": min(durations) if durations else None,
        },
        "errors": top_errors,
        "items": items,
    }
