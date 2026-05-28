# WebHound — apps/api/services/logs.py
# Log Explorer + Audit search. The Log Explorer searches over the `logs`
# table (general application telemetry); the Audit browser searches over
# `admin_audit_logs` (privileged staff actions, recorded by record_action).

from __future__ import annotations

import csv
import io
import logging
import uuid
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.admin_audit_log import AdminAuditLog
from apps.api.models.log_record import LogRecord

logger = logging.getLogger(__name__)

VALID_SEVERITIES = ("debug", "info", "warning", "error", "critical")
# Indexed ascending — easy threshold comparison ("warning and above").
_SEVERITY_RANK = {s: i for i, s in enumerate(VALID_SEVERITIES)}


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- Log record write -------------------------------------------------------


async def record(
    db: AsyncSession, *,
    source: str,
    severity: str,
    message: str,
    context: dict | None = None,
    request_id: str | None = None,
    actor_email: str | None = None,
    timestamp: datetime | None = None,
) -> LogRecord:
    if severity not in VALID_SEVERITIES:
        severity = "info"
    row = LogRecord(
        timestamp=timestamp or _now(),
        source=source[:32], severity=severity,
        message=message[:8000],   # bound storage for runaway tracebacks
        context=context or {},
        request_id=request_id,
        actor_email=actor_email,
    )
    db.add(row)
    await db.flush()
    return row


# --- Log search -------------------------------------------------------------


async def search_logs(
    db: AsyncSession, *,
    source: str | None = None,
    severity_at_least: str | None = None,
    severity: str | None = None,
    q: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    request_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[LogRecord], int]:
    base = select(LogRecord)
    count_base = select(func.count()).select_from(LogRecord)
    conds = []
    if source:
        conds.append(LogRecord.source == source)
    if severity:
        conds.append(LogRecord.severity == severity)
    elif severity_at_least and severity_at_least in _SEVERITY_RANK:
        threshold = _SEVERITY_RANK[severity_at_least]
        allowed = [s for s, r in _SEVERITY_RANK.items() if r >= threshold]
        conds.append(LogRecord.severity.in_(allowed))
    if q:
        like = f"%{q.lower()}%"
        conds.append(sa.func.lower(LogRecord.message).like(like))
    if since:
        conds.append(LogRecord.timestamp >= since)
    if until:
        conds.append(LogRecord.timestamp <= until)
    if request_id:
        conds.append(LogRecord.request_id == request_id)
    for c in conds:
        base = base.where(c)
        count_base = count_base.where(c)
    total = await db.scalar(count_base) or 0
    rows = await db.scalars(
        base.order_by(LogRecord.timestamp.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), int(total)


def log_to_dict(r: LogRecord) -> dict:
    return {
        "id": str(r.id),
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        "source": r.source,
        "severity": r.severity,
        "message": r.message,
        "context": dict(r.context or {}),
        "request_id": r.request_id,
        "actor_email": r.actor_email,
    }


def logs_to_csv(rows: list[LogRecord]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "source", "severity", "actor_email", "request_id", "message"])
    for r in rows:
        w.writerow([
            r.timestamp.isoformat() if r.timestamp else "",
            r.source, r.severity, r.actor_email or "",
            r.request_id or "",
            (r.message or "").replace("\n", " "),
        ])
    return buf.getvalue()


# --- Audit search -----------------------------------------------------------


async def search_audit(
    db: AsyncSession, *,
    action: str | None = None,
    actor_email: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    q: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[AdminAuditLog], int]:
    base = select(AdminAuditLog)
    count_base = select(func.count()).select_from(AdminAuditLog)
    conds = []
    if action:
        conds.append(AdminAuditLog.action == action)
    if actor_email:
        conds.append(sa.func.lower(AdminAuditLog.actor_email) == actor_email.lower())
    if target_type:
        conds.append(AdminAuditLog.target_type == target_type)
    if target_id:
        conds.append(AdminAuditLog.target_id == target_id)
    if q:
        like = f"%{q.lower()}%"
        conds.append(sa.or_(
            sa.func.lower(AdminAuditLog.action).like(like),
            sa.func.lower(sa.func.coalesce(AdminAuditLog.actor_email, "")).like(like),
            sa.func.lower(sa.func.coalesce(AdminAuditLog.target_id, "")).like(like),
        ))
    if since:
        conds.append(AdminAuditLog.created_at >= since)
    if until:
        conds.append(AdminAuditLog.created_at <= until)
    for c in conds:
        base = base.where(c)
        count_base = count_base.where(c)
    total = await db.scalar(count_base) or 0
    rows = await db.scalars(
        base.order_by(AdminAuditLog.created_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), int(total)


def audit_to_dict(r: AdminAuditLog) -> dict:
    return {
        "id": str(r.id),
        "action": r.action,
        "actor_email": r.actor_email,
        "actor_role": r.actor_role,
        "target_type": r.target_type,
        "target_id": r.target_id,
        "detail": dict(r.detail or {}),
        "ip_address": r.ip_address,
        "request_id": r.request_id,
        "at": r.created_at.isoformat() if r.created_at else None,
    }


def audit_to_csv(rows: list[AdminAuditLog]) -> str:
    import json
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["at", "actor_email", "actor_role", "action",
                "target_type", "target_id", "ip_address", "request_id", "detail"])
    for r in rows:
        w.writerow([
            r.created_at.isoformat() if r.created_at else "",
            r.actor_email or "", r.actor_role or "", r.action,
            r.target_type or "", r.target_id or "",
            r.ip_address or "", r.request_id or "",
            json.dumps(r.detail or {}, default=str),
        ])
    return buf.getvalue()


# --- Convenience: record a server error so the explorer surfaces it ---------


async def record_server_error(
    db: AsyncSession, *,
    request_method: str, request_path: str,
    exception: BaseException, request_id: str | None = None,
    actor_email: str | None = None,
) -> None:
    """Fire-and-forget — called from the global exception handler. Swallows
    its own errors so a logging failure never masks the original 500."""
    try:
        await record(
            db, source="api", severity="error",
            message=f"{type(exception).__name__}: {exception}",
            context={"method": request_method, "path": request_path,
                     "exception_type": type(exception).__name__},
            request_id=request_id, actor_email=actor_email,
        )
        await db.commit()
    except Exception:  # noqa: BLE001
        try:
            await db.rollback()
        except Exception:  # noqa: BLE001
            pass
        logger.debug("log record_server_error failed (non-fatal)", exc_info=True)
