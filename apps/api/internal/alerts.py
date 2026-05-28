# WebHound — apps/api/internal/alerts.py
# Phase 3: SOC alerting API + realtime SSE stream (RBAC-gated, audited).

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Annotated

import redis.asyncio as aioredis
import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.database import get_db
from apps.api.internal.audit import record_action
from apps.api.internal.rbac import require_admin
from apps.api.models.alert import Alert, AlertComment
from apps.api.models.enums import AdminRole
from apps.api.models.user import User
from apps.api.services import alerts as alert_svc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])

_Read = Annotated[User, Depends(require_admin(AdminRole.READ_ONLY))]
_Op = Annotated[User, Depends(require_admin(AdminRole.ANALYST))]
_DB = Annotated[AsyncSession, Depends(get_db)]


class _CommentBody(BaseModel):
    body: str


class _AssignBody(BaseModel):
    assignee_id: uuid.UUID | None = None


def _audit_ctx(request: Request) -> dict:
    return {
        "ip_address": (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                       or (request.client.host if request.client else None)),
        "request_id": getattr(request.state, "request_id", None),
    }


def _alert_dict(a: Alert) -> dict:
    return {
        "id": str(a.id),
        "dedup_key": a.dedup_key,
        "source": a.source,
        "severity": a.severity,
        "status": a.status,
        "title": a.title,
        "description": a.description,
        "target_type": a.target_type,
        "target_id": a.target_id,
        "occurrences": a.occurrences,
        "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
        "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        "assignee_id": str(a.assignee_id) if a.assignee_id else None,
        "acknowledged_by": a.acknowledged_by_email,
        "resolved_by": a.resolved_by_email,
    }


@router.get("/alerts")
async def list_alerts(
    admin: _Read,
    db: _DB,
    status: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> dict:
    base = select(Alert)
    count_base = select(func.count()).select_from(Alert)
    conds = []
    if status:
        conds.append(Alert.status == status)
    if severity:
        conds.append(Alert.severity == severity)
    if source:
        conds.append(Alert.source == source)
    for c in conds:
        base = base.where(c)
        count_base = count_base.where(c)
    total = await db.scalar(count_base) or 0
    rows = await db.scalars(
        base.order_by(Alert.last_seen_at.desc()).limit(limit).offset(offset)
    )
    return {
        "items": [_alert_dict(a) for a in rows.all()],
        "total": int(total), "limit": limit, "offset": offset,
    }


@router.get("/alerts/summary")
async def alerts_summary(admin: _Read, db: _DB) -> dict:
    """Open-alert counts for the nav badge + severity breakdown."""
    rows = await db.execute(
        select(Alert.severity, func.count())
        .where(Alert.status.in_(("open", "acknowledged")))
        .group_by(Alert.severity)
    )
    by_sev = {str(s): int(n) for s, n in rows.all()}
    open_count = await db.scalar(
        select(func.count()).select_from(Alert).where(Alert.status == "open")
    ) or 0
    return {
        "open": int(open_count),
        "active": sum(by_sev.values()),
        "by_severity": by_sev,
    }


@router.get("/alerts/{alert_id}")
async def alert_detail(alert_id: uuid.UUID, admin: _Read, db: _DB) -> dict:
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    crows = await db.scalars(
        select(AlertComment).where(AlertComment.alert_id == alert_id)
        .order_by(AlertComment.created_at)
    )
    out = _alert_dict(alert)
    out["detail"] = alert.detail
    out["comments"] = [
        {
            "id": str(c.id), "kind": c.kind, "author": c.author_email,
            "body": c.body, "at": c.created_at.isoformat() if c.created_at else None,
        }
        for c in crows.all()
    ]
    return out


async def _load(db: AsyncSession, alert_id: uuid.UUID) -> Alert:
    alert = await db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/alerts/{alert_id}/ack")
async def ack_alert(alert_id: uuid.UUID, admin: _Op, db: _DB, request: Request) -> dict:
    alert = await _load(db, alert_id)
    await alert_svc.acknowledge(db, alert, actor_email=admin.email)
    await record_action(db, actor=admin, action="alert.ack", target_type="alert",
                        target_id=str(alert_id), **_audit_ctx(request))
    await db.commit()
    await alert_svc.publish_alert_event({"type": "ack", "id": str(alert_id)})
    return {"ok": True, "status": "acknowledged"}


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: uuid.UUID, admin: _Op, db: _DB, request: Request) -> dict:
    alert = await _load(db, alert_id)
    await alert_svc.resolve(db, alert, actor_email=admin.email)
    await record_action(db, actor=admin, action="alert.resolve", target_type="alert",
                        target_id=str(alert_id), **_audit_ctx(request))
    await db.commit()
    await alert_svc.publish_alert_event({"type": "resolve", "id": str(alert_id)})
    return {"ok": True, "status": "resolved"}


@router.post("/alerts/{alert_id}/assign")
async def assign_alert(alert_id: uuid.UUID, body: _AssignBody, admin: _Op, db: _DB,
                       request: Request) -> dict:
    alert = await _load(db, alert_id)
    assignee_email = None
    if body.assignee_id is not None:
        assignee = await db.get(User, body.assignee_id)
        if assignee is None:
            raise HTTPException(status_code=404, detail="Assignee not found")
        assignee_email = assignee.email
    await alert_svc.assign(db, alert, assignee_id=body.assignee_id,
                           assignee_email=assignee_email, actor_email=admin.email)
    await record_action(db, actor=admin, action="alert.assign", target_type="alert",
                        target_id=str(alert_id),
                        detail={"assignee": assignee_email}, **_audit_ctx(request))
    await db.commit()
    await alert_svc.publish_alert_event({"type": "assign", "id": str(alert_id)})
    return {"ok": True, "assignee": assignee_email}


@router.post("/alerts/{alert_id}/comment")
async def comment_alert(alert_id: uuid.UUID, body: _CommentBody, admin: _Op, db: _DB,
                        request: Request) -> dict:
    text = body.body.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Comment body required")
    alert = await _load(db, alert_id)
    await alert_svc.add_comment(db, alert, body=text, author_email=admin.email)
    await record_action(db, actor=admin, action="alert.comment", target_type="alert",
                        target_id=str(alert_id), **_audit_ctx(request))
    await db.commit()
    await alert_svc.publish_alert_event({"type": "comment", "id": str(alert_id)})
    return {"ok": True}


@router.get("/stream")
async def event_stream(admin: _Read, request: Request) -> StreamingResponse:
    """Server-Sent Events: live SOC alert/activity pings via Redis pub/sub.

    The browser consumes this with fetch + a stream reader (so the Bearer token
    can be sent as a header). Each payload is a small JSON 'something changed'
    ping; the client refetches the affected resource.
    """
    settings = get_settings()

    async def gen():
        r = None
        pubsub = None
        try:
            r = aioredis.from_url(settings.redis_url, socket_connect_timeout=2,
                                  decode_responses=True)
            pubsub = r.pubsub()
            await pubsub.subscribe(alert_svc.ALERT_EVENT_CHANNEL)
            yield ": connected\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=15)
                except Exception:  # noqa: BLE001
                    break
                if msg and msg.get("type") == "message":
                    yield f"data: {msg['data']}\n\n"
                else:
                    yield ": keepalive\n\n"  # comment frame keeps the connection warm
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.debug("SSE stream error", exc_info=True)
        finally:
            try:
                if pubsub is not None:
                    await pubsub.unsubscribe(alert_svc.ALERT_EVENT_CHANNEL)
                    await pubsub.aclose()
                if r is not None:
                    await r.aclose()
            except Exception:  # noqa: BLE001
                pass

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
        "Connection": "keep-alive",
    })
