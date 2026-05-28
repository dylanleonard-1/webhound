# WebHound — apps/api/services/alerts.py
# SOC alert lifecycle. Used by the worker evaluator (to upsert/auto-resolve
# derived alerts) and the /internal API (ack/assign/resolve/comment).
#
# Mutators add/flush within the caller's transaction; the caller commits, then
# calls publish_alert_event() so the SSE stream (/internal/stream) wakes up.

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.config import get_settings
from apps.api.models.alert import Alert, AlertComment

logger = logging.getLogger(__name__)

ALERT_EVENT_CHANNEL = "webhound:alerts:events"

# Sources whose condition is continuously re-evaluated, so they can be
# auto-resolved when healthy again (vs. point-in-time events like a scan failure).
HEALTH_SOURCES = frozenset({"worker_down", "queue_backup", "engine_reliability", "infra_redis"})


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _add_comment(db: AsyncSession, alert: Alert, *, kind: str, body: str,
                       author_email: str | None = None) -> None:
    db.add(AlertComment(alert_id=alert.id, kind=kind, body=body, author_email=author_email))


async def upsert_alert(
    db: AsyncSession,
    *,
    dedup_key: str,
    source: str,
    severity: str,
    title: str,
    description: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
) -> tuple[Alert, bool]:
    """Create the alert, or bump an existing one with the same dedup_key.

    Returns (alert, created). A resolved alert that recurs is re-opened.
    """
    existing = await db.scalar(sa.select(Alert).where(Alert.dedup_key == dedup_key))
    now = _now()
    if existing is None:
        alert = Alert(
            dedup_key=dedup_key, source=source, severity=severity, status="open",
            title=title, description=description, target_type=target_type,
            target_id=target_id, detail=detail or {}, occurrences=1,
            first_seen_at=now, last_seen_at=now,
        )
        db.add(alert)
        await db.flush()
        await _add_comment(db, alert, kind="system", body="Alert opened.")
        return alert, True

    reopened = existing.status in ("resolved", "suppressed")
    existing.occurrences += 1
    existing.last_seen_at = now
    existing.severity = severity
    existing.title = title
    existing.description = description
    if detail is not None:
        existing.detail = detail
    if reopened:
        existing.status = "open"
        existing.resolved_at = None
        existing.resolved_by_email = None
        await _add_comment(db, existing, kind="system",
                           body="Re-opened — condition recurred.")
    await db.flush()
    return existing, False


async def auto_resolve(db: AsyncSession, dedup_key: str, *, note: str) -> bool:
    """Resolve an open/acknowledged alert because its condition cleared.

    Returns True if an alert was resolved. Used by the evaluator for health
    sources (worker recovered, queue drained, engine reliability restored).
    """
    alert = await db.scalar(
        sa.select(Alert).where(
            Alert.dedup_key == dedup_key, Alert.status.in_(("open", "acknowledged"))
        )
    )
    if alert is None:
        return False
    alert.status = "resolved"
    alert.resolved_at = _now()
    alert.resolved_by_email = "system"
    await _add_comment(db, alert, kind="system", body=note)
    await db.flush()
    return True


async def acknowledge(db: AsyncSession, alert: Alert, *, actor_email: str | None) -> Alert:
    alert.status = "acknowledged"
    alert.acknowledged_at = _now()
    alert.acknowledged_by_email = actor_email
    await _add_comment(db, alert, kind="status_change",
                       body=f"Acknowledged by {actor_email or 'staff'}.")
    await db.flush()
    return alert


async def resolve(db: AsyncSession, alert: Alert, *, actor_email: str | None) -> Alert:
    alert.status = "resolved"
    alert.resolved_at = _now()
    alert.resolved_by_email = actor_email
    await _add_comment(db, alert, kind="status_change",
                       body=f"Resolved by {actor_email or 'staff'}.")
    await db.flush()
    return alert


async def assign(db: AsyncSession, alert: Alert, *, assignee_id, assignee_email: str | None,
                 actor_email: str | None) -> Alert:
    alert.assignee_id = assignee_id
    await _add_comment(db, alert, kind="status_change",
                       body=f"Assigned to {assignee_email or assignee_id} by {actor_email or 'staff'}.")
    await db.flush()
    return alert


async def add_comment(db: AsyncSession, alert: Alert, *, body: str,
                      author_email: str | None) -> AlertComment:
    comment = AlertComment(alert_id=alert.id, kind="comment", body=body, author_email=author_email)
    db.add(comment)
    await db.flush()
    return comment


async def publish_alert_event(payload: dict) -> None:
    """Best-effort publish to the SSE fan-out channel. Never raises."""
    try:
        import redis.asyncio as aioredis

        r = aioredis.from_url(get_settings().redis_url, socket_connect_timeout=2)
        await r.publish(ALERT_EVENT_CHANNEL, json.dumps(payload))
        await r.aclose()
    except Exception:  # noqa: BLE001
        logger.debug("alert event publish failed (non-fatal)", exc_info=True)
