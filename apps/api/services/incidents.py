# WebHound — apps/api/services/incidents.py
# SOC incident management. Alerts are deduped grouping atoms; incidents are
# a higher-level grouping of related alerts that staff actually work on.
#
# Correlation key: `<source>:<target_type>:<target_id>` when a target exists,
# else just `<source>`. Re-firing alerts within an active incident's lifetime
# attach to the same incident (bumping alert_count + last_seen). When all
# alerts go quiet for the cooldown window we leave the incident open so an
# analyst can still review it — the resolve happens manually.

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.alert import Alert
from apps.api.models.incident import Incident, IncidentEvent
from apps.api.telemetry import (
    Event, EventKind, Severity, publish_event, severity_rank,
)

logger = logging.getLogger(__name__)

VALID_STATUSES = ("open", "acknowledged", "investigating", "mitigated",
                  "resolved", "suppressed")
ACTIVE_STATUSES = ("open", "acknowledged", "investigating")
TERMINAL_STATUSES = ("resolved", "suppressed")


# SLA targets per severity — soft deadlines used by the SLA pill on the queue.
_SLA_HOURS: dict[str, int] = {
    "critical": 1, "high": 4, "medium": 24, "low": 72, "info": 168,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sla_for(severity: str) -> datetime:
    return _now() + timedelta(hours=_SLA_HOURS.get(severity, 24))


def _correlation_key(*, source: str, target_type: str | None,
                     target_id: str | None, dedup_key: str | None) -> str:
    if target_type and target_id:
        return f"{source}:{target_type}:{target_id}"
    if dedup_key:
        return dedup_key
    return source


async def _next_number(db: AsyncSession) -> int:
    cur = await db.scalar(select(func.coalesce(func.max(Incident.number), 0)))
    return int(cur or 0) + 1


async def _add_event(db: AsyncSession, incident: Incident, *,
                     kind: str, body: str,
                     author_email: str | None = None,
                     alert_id: uuid.UUID | None = None) -> IncidentEvent:
    ev = IncidentEvent(
        incident_id=incident.id, kind=kind, body=body,
        author_email=author_email, alert_id=alert_id,
    )
    db.add(ev)
    await db.flush()
    return ev


def is_breached(incident: Incident) -> bool:
    if (incident.status in TERMINAL_STATUSES
            or incident.mitigated_at is not None
            or incident.sla_due_at is None):
        return False
    due = incident.sla_due_at
    if due.tzinfo is None:
        due = due.replace(tzinfo=timezone.utc)
    return due < _now()


# --- Correlation ------------------------------------------------------------


async def correlate_alert(db: AsyncSession, alert: Alert) -> Incident:
    """Attach this alert to an open incident with the same correlation key,
    or create a new one. Always returns the incident (caller can deep-link).

    Severity escalates: if the alert is more severe than the incident, the
    incident severity is bumped and the timeline records it."""
    key = _correlation_key(
        source=alert.source, target_type=alert.target_type,
        target_id=alert.target_id, dedup_key=alert.dedup_key,
    )
    existing = await db.scalar(
        select(Incident).where(
            Incident.correlation_key == key,
            Incident.status.in_(ACTIVE_STATUSES),
        ).order_by(Incident.last_seen_at.desc())
    )
    now = _now()
    if existing is None:
        incident = Incident(
            number=await _next_number(db),
            correlation_key=key, source=alert.source,
            title=alert.title or f"Incident from {alert.source}",
            severity=alert.severity, status="open",
            target_type=alert.target_type, target_id=alert.target_id,
            detail={"first_alert_id": str(alert.id)},
            alert_count=1, first_seen_at=now, last_seen_at=now,
            sla_due_at=_sla_for(alert.severity),
        )
        db.add(incident)
        await db.flush()
        await _add_event(db, incident, kind="system",
                         body=f"Incident opened from alert {alert.id} (severity={alert.severity}).",
                         alert_id=alert.id)
        await publish_event(Event(
            kind=EventKind.INCIDENT_OPENED, severity=alert.severity,
            source=alert.source, message=incident.title,
            target_type="incident", target_id=str(incident.id),
            detail={"number": incident.number, "alert_id": str(alert.id)},
        ))
        return incident

    # Attach to the existing incident.
    existing.last_seen_at = now
    existing.alert_count += 1
    bumped = False
    if severity_rank(alert.severity) > severity_rank(existing.severity):
        prior = existing.severity
        existing.severity = alert.severity
        existing.sla_due_at = _sla_for(alert.severity)   # tighter SLA
        bumped = True
        await _add_event(db, existing, kind="system",
                         body=f"Severity escalated {prior} → {alert.severity}.",
                         alert_id=alert.id)
    await _add_event(db, existing, kind="alert_attached",
                     body=f"Alert {alert.id} attached (occurrences now {existing.alert_count}).",
                     alert_id=alert.id)
    if bumped:
        await publish_event(Event(
            kind=EventKind.INCIDENT_STATUS, severity=alert.severity,
            source=alert.source, message=f"Incident #{existing.number} escalated",
            target_type="incident", target_id=str(existing.id),
        ))
    await db.flush()
    return existing


# --- Queue / detail / lifecycle -------------------------------------------


async def search(
    db: AsyncSession, *,
    status: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    assignee_id: uuid.UUID | None = None,
    breached_only: bool = False,
    limit: int = 50, offset: int = 0,
) -> tuple[list[Incident], int]:
    base = select(Incident)
    count_base = select(func.count()).select_from(Incident)
    conds = []
    if status:
        conds.append(Incident.status == status)
    if severity:
        conds.append(Incident.severity == severity)
    if source:
        conds.append(Incident.source == source)
    if assignee_id:
        conds.append(Incident.assignee_id == assignee_id)
    if breached_only:
        conds.append(Incident.sla_due_at.is_not(None))
        conds.append(Incident.sla_due_at < _now())
        conds.append(Incident.status.in_(ACTIVE_STATUSES))
    for c in conds:
        base = base.where(c)
        count_base = count_base.where(c)
    total = await db.scalar(count_base) or 0
    rows = await db.scalars(
        base.order_by(Incident.last_seen_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), int(total)


async def summary(db: AsyncSession) -> dict:
    """Counts for the nav badge + the command-center banner."""
    by_status_rows = await db.execute(
        select(Incident.status, func.count()).group_by(Incident.status)
    )
    by_status = {str(s): int(n) for s, n in by_status_rows.all()}
    by_sev_rows = await db.execute(
        select(Incident.severity, func.count())
        .where(Incident.status.in_(ACTIVE_STATUSES))
        .group_by(Incident.severity)
    )
    by_severity = {str(s): int(n) for s, n in by_sev_rows.all()}
    breached = await db.scalar(
        select(func.count()).select_from(Incident).where(
            Incident.sla_due_at.is_not(None),
            Incident.sla_due_at < _now(),
            Incident.status.in_(ACTIVE_STATUSES),
        )
    ) or 0
    active = sum(by_severity.values())
    # The highest-severity active incident drives the banner.
    top = await db.scalar(
        select(Incident)
        .where(Incident.status.in_(ACTIVE_STATUSES))
        .order_by(sa.case(
            (Incident.severity == "critical", 4),
            (Incident.severity == "high", 3),
            (Incident.severity == "medium", 2),
            (Incident.severity == "low", 1),
            else_=0,
        ).desc(), Incident.last_seen_at.desc())
        .limit(1)
    )
    return {
        "active": int(active),
        "by_status": by_status,
        "by_severity": by_severity,
        "breached": int(breached),
        "top": _incident_summary(top) if top else None,
    }


def _incident_summary(i: Incident) -> dict:
    return {
        "id": str(i.id), "number": i.number, "title": i.title,
        "severity": i.severity, "status": i.status,
        "alert_count": i.alert_count,
        "last_seen_at": i.last_seen_at.isoformat() if i.last_seen_at else None,
        "breached": is_breached(i),
    }


def to_dict(i: Incident) -> dict:
    return {
        "id": str(i.id), "number": i.number,
        "correlation_key": i.correlation_key,
        "source": i.source, "title": i.title,
        "severity": i.severity, "status": i.status,
        "target_type": i.target_type, "target_id": i.target_id,
        "detail": dict(i.detail or {}), "alert_count": i.alert_count,
        "assignee_id": str(i.assignee_id) if i.assignee_id else None,
        "first_seen_at": i.first_seen_at.isoformat() if i.first_seen_at else None,
        "last_seen_at": i.last_seen_at.isoformat() if i.last_seen_at else None,
        "sla_due_at": i.sla_due_at.isoformat() if i.sla_due_at else None,
        "acknowledged_at": i.acknowledged_at.isoformat() if i.acknowledged_at else None,
        "acknowledged_by": i.acknowledged_by_email,
        "mitigated_at": i.mitigated_at.isoformat() if i.mitigated_at else None,
        "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
        "resolved_by": i.resolved_by_email,
        "mttr_seconds": i.mttr_seconds,
        "breached": is_breached(i),
    }


async def list_events(db: AsyncSession, incident_id: uuid.UUID) -> list[dict]:
    rows = await db.scalars(
        select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
        .order_by(IncidentEvent.created_at)
    )
    return [
        {
            "id": str(e.id), "kind": e.kind, "author": e.author_email,
            "body": e.body, "alert_id": str(e.alert_id) if e.alert_id else None,
            "at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in rows.all()
    ]


async def change_status(db: AsyncSession, incident: Incident, status: str, *,
                        actor_email: str | None) -> Incident:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {status}")
    if status == incident.status:
        return incident
    prior = incident.status
    incident.status = status
    now = _now()
    if status == "acknowledged" and incident.acknowledged_at is None:
        incident.acknowledged_at = now
        incident.acknowledged_by_email = actor_email
    if status == "mitigated" and incident.mitigated_at is None:
        incident.mitigated_at = now
    if status == "resolved":
        incident.resolved_at = now
        incident.resolved_by_email = actor_email
        # MTTR = first_seen → resolved. SQLite strips tzinfo on reload, so
        # normalize before subtracting to keep this portable.
        if incident.first_seen_at:
            first = incident.first_seen_at
            if first.tzinfo is None:
                first = first.replace(tzinfo=timezone.utc)
            delta = (now - first).total_seconds()
            incident.mttr_seconds = int(max(0, delta))
    if prior in TERMINAL_STATUSES and status not in TERMINAL_STATUSES:
        # Re-open clears terminal timestamps so the timers make sense.
        incident.resolved_at = None
        incident.resolved_by_email = None
        incident.mttr_seconds = None
    await _add_event(db, incident, kind="status_change",
                     body=f"Status: {prior} → {status}",
                     author_email=actor_email)
    await publish_event(Event(
        kind=EventKind.INCIDENT_STATUS, severity=incident.severity,
        source=incident.source, message=f"Incident #{incident.number} → {status}",
        target_type="incident", target_id=str(incident.id),
        actor_email=actor_email,
    ))
    return incident


async def assign(db: AsyncSession, incident: Incident, *,
                 assignee_id: uuid.UUID | None,
                 assignee_email: str | None,
                 actor_email: str | None) -> Incident:
    incident.assignee_id = assignee_id
    await _add_event(db, incident, kind="system",
                     body=f"Assigned to {assignee_email or assignee_id or 'nobody'} "
                          f"by {actor_email or 'staff'}.",
                     author_email=actor_email)
    return incident


async def add_note(db: AsyncSession, incident: Incident, *,
                   body: str, author_email: str | None) -> IncidentEvent:
    return await _add_event(db, incident, kind="note", body=body,
                            author_email=author_email)
