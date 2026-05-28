# WebHound — apps/api/services/support.py
# Support / Fix Service ticket lifecycle. Mutators add/flush within the
# caller's transaction; the caller commits.

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import PlanTier, ScanProfile
from apps.api.models.scan_job import ScanJob
from apps.api.models.support_ticket import SupportTicket, SupportTicketEvent
from apps.api.models.user import User

logger = logging.getLogger(__name__)

VALID_STATUSES = ("open", "in_progress", "awaiting_customer", "resolved", "closed")
TERMINAL_STATUSES = ("resolved", "closed")
VALID_PRIORITIES = ("low", "medium", "high", "urgent")
VALID_CATEGORIES = ("remediation", "question", "bug", "billing")

# SLA target time-to-resolution per plan tier. The free plan has no formal
# SLA — we still set a generous 7-day target so the breach signal isn't
# meaningless. Pro+ ticks down faster.
_SLA_HOURS: dict[PlanTier, int] = {
    PlanTier.FREE:       7 * 24,
    PlanTier.PRO:        48,
    PlanTier.SHIELD:     24,
    PlanTier.ENTERPRISE: 8,
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sla_due_for(plan: PlanTier) -> datetime:
    return _now() + timedelta(hours=_SLA_HOURS.get(plan, 7 * 24))


async def _next_number(db: AsyncSession) -> int:
    cur = await db.scalar(select(func.coalesce(func.max(SupportTicket.number), 0)))
    return int(cur or 0) + 1


# --- Lifecycle --------------------------------------------------------------


async def create_ticket(
    db: AsyncSession, *,
    user: User | None,
    subject: str,
    description: str | None = None,
    category: str = "remediation",
    priority: str = "medium",
    source_scan_id: uuid.UUID | None = None,
    author_email: str | None = None,
) -> SupportTicket:
    if category not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category: {category}")
    if priority not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority: {priority}")
    plan = user.plan if user else PlanTier.FREE
    number = await _next_number(db)
    ticket = SupportTicket(
        number=number,
        user_id=user.id if user else None,
        subject=subject.strip()[:200],
        description=description,
        category=category, priority=priority, status="open",
        source_scan_id=source_scan_id,
        sla_due_at=_sla_due_for(plan),
        opened_at=_now(),
    )
    db.add(ticket)
    await db.flush()
    db.add(SupportTicketEvent(
        ticket_id=ticket.id, kind="system", visibility="internal",
        author_email=author_email,
        body=f"Ticket opened (plan={plan.value}, sla_hours={_SLA_HOURS.get(plan, 7*24)}).",
    ))
    await db.flush()
    return ticket


async def add_event(
    db: AsyncSession, ticket: SupportTicket, *,
    kind: str, body: str, visibility: str = "public",
    author_email: str | None = None,
) -> SupportTicketEvent:
    if visibility not in ("public", "internal"):
        raise ValueError("visibility must be public or internal")
    event = SupportTicketEvent(
        ticket_id=ticket.id, kind=kind, visibility=visibility,
        body=body, author_email=author_email,
    )
    db.add(event)
    # First public response from staff stamps first_response_at — used to
    # measure responsiveness independent of full resolution.
    if (kind == "comment" and visibility == "public"
            and ticket.first_response_at is None):
        ticket.first_response_at = _now()
    await db.flush()
    return event


async def change_status(
    db: AsyncSession, ticket: SupportTicket, status: str, *,
    actor_email: str | None,
) -> SupportTicket:
    if status not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {status}")
    if status == ticket.status:
        return ticket
    prior = ticket.status
    ticket.status = status
    now = _now()
    if status == "resolved" and ticket.resolved_at is None:
        ticket.resolved_at = now
    if status == "closed" and ticket.closed_at is None:
        ticket.closed_at = now
    # Re-opening clears the terminal timestamps so the SLA clock makes sense.
    if prior in TERMINAL_STATUSES and status not in TERMINAL_STATUSES:
        ticket.resolved_at = None
        ticket.closed_at = None
    await add_event(db, ticket, kind="status_change", visibility="internal",
                    author_email=actor_email,
                    body=f"Status: {prior} → {status}")
    return ticket


async def change_priority(
    db: AsyncSession, ticket: SupportTicket, priority: str, *,
    actor_email: str | None,
) -> SupportTicket:
    if priority not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority: {priority}")
    if priority == ticket.priority:
        return ticket
    prior = ticket.priority
    ticket.priority = priority
    await add_event(db, ticket, kind="priority_change", visibility="internal",
                    author_email=actor_email,
                    body=f"Priority: {prior} → {priority}")
    return ticket


async def assign(
    db: AsyncSession, ticket: SupportTicket, assignee: User | None, *,
    actor_email: str | None,
) -> SupportTicket:
    if (assignee.id if assignee else None) == ticket.assignee_id:
        return ticket
    ticket.assignee_id = assignee.id if assignee else None
    await add_event(db, ticket, kind="assignment", visibility="internal",
                    author_email=actor_email,
                    body=f"Assigned to {assignee.email if assignee else 'nobody'}")
    return ticket


async def attach_verification_scan(
    db: AsyncSession, ticket: SupportTicket, scan_job: ScanJob, *,
    actor_email: str | None,
) -> SupportTicket:
    """Link the staff-initiated verification rescan and surface it on the
    timeline. The actual enqueue happens in the API handler so this service
    stays Celery-free for tests."""
    ticket.verification_scan_id = scan_job.id
    await add_event(db, ticket, kind="system", visibility="internal",
                    author_email=actor_email,
                    body=f"Verification rescan queued: scan {scan_job.id}")
    return ticket


# --- Queries ----------------------------------------------------------------


async def search(
    db: AsyncSession, *,
    status: str | None = None,
    priority: str | None = None,
    assignee_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    breached_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[SupportTicket], int]:
    base = select(SupportTicket)
    count_base = select(func.count()).select_from(SupportTicket)
    conds = []
    if status:
        conds.append(SupportTicket.status == status)
    if priority:
        conds.append(SupportTicket.priority == priority)
    if assignee_id:
        conds.append(SupportTicket.assignee_id == assignee_id)
    if user_id:
        conds.append(SupportTicket.user_id == user_id)
    if breached_only:
        conds.append(SupportTicket.sla_due_at.is_not(None))
        conds.append(SupportTicket.sla_due_at < _now())
        conds.append(SupportTicket.status.not_in(TERMINAL_STATUSES))
    for c in conds:
        base = base.where(c)
        count_base = count_base.where(c)
    total = await db.scalar(count_base) or 0
    rows = await db.scalars(
        base.order_by(SupportTicket.opened_at.desc()).limit(limit).offset(offset)
    )
    return list(rows.all()), int(total)


async def summary(db: AsyncSession) -> dict:
    """Used by the nav badge — counts by status + breached count."""
    rows = await db.execute(
        select(SupportTicket.status, func.count()).group_by(SupportTicket.status)
    )
    by_status = {str(s): int(n) for s, n in rows.all()}
    breached = await db.scalar(
        select(func.count()).select_from(SupportTicket).where(
            SupportTicket.sla_due_at.is_not(None),
            SupportTicket.sla_due_at < _now(),
            SupportTicket.status.not_in(TERMINAL_STATUSES),
        )
    ) or 0
    open_count = sum(by_status.get(s, 0) for s in ("open", "in_progress", "awaiting_customer"))
    return {
        "by_status": by_status,
        "open": int(open_count),
        "breached": int(breached),
    }


async def list_events(
    db: AsyncSession, ticket_id: uuid.UUID, *, include_internal: bool = True,
) -> list[dict]:
    q = select(SupportTicketEvent).where(SupportTicketEvent.ticket_id == ticket_id)
    if not include_internal:
        q = q.where(SupportTicketEvent.visibility == "public")
    rows = await db.scalars(q.order_by(SupportTicketEvent.created_at))
    return [
        {
            "id": str(e.id), "kind": e.kind, "visibility": e.visibility,
            "author": e.author_email, "body": e.body,
            "at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in rows.all()
    ]


def is_breached(ticket: SupportTicket) -> bool:
    if ticket.sla_due_at is None or ticket.status in TERMINAL_STATUSES:
        return False
    due = ticket.sla_due_at
    # SQLite strips tzinfo on reload; normalize to UTC for the comparison so
    # this works the same way in Postgres production and SQLite tests.
    if due.tzinfo is None:
        due = due.replace(tzinfo=timezone.utc)
    return due < _now()
