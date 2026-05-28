# WebHound — apps/api/models/support_ticket.py
# Phase 6: Support / Fix Service. A ticket is the unit of work staff handle
# for a customer — most often a remediation request after a scan turned up
# findings. Customer = `user_id`; the scan that produced the issue =
# `source_scan_id`; a verification rescan that confirms the fix =
# `verification_scan_id`. SLA is computed at creation from the customer's
# plan tier and locked onto the row.

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin

if TYPE_CHECKING:
    pass


class SupportTicket(Base, UpdatedAtMixin):
    __tablename__ = "support_tickets"
    __table_args__ = (
        sa.Index("ix_support_tickets_status_priority", "status", "priority"),
        sa.Index("ix_support_tickets_assignee_id", "assignee_id"),
        sa.Index("ix_support_tickets_user_id", "user_id"),
        sa.Index("ix_support_tickets_sla_due_at", "sla_due_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Short, human-friendly ticket number (e.g. WH-0042). Filled by the
    # service at creation time from an incrementing per-table count.
    number: Mapped[int] = mapped_column(sa.Integer, nullable=False, unique=True, index=True)

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    subject: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(sa.Text)
    category: Mapped[str] = mapped_column(sa.String(32), nullable=False, default="remediation")
    priority: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="medium", index=True)
    status: Mapped[str] = mapped_column(sa.String(24), nullable=False, default="open",
                                        server_default="open", index=True)

    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"),
    )

    # Optional links to scan_jobs. We keep the names symmetrical so an UI
    # can render "scan that found the issue" vs "scan that verified the fix".
    source_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"),
    )
    verification_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True), sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"),
    )

    sla_due_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    opened_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    first_response_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    events: Mapped[list["SupportTicketEvent"]] = relationship(
        "SupportTicketEvent", back_populates="ticket", cascade="all, delete-orphan",
        order_by="SupportTicketEvent.created_at",
    )


class SupportTicketEvent(Base, UpdatedAtMixin):
    """One row per timeline entry — public comments, internal notes, and
    every automated status/assignment change. `visibility='internal'` is
    staff-only (customer self-service portal won't render those)."""

    __tablename__ = "support_ticket_events"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ticket_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("support_tickets.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    kind: Mapped[str] = mapped_column(sa.String(24), nullable=False, default="comment")
    visibility: Mapped[str] = mapped_column(sa.String(16), nullable=False,
                                            default="public", server_default="public")
    author_email: Mapped[str | None] = mapped_column(sa.String(320))
    body: Mapped[str] = mapped_column(sa.Text, nullable=False)

    ticket: Mapped["SupportTicket"] = relationship("SupportTicket", back_populates="events")
