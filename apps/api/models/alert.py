# WebHound — apps/api/models/alert.py
# SOC alerts + their timeline comments. Alerts are derived from observable
# system state by the worker evaluator (worker/alert_tasks.py) and deduped by
# `dedup_key`, so a recurring condition bumps one row rather than spamming new
# ones. Staff acknowledge / assign / resolve them from the /control SOC.

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin

if TYPE_CHECKING:
    pass


class Alert(Base, UpdatedAtMixin):
    __tablename__ = "alerts"
    __table_args__ = (
        sa.Index("ix_alerts_status_severity", "status", "severity"),
        sa.Index("ix_alerts_last_seen_at", "last_seen_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Stable identity for an alert condition; the evaluator upserts on this so
    # a flapping engine or down worker is a single row with a rising count.
    dedup_key: Mapped[str] = mapped_column(sa.String(200), unique=True, index=True)
    source: Mapped[str] = mapped_column(sa.String(48), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(sa.String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        sa.String(16), nullable=False, default="open", server_default="open", index=True
    )

    title: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(sa.Text)
    target_type: Mapped[str | None] = mapped_column(sa.String(48))
    target_id: Mapped[str | None] = mapped_column(sa.String(64))

    # JSONB in prod (Postgres); JSON on SQLite so the test fixture can build it.
    detail: Mapped[dict] = mapped_column(
        JSONB().with_variant(sa.JSON(), "sqlite"), default=dict, server_default="{}"
    )
    occurrences: Mapped[int] = mapped_column(sa.Integer, default=1, server_default="1", nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    # Indexed via __table_args__ ix_alerts_last_seen_at (the list-ordering index).
    last_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")
    )

    # Multi-tenancy scoping (Phase-4). Nullable until backfill — set by the
    # alert evaluator from the upstream target's website.org_id when known.
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("orgs.id", ondelete="SET NULL"),
        index=True,
    )

    acknowledged_by_email: Mapped[str | None] = mapped_column(sa.String(320))
    acknowledged_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    resolved_by_email: Mapped[str | None] = mapped_column(sa.String(320))
    resolved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    comments: Mapped[list["AlertComment"]] = relationship(
        "AlertComment", back_populates="alert", cascade="all, delete-orphan",
        order_by="AlertComment.created_at",
    )


class AlertComment(Base, UpdatedAtMixin):
    __tablename__ = "alert_comments"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    # "comment" = human note, "status_change"/"system" = automated timeline entry.
    kind: Mapped[str] = mapped_column(sa.String(24), nullable=False, default="comment")
    author_email: Mapped[str | None] = mapped_column(sa.String(320))
    body: Mapped[str] = mapped_column(sa.Text, nullable=False)

    alert: Mapped["Alert"] = relationship("Alert", back_populates="comments")
