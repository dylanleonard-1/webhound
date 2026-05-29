# WebHound — apps/api/models/incident.py
# Phase 10: SOC incident management. An incident is a correlated grouping of
# one or more alerts (typically same source + target within a time window),
# with a status workflow, ownership, MTTR + SLA, and a per-incident timeline.

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin


class Incident(Base, UpdatedAtMixin):
    """One operational incident — the unit analysts work on. Alerts attach to
    incidents (an alert may be unattached briefly while the correlator
    decides). Status flows: open → acknowledged → investigating → mitigated
    → resolved. `suppressed` is a terminal state for false positives."""

    __tablename__ = "incidents"
    __table_args__ = (
        sa.Index("ix_incidents_status_severity", "status", "severity"),
        sa.Index("ix_incidents_last_seen_at", "last_seen_at"),
        sa.Index("ix_incidents_correlation_key", "correlation_key"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Display tag (INC-####), populated by the service at creation time.
    number: Mapped[int] = mapped_column(sa.Integer, nullable=False, unique=True, index=True)

    # Stable key the correlator uses to find an open incident to attach a new
    # alert to. Typically `<source>:<target_type>:<target_id>` or just the
    # alert's dedup_key when no target.
    # Indexed via __table_args__ ix_incidents_correlation_key.
    correlation_key: Mapped[str] = mapped_column(sa.String(220), nullable=False)
    source: Mapped[str] = mapped_column(sa.String(48), nullable=False, index=True)
    title: Mapped[str] = mapped_column(sa.String(220), nullable=False)
    severity: Mapped[str] = mapped_column(sa.String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        sa.String(20), nullable=False, default="open", server_default="open", index=True
    )

    # Optional pointers — useful for "show me incidents about user X / scan Y".
    target_type: Mapped[str | None] = mapped_column(sa.String(48))
    target_id: Mapped[str | None] = mapped_column(sa.String(64))

    # Multi-tenancy scoping (Phase-4). Nullable until backfill / cutover.
    # Incidents are typically about a customer asset, so this is normally
    # populated by the correlator from the related alert / scan_job.
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("orgs.id", ondelete="SET NULL"),
        index=True,
    )

    detail: Mapped[dict] = mapped_column(
        JSONB().with_variant(sa.JSON(), "sqlite"),
        default=dict, server_default="{}",
    )
    # How many alert rows are attached. The service maintains this rather than
    # joining alerts on every list — keeps the queue page cheap.
    alert_count: Mapped[int] = mapped_column(sa.Integer, default=1,
                                             server_default="1", nullable=False)

    first_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    # SLA: the soft deadline by which we should have at least mitigated. Set
    # at creation based on severity (configurable; defaults in service).
    sla_due_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"),
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    acknowledged_by_email: Mapped[str | None] = mapped_column(sa.String(320))
    mitigated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    resolved_by_email: Mapped[str | None] = mapped_column(sa.String(320))

    # MTTR (mean time to resolve) for this incident in seconds — computed at
    # resolution time so historical reporting is free.
    mttr_seconds: Mapped[int | None] = mapped_column(sa.Integer)

    events: Mapped[list["IncidentEvent"]] = relationship(
        "IncidentEvent", back_populates="incident", cascade="all, delete-orphan",
        order_by="IncidentEvent.created_at",
    )


class IncidentEvent(Base, UpdatedAtMixin):
    """Per-incident timeline entry. Kinds:
       - alert_attached / alert_updated — the correlator wrote one
       - status_change — open → ack → investigating → mitigated → resolved
       - note — a human investigation note
       - system — anything else (re-open, severity bump, auto-assign)"""

    __tablename__ = "incident_events"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    kind: Mapped[str] = mapped_column(sa.String(24), nullable=False, default="note")
    author_email: Mapped[str | None] = mapped_column(sa.String(320))
    body: Mapped[str] = mapped_column(sa.Text, nullable=False)
    # Optional ID of the alert this event references when kind==alert_*.
    alert_id: Mapped[uuid.UUID | None] = mapped_column(sa.Uuid(as_uuid=True))

    incident: Mapped["Incident"] = relationship("Incident", back_populates="events")
