# WebHound — apps/api/models/abuse.py
# Phase 5: Fraud & Abuse — flagged user/IP records + login fingerprints used
# by the evaluator to score abuse signals (excessive scans, payment failures,
# IP diversity, auth failures).

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin


class AbuseFlag(Base, UpdatedAtMixin):
    """One row per (subject, current status) — the evaluator upserts onto
    `dedup_key` so a persistent signal stays a single row with rising
    occurrences. Staff dismiss or escalate to a ban from /control/abuse."""

    __tablename__ = "abuse_flags"
    __table_args__ = (
        sa.Index("ix_abuse_flags_status_severity", "status", "severity"),
        sa.Index("ix_abuse_flags_user_id", "user_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    dedup_key: Mapped[str] = mapped_column(sa.String(200), unique=True, index=True)

    # Subject of the flag (usually a user; ip-only flags carry a null user_id).
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")
    )
    ip_address: Mapped[str | None] = mapped_column(sa.String(64))

    score: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    severity: Mapped[str] = mapped_column(sa.String(16), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        sa.String(16), nullable=False, default="pending",
        server_default="pending", index=True,
    )

    # Why this user/IP was flagged — list of short reason codes.
    reasons: Mapped[list] = mapped_column(
        JSONB().with_variant(sa.JSON(), "sqlite"),
        default=list, server_default="[]",
    )
    detail: Mapped[dict] = mapped_column(
        JSONB().with_variant(sa.JSON(), "sqlite"),
        default=dict, server_default="{}",
    )

    occurrences: Mapped[int] = mapped_column(sa.Integer, default=1, server_default="1", nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)

    resolved_by_email: Mapped[str | None] = mapped_column(sa.String(320))
    resolved_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    resolution_note: Mapped[str | None] = mapped_column(sa.Text)


class IPDeviceFingerprint(Base):
    """Lightweight (user, ip, user_agent) tuples seen on successful login.

    Upserted: every login bumps `occurrences` + `last_seen_at` on the
    matching row, or creates a new one. Used by the evaluator to flag
    accounts with anomalous IP / UA diversity.
    """

    __tablename__ = "ip_device_fingerprints"
    __table_args__ = (
        sa.UniqueConstraint("user_id", "ip_address", "user_agent",
                            name="uq_fingerprint_user_ip_ua"),
        sa.Index("ix_fingerprint_user_id", "user_id"),
        sa.Index("ix_fingerprint_last_seen_at", "last_seen_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    ip_address: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    user_agent: Mapped[str] = mapped_column(sa.String(500), nullable=False)
    occurrences: Mapped[int] = mapped_column(sa.Integer, default=1, server_default="1", nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
