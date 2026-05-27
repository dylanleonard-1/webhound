# WebHound — apps/api/models/admin_audit_log.py
# Immutable audit trail for every privileged action taken in the internal
# /control command center (logins, role changes, bans, scan deletions,
# subscription changes, etc.). Append-only by convention; never updated.

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.database import Base


class AdminAuditLog(Base):
    __tablename__ = "admin_audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # The staff member who performed the action (nullable for system events).
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    actor_email: Mapped[str | None] = mapped_column(sa.String(320))
    actor_role: Mapped[str | None] = mapped_column(sa.String(32))

    action: Mapped[str] = mapped_column(sa.String(80), nullable=False, index=True)
    # What the action targeted, e.g. ("user", "<uuid>") or ("scan_job", "<uuid>").
    target_type: Mapped[str | None] = mapped_column(sa.String(48), index=True)
    target_id: Mapped[str | None] = mapped_column(sa.String(64), index=True)

    # Arbitrary structured context (diffs, reasons, request metadata).
    detail: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    ip_address: Mapped[str | None] = mapped_column(sa.String(64))
    request_id: Mapped[str | None] = mapped_column(sa.String(64))

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False, index=True
    )
