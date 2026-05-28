# WebHound — apps/api/models/log_record.py
# Phase 8: the queryable log store. Distinct from `admin_audit_logs` (which
# records privileged staff actions) — this is general application telemetry
# the /control Log Explorer searches over.

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.database import Base


class LogRecord(Base):
    __tablename__ = "logs"
    __table_args__ = (
        sa.Index("ix_logs_timestamp", "timestamp"),
        sa.Index("ix_logs_source_severity", "source", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    timestamp: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    source: Mapped[str] = mapped_column(sa.String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(sa.String(16), nullable=False, index=True)
    message: Mapped[str] = mapped_column(sa.Text, nullable=False)
    context: Mapped[dict] = mapped_column(
        JSONB().with_variant(sa.JSON(), "sqlite"),
        default=dict, server_default="{}",
    )
    request_id: Mapped[str | None] = mapped_column(sa.String(64), index=True)
    actor_email: Mapped[str | None] = mapped_column(sa.String(320))
