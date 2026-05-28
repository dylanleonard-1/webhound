# WebHound — apps/api/models/infrastructure_sample.py
# Phase 7: periodic snapshots of operational metrics so /control can render
# trend charts. One row per beat tick from worker.infra_tasks.sample_infra.

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.database import Base


class InfrastructureSample(Base):
    __tablename__ = "infrastructure_samples"
    __table_args__ = (
        sa.Index("ix_infra_samples_taken_at", "taken_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    taken_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    queue_depth: Mapped[int | None] = mapped_column(sa.Integer)
    worker_alive: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    worker_heartbeat_age_s: Mapped[float | None] = mapped_column(sa.Float)
    redis_used_memory_mb: Mapped[float | None] = mapped_column(sa.Float)
    active_scans: Mapped[int | None] = mapped_column(sa.Integer)
