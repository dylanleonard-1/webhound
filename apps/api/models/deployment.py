# WebHound — apps/api/models/deployment.py
# Phase 7: deploy history. Rows are recorded manually by staff (or by a CI
# hook later) so we have an audit trail of what shipped, when, and by whom.
# The Railway-injected RAILWAY_GIT_COMMIT_SHA env var is the source of truth
# for "what's running right now"; this table is the history.

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin


class Deployment(Base, TimestampMixin):
    __tablename__ = "deployments"
    __table_args__ = (
        sa.Index("ix_deployments_service_started_at", "service", "started_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    service: Mapped[str] = mapped_column(sa.String(32), nullable=False, index=True)
    sha: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        sa.String(24), nullable=False, default="succeeded",
        server_default="succeeded", index=True,
    )
    actor_email: Mapped[str | None] = mapped_column(sa.String(320))
    note: Mapped[str | None] = mapped_column(sa.Text)
    started_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
