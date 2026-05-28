# WebHound — apps/api/models/engine.py
# Phase 10: engines registry — stateful per-engine configuration (maintenance
# flag, auto-disable threshold) that can't be derived from diagnostics.
# Health/state is still derived in services/engines.compute_state.

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin


class EngineRegistry(Base, UpdatedAtMixin):
    """One row per engine name we want to override. Engines without a row
    use safe defaults — i.e. the registry is opt-in metadata, not the source
    of truth for which engines exist (that's still engine_diagnostics)."""

    __tablename__ = "engines"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(sa.String(64), nullable=False, unique=True, index=True)
    # When True the evaluator + worker treat the engine as paused.
    maintenance_mode: Mapped[bool] = mapped_column(sa.Boolean, default=False,
                                                  server_default=sa.text("false"),
                                                  nullable=False)
    # If failure rate over the recent window crosses this, the engine should
    # auto-disable + raise an incident. NULL = no auto-disable.
    auto_disable_at_failure_pct: Mapped[int | None] = mapped_column(sa.Integer)
    auto_disabled_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(sa.Text)
    updated_by_email: Mapped[str | None] = mapped_column(sa.String(320))
