from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Enum as SAEnum, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin
from apps.api.models.enums import ScheduleFrequency, ScanProfile

if TYPE_CHECKING:
    from apps.api.models.user import User
    from apps.api.models.website import Website


class ScanSchedule(Base, UpdatedAtMixin):
    __tablename__ = "scan_schedules"
    __table_args__ = (
        sa.Index("ix_scan_schedules_enabled_next", "is_enabled", "next_run_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Multi-tenancy scoping (Phase-4). Nullable until backfill.
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("orgs.id", ondelete="SET NULL"),
        index=True,
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    profile: Mapped[ScanProfile] = mapped_column(
        SAEnum(ScanProfile, name="scanprofile", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=ScanProfile.STANDARD,
    )
    frequency: Mapped[ScheduleFrequency] = mapped_column(
        SAEnum(ScheduleFrequency, name="schedulefrequency", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    is_enabled: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    use_latest_baseline: Mapped[bool] = mapped_column(
        sa.Boolean, default=True, nullable=False
    )
    save_baseline: Mapped[bool] = mapped_column(
        sa.Boolean, default=True, nullable=False
    )
    next_run_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, index=True
    )
    last_run_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    user: Mapped["User"] = relationship("User", back_populates="scan_schedules")
    website: Mapped["Website"] = relationship("Website", back_populates="scan_schedules")
