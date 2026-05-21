from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Enum as SAEnum, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin
from apps.api.models.enums import ScanProfile, ScanStatus

if TYPE_CHECKING:
    from apps.api.models.scan_result import ScanResultRecord
    from apps.api.models.website import Website


class ScanJob(Base, UpdatedAtMixin):
    __tablename__ = "scan_jobs"
    __table_args__ = (sa.Index("ix_scan_jobs_created_at", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[ScanStatus] = mapped_column(
        SAEnum(ScanStatus, name="scanstatus", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=ScanStatus.QUEUED,
        index=True,
    )
    profile: Mapped[ScanProfile] = mapped_column(
        SAEnum(ScanProfile, name="scanprofile", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=ScanProfile.STANDARD,
    )
    requested_url: Mapped[str] = mapped_column(sa.String(2048), nullable=False)
    use_latest_baseline: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, nullable=False
    )
    save_baseline: Mapped[bool] = mapped_column(
        sa.Boolean, default=True, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(sa.Text)
    celery_task_id: Mapped[str | None] = mapped_column(sa.String(255))

    website: Mapped["Website"] = relationship("Website", back_populates="scan_jobs")
    result: Mapped["ScanResultRecord | None"] = relationship(
        "ScanResultRecord", back_populates="scan_job", uselist=False
    )
