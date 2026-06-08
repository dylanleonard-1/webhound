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
    # Multi-tenancy scoping (Phase-4) — denormalised from
    # ``website.org_id`` so org-scoped scan queries don't need a join.
    # Nullable until the backfill migration runs.
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("orgs.id", ondelete="SET NULL"),
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

    # FIX 9 — liveness. The worker stamps heartbeat_at when it picks the job up
    # (RUNNING) and again at each scan-phase boundary; the stale-job reaper marks
    # a RUNNING job whose heartbeat stopped advancing (worker died/hung) as
    # failed. Nullable: legacy rows and freshly-queued jobs have no heartbeat.
    heartbeat_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    # FIX 10 — cooperative cancellation. The API sets this when a user cancels a
    # RUNNING scan; the worker checks it between scan phases and aborts
    # (ScanCancelled) so the job ends CANCELLED instead of completing.
    cancellation_requested: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default=sa.false()
    )

    # Slice 4.A — public/guest scan flow. When a visitor enters a
    # URL on /scan without an account, we create the scan_job with
    # a guest_token; the public router only looks up jobs by this
    # token (never by id) so a guest can't enumerate other scans.
    # Nullable for every existing scan path (authenticated scans
    # don't set it).
    guest_token: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), index=True, unique=True,
    )

    website: Mapped["Website"] = relationship("Website", back_populates="scan_jobs")
    result: Mapped["ScanResultRecord | None"] = relationship(
        "ScanResultRecord", back_populates="scan_job", uselist=False,
        cascade="all, delete-orphan", single_parent=True,
        passive_deletes=True,
    )
