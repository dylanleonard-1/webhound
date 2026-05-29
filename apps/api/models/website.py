from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Enum as SAEnum, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin, UpdatedAtMixin
from apps.api.models.enums import VerificationMethod, VerificationStatus

if TYPE_CHECKING:
    from apps.api.models.baseline import BaselineRecord
    from apps.api.models.scan_job import ScanJob
    from apps.api.models.scan_schedule import ScanSchedule
    from apps.api.models.user import User


class Website(Base, UpdatedAtMixin):
    __tablename__ = "websites"
    __table_args__ = (
        sa.UniqueConstraint("url", name="uq_websites_url"),
        sa.Index("ix_websites_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    # Multi-tenancy scoping (Phase-4). Nullable until the backfill +
    # cutover migration runs — existing single-tenant rows continue to
    # validate; new rows should set it when an org context is available.
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("orgs.id", ondelete="SET NULL"),
        index=True,
    )
    url: Mapped[str] = mapped_column(sa.String(2048), nullable=False)
    hostname: Mapped[str] = mapped_column(sa.String(255), nullable=False, index=True)
    scheme: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    display_name: Mapped[str | None] = mapped_column(sa.String(255))
    verification_status: Mapped[VerificationStatus] = mapped_column(
        SAEnum(VerificationStatus, name="verificationstatus", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=VerificationStatus.UNVERIFIED,
    )

    user: Mapped["User | None"] = relationship("User", back_populates="websites")
    domain_verifications: Mapped[list["DomainVerification"]] = relationship(
        "DomainVerification", back_populates="website", cascade="all, delete-orphan"
    )
    scan_jobs: Mapped[list["ScanJob"]] = relationship(
        "ScanJob", back_populates="website", cascade="all, delete-orphan"
    )
    baselines: Mapped[list["BaselineRecord"]] = relationship(
        "BaselineRecord", back_populates="website", cascade="all, delete-orphan"
    )
    scan_schedules: Mapped[list["ScanSchedule"]] = relationship(
        "ScanSchedule", back_populates="website", cascade="all, delete-orphan"
    )


class DomainVerification(Base, TimestampMixin):
    __tablename__ = "domain_verifications"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    method: Mapped[VerificationMethod] = mapped_column(
        SAEnum(VerificationMethod, name="verificationmethod", values_callable=lambda x: [e.value for e in x]), nullable=False
    )
    token: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    status: Mapped[VerificationStatus] = mapped_column(
        SAEnum(VerificationStatus, name="verificationstatus", values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        default=VerificationStatus.PENDING,
    )
    verified_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    website: Mapped["Website"] = relationship(
        "Website", back_populates="domain_verifications"
    )
