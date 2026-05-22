from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin

if TYPE_CHECKING:
    from apps.api.models.notification import Notification
    from apps.api.models.scan_schedule import ScanSchedule
    from apps.api.models.website import Website


class User(Base, UpdatedAtMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        sa.String(255), unique=True, nullable=False, index=True
    )
    hashed_password: Mapped[str | None] = mapped_column(sa.String(255))
    is_active: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)

    oauth_provider: Mapped[str | None] = mapped_column(sa.String(50))
    oauth_provider_id: Mapped[str | None] = mapped_column(sa.String(255), index=True)
    full_name: Mapped[str | None] = mapped_column(sa.String(255))
    avatar_url: Mapped[str | None] = mapped_column(sa.String(500))

    email_verified: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    email_verification_token: Mapped[str | None] = mapped_column(sa.String(128), index=True)
    email_verification_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    password_reset_token: Mapped[str | None] = mapped_column(sa.String(128), index=True)
    password_reset_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    phone_number: Mapped[str | None] = mapped_column(sa.String(32))
    phone_verified: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    phone_otp: Mapped[str | None] = mapped_column(sa.String(10))
    phone_otp_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    websites: Mapped[list["Website"]] = relationship(
        "Website", back_populates="user", cascade="all, delete-orphan"
    )
    scan_schedules: Mapped[list["ScanSchedule"]] = relationship(
        "ScanSchedule", back_populates="user", cascade="all, delete-orphan"
    )
    notifications: Mapped[list["Notification"]] = relationship(
        "Notification", back_populates="user", cascade="all, delete-orphan"
    )
