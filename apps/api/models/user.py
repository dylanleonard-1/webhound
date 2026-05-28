from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin
from apps.api.models.enums import PlanTier

if TYPE_CHECKING:
    from apps.api.models.notification import Notification
    from apps.api.models.scan_schedule import ScanSchedule
    from apps.api.models.subscription import Subscription
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
    # Internal-platform RBAC role (the /control command center). "none" for
    # every customer; elevated only for staff. Stored as a string so adding
    # roles never needs a Postgres enum migration.
    admin_role: Mapped[str] = mapped_column(
        sa.String(32), default="none", server_default="none", nullable=False
    )

    oauth_provider: Mapped[str | None] = mapped_column(sa.String(50))
    oauth_provider_id: Mapped[str | None] = mapped_column(sa.String(255), index=True)
    full_name: Mapped[str | None] = mapped_column(sa.String(255))
    avatar_url: Mapped[str | None] = mapped_column(sa.String(500))
    company_name: Mapped[str | None] = mapped_column(sa.String(255))
    use_case: Mapped[str | None] = mapped_column(sa.String(64))

    email_verified: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    email_verification_token: Mapped[str | None] = mapped_column(sa.String(128), index=True)
    email_verification_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    password_reset_token: Mapped[str | None] = mapped_column(sa.String(128), index=True)
    password_reset_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    login_otp: Mapped[str | None] = mapped_column(sa.String(10))
    login_otp_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    phone_number: Mapped[str | None] = mapped_column(sa.String(32))
    phone_verified: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    phone_otp: Mapped[str | None] = mapped_column(sa.String(10))
    phone_otp_expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    # Billing
    plan: Mapped[PlanTier] = mapped_column(
        sa.Enum(PlanTier, name="plantier", values_callable=lambda e: [v.value for v in e]),
        default=PlanTier.FREE, nullable=False,
    )
    stripe_customer_id: Mapped[str | None] = mapped_column(
        sa.String(64), unique=True, index=True,
    )

    # Legal: timestamp when user agreed to Terms / Privacy / AUP. NULL means
    # they have not yet agreed — AuthProvider will route them to /agreement.
    terms_agreed_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
    )

    # Operational metadata for the /control SOC:
    #   * `last_login_at` is stamped by the auth flow on successful login.
    #   * `banned_at` + `banned_reason` are set when staff suspend the account
    #     (is_active is also flipped to False so the very next request 401s).
    last_login_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    banned_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    banned_reason: Mapped[str | None] = mapped_column(sa.Text)

    websites: Mapped[list["Website"]] = relationship(
        "Website", back_populates="user", cascade="all, delete-orphan"
    )
    scan_schedules: Mapped[list["ScanSchedule"]] = relationship(
        "ScanSchedule", back_populates="user", cascade="all, delete-orphan"
    )
    notifications: Mapped[list["Notification"]] = relationship(
        "Notification", back_populates="user", cascade="all, delete-orphan"
    )
    subscriptions: Mapped[list["Subscription"]] = relationship(
        "Subscription", back_populates="user", cascade="all, delete-orphan",
    )
