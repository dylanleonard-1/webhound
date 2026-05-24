from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin
from apps.api.models.enums import PlanTier, SubscriptionStatus

if TYPE_CHECKING:
    from apps.api.models.user import User


class Subscription(Base, UpdatedAtMixin):
    """A user's Stripe subscription state, mirrored locally.

    The single source of truth is Stripe — this table is updated from
    webhook events. Reading from it (rather than calling Stripe on every
    request) gives quota enforcement constant-time access to the user's
    current plan.
    """

    __tablename__ = "subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )

    stripe_subscription_id: Mapped[str] = mapped_column(
        sa.String(64), unique=True, nullable=False, index=True,
    )
    stripe_customer_id: Mapped[str] = mapped_column(
        sa.String(64), nullable=False, index=True,
    )
    stripe_price_id: Mapped[str | None] = mapped_column(sa.String(64))

    status: Mapped[SubscriptionStatus] = mapped_column(
        sa.Enum(SubscriptionStatus, name="subscriptionstatus",
                values_callable=lambda e: [v.value for v in e]),
        nullable=False, index=True,
    )
    plan: Mapped[PlanTier] = mapped_column(
        sa.Enum(PlanTier, name="plantier", values_callable=lambda e: [v.value for v in e],
                create_type=False),
        nullable=False,
    )

    current_period_start: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
    )
    current_period_end: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True), index=True,
    )
    cancel_at_period_end: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, nullable=False,
    )
    canceled_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False,
    )

    user: Mapped["User"] = relationship("User", back_populates="subscriptions")
