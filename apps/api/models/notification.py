from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Enum as SAEnum, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin
from apps.api.models.enums import NotificationSeverity, NotificationType

if TYPE_CHECKING:
    from apps.api.models.user import User


class Notification(Base, TimestampMixin):
    __tablename__ = "notifications"
    __table_args__ = (
        sa.Index("ix_notifications_user_created", "user_id", "created_at"),
        sa.Index("ix_notifications_user_read", "user_id", "is_read"),
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
    website_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("websites.id", ondelete="SET NULL"),
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"),
    )
    scan_result_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("scan_results.id", ondelete="SET NULL"),
    )
    type: Mapped[NotificationType] = mapped_column(
        SAEnum(
            NotificationType,
            name="notificationtype",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        index=True,
    )
    severity: Mapped[NotificationSeverity] = mapped_column(
        SAEnum(
            NotificationSeverity,
            name="notificationseverity",
            values_callable=lambda x: [e.value for e in x],
        ),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    message: Mapped[str] = mapped_column(sa.Text, nullable=False)
    is_read: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, nullable=False, index=True
    )
    extra_metadata: Mapped[dict | None] = mapped_column("metadata", sa.JSON)
    read_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    # --- Outbound email delivery (FIX 6) ---------------------------------
    # Tracks whether this in-app notification was ALSO delivered by email.
    # Values: skipped (not eligible / feature off — never attempted),
    # pending (queued), sent, failed (retries exhausted), suppressed
    # (duplicate within the dedup window). Default "skipped" so existing
    # rows and the email-off path never claim an email was sent.
    email_status: Mapped[str] = mapped_column(
        sa.String(16), nullable=False, default="skipped", server_default="skipped",
    )
    email_attempts: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0",
    )
    email_sent_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    email_last_error: Mapped[str | None] = mapped_column(sa.Text)

    user: Mapped["User"] = relationship("User", back_populates="notifications")
