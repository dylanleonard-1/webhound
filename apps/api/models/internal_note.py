# WebHound — apps/api/models/internal_note.py
# Free-form staff notes attached to any entity (initially: users) and surfaced
# in the /control detail drawers. Not visible to customers.

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin


class InternalNote(Base, TimestampMixin):
    __tablename__ = "internal_notes"
    __table_args__ = (
        sa.Index("ix_internal_notes_target", "target_type", "target_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target_type: Mapped[str] = mapped_column(sa.String(48), nullable=False)
    target_id: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    author_email: Mapped[str | None] = mapped_column(sa.String(320))
    body: Mapped[str] = mapped_column(sa.Text, nullable=False)
