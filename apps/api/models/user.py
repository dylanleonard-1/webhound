from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin

if TYPE_CHECKING:
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

    websites: Mapped[list["Website"]] = relationship(
        "Website", back_populates="user", cascade="all, delete-orphan"
    )
    scan_schedules: Mapped[list["ScanSchedule"]] = relationship(
        "ScanSchedule", back_populates="user", cascade="all, delete-orphan"
    )
