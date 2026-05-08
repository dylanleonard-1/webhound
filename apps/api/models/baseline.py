from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin

if TYPE_CHECKING:
    from apps.api.models.website import Website


class BaselineRecord(Base, TimestampMixin):
    __tablename__ = "baselines"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    baseline_id: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    baseline_version: Mapped[int] = mapped_column(
        sa.Integer, default=1, nullable=False
    )
    baseline_json: Mapped[dict] = mapped_column(sa.JSON, nullable=False, default=dict)

    website: Mapped["Website"] = relationship("Website", back_populates="baselines")
