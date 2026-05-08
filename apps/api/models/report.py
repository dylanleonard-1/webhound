from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Enum as SAEnum, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin
from apps.api.models.enums import ReportFormat

if TYPE_CHECKING:
    from apps.api.models.scan_result import ScanResultRecord


class ReportRecord(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_result_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("scan_results.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    format: Mapped[ReportFormat] = mapped_column(
        SAEnum(ReportFormat, name="reportformat"), nullable=False
    )
    path: Mapped[str | None] = mapped_column(sa.String(2048))
    content_json: Mapped[dict | None] = mapped_column(sa.JSON)

    scan_result: Mapped["ScanResultRecord"] = relationship(
        "ScanResultRecord", back_populates="reports"
    )
