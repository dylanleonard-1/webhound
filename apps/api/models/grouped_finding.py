from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin

if TYPE_CHECKING:
    from apps.api.models.scan_result import ScanResultRecord


class GroupedFindingRecord(Base, TimestampMixin):
    __tablename__ = "grouped_findings"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_result_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("scan_results.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    severity: Mapped[str] = mapped_column(sa.String(32), nullable=False, index=True)
    category: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    scanner_engine: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    affected_url_count: Mapped[int] = mapped_column(
        sa.Integer, default=0, nullable=False
    )
    affected_urls: Mapped[list | None] = mapped_column(sa.JSON)
    evidence_count: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    confidence: Mapped[float | None] = mapped_column(sa.Float)
    remediation: Mapped[str | None] = mapped_column(sa.Text)
    framework: Mapped[dict | None] = mapped_column(sa.JSON)
    finding_ids: Mapped[list | None] = mapped_column(sa.JSON)

    scan_result: Mapped["ScanResultRecord"] = relationship(
        "ScanResultRecord", back_populates="grouped_findings"
    )
