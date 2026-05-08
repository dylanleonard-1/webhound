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


class EngineDiagnosticRecord(Base, TimestampMixin):
    __tablename__ = "engine_diagnostics"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_result_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("scan_results.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    engine_name: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    category: Mapped[str | None] = mapped_column(sa.String(64))
    status: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    findings_count: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    severity_counts: Mapped[dict | None] = mapped_column(sa.JSON)
    duration_ms: Mapped[float | None] = mapped_column(sa.Float)
    skipped_reason: Mapped[str | None] = mapped_column(sa.Text)
    error_message: Mapped[str | None] = mapped_column(sa.Text)

    scan_result: Mapped["ScanResultRecord"] = relationship(
        "ScanResultRecord", back_populates="engine_diagnostics"
    )
