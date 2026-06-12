from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin

if TYPE_CHECKING:
    from apps.api.models.engine_diagnostic import EngineDiagnosticRecord
    from apps.api.models.finding import FindingRecord
    from apps.api.models.grouped_finding import GroupedFindingRecord
    from apps.api.models.report import ReportRecord
    from apps.api.models.scan_job import ScanJob
    from apps.api.models.visibility_report import VisibilityReportRecord


class ScanResultRecord(Base, TimestampMixin):
    __tablename__ = "scan_results"
    __table_args__ = (
        sa.Index("ix_scan_results_risk_level", "risk_level"),
        sa.Index("ix_scan_results_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    scan_id: Mapped[str | None] = mapped_column(sa.String(255))
    risk_score: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    duration_seconds: Mapped[float | None] = mapped_column(sa.Float)
    pages_crawled: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    total_findings: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    actionable_findings: Mapped[int] = mapped_column(
        sa.Integer, default=0, nullable=False
    )
    severity_breakdown: Mapped[dict] = mapped_column(
        sa.JSON, nullable=False, default=dict
    )
    scanner_metadata: Mapped[dict | None] = mapped_column(sa.JSON)

    scan_job: Mapped["ScanJob"] = relationship("ScanJob", back_populates="result")
    findings: Mapped[list["FindingRecord"]] = relationship(
        "FindingRecord", back_populates="scan_result", cascade="all, delete-orphan"
    )
    grouped_findings: Mapped[list["GroupedFindingRecord"]] = relationship(
        "GroupedFindingRecord", back_populates="scan_result", cascade="all, delete-orphan"
    )
    engine_diagnostics: Mapped[list["EngineDiagnosticRecord"]] = relationship(
        "EngineDiagnosticRecord",
        back_populates="scan_result",
        cascade="all, delete-orphan",
    )
    reports: Mapped[list["ReportRecord"]] = relationship(
        "ReportRecord", back_populates="scan_result", cascade="all, delete-orphan"
    )
    visibility_report: Mapped["VisibilityReportRecord | None"] = relationship(
        "VisibilityReportRecord",
        back_populates="scan_result",
        cascade="all, delete-orphan",
        uselist=False,
    )
