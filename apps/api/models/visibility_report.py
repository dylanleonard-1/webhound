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


class VisibilityReportRecord(Base, TimestampMixin):
    """Crawler-visibility report for one scan (1:1 with scan_results).

    Denormalises the headline coverage metrics into columns for querying /
    filtering, and keeps the full report JSON (sections + score breakdown +
    page tree) for the dashboard. Written only when the scan ran with the
    visibility layer enabled."""

    __tablename__ = "visibility_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_result_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("scan_results.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    domain: Mapped[str | None] = mapped_column(sa.String(255), index=True)
    crawl_mode: Mapped[str | None] = mapped_column(sa.String(32))
    pages_found: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    pages_crawled: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    visibility_score: Mapped[int | None] = mapped_column(sa.Integer, index=True)
    forms_count: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    api_count: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    js_routes_count: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    assets_count: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    third_party_count: Mapped[int] = mapped_column(
        sa.Integer, default=0, nullable=False
    )
    site_graph_generated: Mapped[bool] = mapped_column(
        sa.Boolean, default=False, nullable=False
    )
    report: Mapped[dict | None] = mapped_column(sa.JSON)
    limitations: Mapped[list | None] = mapped_column(sa.JSON)

    scan_result: Mapped["ScanResultRecord"] = relationship(
        "ScanResultRecord", back_populates="visibility_report"
    )
    discovered_urls: Mapped[list["DiscoveredUrlRecord"]] = relationship(
        "DiscoveredUrlRecord",
        back_populates="visibility_report",
        cascade="all, delete-orphan",
    )


class DiscoveredUrlRecord(Base, TimestampMixin):
    """One discovered URL in a visibility report (N per report).

    Persists the canonical discovery inventory with provenance + the explainable
    skip reason so the dashboard can render the page tree + a per-URL audit
    ("found via sitemap, skipped: disallowed by robots.txt"). Capped per scan."""

    __tablename__ = "discovered_urls"
    __table_args__ = (
        sa.Index("ix_discovered_urls_report_status", "visibility_report_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    visibility_report_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("visibility_reports.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url: Mapped[str] = mapped_column(sa.Text, nullable=False)
    normalized: Mapped[str | None] = mapped_column(sa.Text)
    discovered_via: Mapped[str | None] = mapped_column(sa.String(32))
    sources: Mapped[list | None] = mapped_column(sa.JSON)
    tags: Mapped[list | None] = mapped_column(sa.JSON)
    depth: Mapped[int] = mapped_column(sa.Integer, default=0, nullable=False)
    parent: Mapped[str | None] = mapped_column(sa.Text)
    status: Mapped[str | None] = mapped_column(sa.String(16), index=True)
    skip_reason: Mapped[str | None] = mapped_column(sa.Text)
    in_scope: Mapped[bool] = mapped_column(sa.Boolean, default=True, nullable=False)
    status_code: Mapped[int | None] = mapped_column(sa.Integer)
    content_type: Mapped[str | None] = mapped_column(sa.String(128))

    visibility_report: Mapped["VisibilityReportRecord"] = relationship(
        "VisibilityReportRecord", back_populates="discovered_urls"
    )
