# WebHound — apps/api/models/scan_delta.py
# Phase-4 continuous monitoring: per-target scan-to-scan delta record.
#
# When a scheduled scan completes, the monitoring service finds the most
# recent prior scan for the same website, computes the structured diff
# (new/removed external domains, header drift, TLS-config drift, new
# tech, new forms, new APIs), and persists a ScanDelta row.
#
# The delta itself is the audit trail: alert dispatch / dashboard
# drift-feed / WADE behavioural analysis all read from this table rather
# than recomputing.

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Enum as SAEnum, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin
from apps.api.models.enums import DriftSeverity

if TYPE_CHECKING:
    from apps.api.models.scan_job import ScanJob
    from apps.api.models.website import Website


# Portable JSON column — JSONB on Postgres for indexing/perf, plain JSON
# on SQLite (tests). Lifted to a constant so each delta-shaped column
# uses the identical declaration.
_JSON = sa.JSON().with_variant(JSONB(), "postgresql")


class ScanDelta(Base, TimestampMixin):
    """Structured diff between two consecutive scans of the same website.

    ``current_scan_job_id`` is the newer scan that triggered the delta.
    ``previous_scan_job_id`` is the prior scan it was compared against —
    nullable so the first-ever scan for a target can record a baseline
    entry (every column empty, drift_severity=NONE).

    All change fields are JSONB so the delta survives schema evolution
    in the underlying scanner — e.g. when a new engine starts emitting
    a new artifact type, we add it to the diff service without an
    Alembic migration. Each field is a list of opaque objects with at
    least a ``kind`` discriminator; the diff service writes the format
    it owns and the dashboard reads what's there.

    ``drift_severity`` is the rolled-up severity the alert engine uses —
    LOW = a few new vendor domains; MEDIUM = changed TLS config or new
    admin surface; HIGH/CRITICAL = injected JS, malicious-tier domain
    appeared, or a confirmed-compromise indicator landed.

    ``drift_summary`` is a one-paragraph human-readable explanation
    suitable for an alert notification body."""

    __tablename__ = "scan_deltas"
    __table_args__ = (
        sa.Index("ix_scan_deltas_website_created",
                 "website_id", "created_at"),
        sa.Index("ix_scan_deltas_drift_severity", "drift_severity"),
        sa.Index("ix_scan_deltas_org_id", "org_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    # Multi-tenant scoping — nullable until backfilled.
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("orgs.id", ondelete="CASCADE"),
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
    )
    current_scan_job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,   # at most one delta per scan
    )
    previous_scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"),
    )

    # Diffed artifacts. Each list of objects; empty when nothing changed.
    new_domains: Mapped[list] = mapped_column(_JSON, nullable=False, default=list)
    removed_domains: Mapped[list] = mapped_column(_JSON, nullable=False, default=list)
    changed_headers: Mapped[list] = mapped_column(_JSON, nullable=False, default=list)
    changed_tls: Mapped[dict] = mapped_column(_JSON, nullable=False, default=dict)
    new_technologies: Mapped[list] = mapped_column(_JSON, nullable=False, default=list)
    removed_technologies: Mapped[list] = mapped_column(_JSON, nullable=False, default=list)
    new_forms: Mapped[list] = mapped_column(_JSON, nullable=False, default=list)
    new_apis: Mapped[list] = mapped_column(_JSON, nullable=False, default=list)
    new_third_party_dependencies: Mapped[list] = mapped_column(
        _JSON, nullable=False, default=list,
    )
    new_findings_summary: Mapped[dict] = mapped_column(
        _JSON, nullable=False, default=dict,
    )

    drift_severity: Mapped[DriftSeverity] = mapped_column(
        SAEnum(DriftSeverity, name="driftseverity",
               values_callable=lambda e: [v.value for v in e]),
        nullable=False, default=DriftSeverity.NONE,
    )
    drift_summary: Mapped[str | None] = mapped_column(sa.Text)
    risk_score_delta: Mapped[int | None] = mapped_column(sa.Integer)

    website: Mapped["Website"] = relationship("Website")
    current_scan_job: Mapped["ScanJob"] = relationship(
        "ScanJob", foreign_keys=[current_scan_job_id],
    )
    previous_scan_job: Mapped["ScanJob | None"] = relationship(
        "ScanJob", foreign_keys=[previous_scan_job_id],
    )
