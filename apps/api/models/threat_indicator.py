# WebHound — apps/api/models/threat_indicator.py
# Phase 9A: Threat-intelligence indicators. Staff (or a feed importer) drop
# known-bad atoms (ip / domain / url / hash / cve) into this table; the fraud
# evaluator + the scanner consult it via fraud_svc / threat_intel.match().

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin


class ThreatIndicator(Base, UpdatedAtMixin):
    __tablename__ = "threat_indicators"
    __table_args__ = (
        sa.UniqueConstraint("kind", "value", "source", name="uq_threat_indicator_kvs"),
        sa.Index("ix_threat_indicators_kind_value", "kind", "value"),
        sa.Index("ix_threat_indicators_severity", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Indicator atom — what kind of thing this is and the value being flagged.
    kind: Mapped[str] = mapped_column(sa.String(16), nullable=False, index=True)
    value: Mapped[str] = mapped_column(sa.String(512), nullable=False)

    # Where the indicator came from — could be a public feed name
    # ("alienvault", "abuseipdb") or "manual" for hand-entered rows.
    source: Mapped[str] = mapped_column(sa.String(64), nullable=False, index=True)

    severity: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="medium")
    # 0-100, how much we trust this indicator. Manual entries default to 80.
    confidence: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=80,
                                            server_default="80")

    tags: Mapped[list] = mapped_column(
        JSONB().with_variant(sa.JSON(), "sqlite"),
        default=list, server_default="[]",
    )
    notes: Mapped[str | None] = mapped_column(sa.Text)

    first_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(sa.DateTime(timezone=True), nullable=False)
    # Optional TTL. expire_stale() prunes rows whose expires_at has passed.
    expires_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
