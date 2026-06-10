# WebHound — apps/api/models/provider_profile.py
# Phase 3.1 — persisted provider-stack discovery result for a website.
# One current profile per website (1:1, updated in place on re-discovery).
# Org-scoped for multi-tenant listing; the durable audit record of a discovery.

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin

if TYPE_CHECKING:
    from apps.api.models.website import Website


class ProviderProfile(Base, UpdatedAtMixin):
    __tablename__ = "provider_profiles"
    __table_args__ = (
        sa.UniqueConstraint("website_id", name="uq_provider_profiles_website_id"),
        sa.Index("ix_provider_profiles_org_id", "org_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Unique (1:1 with website) — the unique constraint also indexes the column.
    website_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Multi-tenancy scoping (mirrors websites.org_id — nullable for legacy rows).
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("orgs.id", ondelete="SET NULL"),
        nullable=True,
    )
    domain: Mapped[str] = mapped_column(sa.String(255), nullable=False, index=True)

    # Detected provider stack — all nullable (a layer may be unknown).
    # registrar + deep hosting (IP/ASN) are deferred in the foundation.
    registrar: Mapped[str | None] = mapped_column(sa.String(120))
    dns_provider: Mapped[str | None] = mapped_column(sa.String(120))
    hosting_provider: Mapped[str | None] = mapped_column(sa.String(120))
    cdn_provider: Mapped[str | None] = mapped_column(sa.String(120))
    waf_provider: Mapped[str | None] = mapped_column(sa.String(120))
    cms: Mapped[str | None] = mapped_column(sa.String(120))
    framework: Mapped[str | None] = mapped_column(sa.String(120))

    # Overall 0–100 confidence + per-field evidence strings.
    confidence: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0)
    evidence: Mapped[list | None] = mapped_column(sa.JSON, default=list)

    # When discovery last ran (refreshed on each re-discovery).
    detected_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )

    website: Mapped["Website"] = relationship("Website")
