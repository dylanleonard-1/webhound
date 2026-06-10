# WebHound — apps/api/models/trusted_access.py
# Phase 3.4 — domain-level trusted scanner access record (1:1 per website).
# Permission/guidance FOUNDATION only — stores NO provider tokens or secrets.
# (When a future slice adds real provider_oauth, token storage brings the
# encryption-at-rest requirement back onto the critical path — not here.)

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin
from apps.api.models.enums import TrustedAccessMethod, TrustedAccessStatus

if TYPE_CHECKING:
    from apps.api.models.website import Website


class TrustedAccessProfile(Base, UpdatedAtMixin):
    __tablename__ = "trusted_access_profiles"
    __table_args__ = (
        sa.UniqueConstraint("website_id", name="uq_trusted_access_website_id"),
        sa.Index("ix_trusted_access_org_id", "org_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # 1:1 with the website (the unique constraint also indexes the column).
    website_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
    )
    # Multi-tenancy + ownership (mirrors websites.org_id/user_id).
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("orgs.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    domain: Mapped[str] = mapped_column(sa.String(255), nullable=False, index=True)

    # Linkage to the Phase-3.1 provider profile + Phase-3.2 verification.
    provider: Mapped[str | None] = mapped_column(sa.String(64))
    provider_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("provider_profiles.id", ondelete="SET NULL"), nullable=True,
    )
    verification_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("domain_verifications.id", ondelete="SET NULL"), nullable=True,
    )

    # Phase-3.3 scanner identity evidence (public, non-secret).
    scanner_identity_version: Mapped[str | None] = mapped_column(sa.String(32))
    scanner_user_agent: Mapped[str | None] = mapped_column(sa.String(255))

    # String-backed status/method — deliberate divergence from the native-enum
    # pattern (verification_status / scan_job.status) so the vocabulary can grow
    # without ALTER TYPE. Validated against the StrEnum at the service boundary.
    access_status: Mapped[str] = mapped_column(
        sa.String(32), nullable=False,
        default=TrustedAccessStatus.NOT_CONFIGURED.value,
        server_default=TrustedAccessStatus.NOT_CONFIGURED.value,
    )
    access_method: Mapped[str] = mapped_column(
        sa.String(40), nullable=False,
        default=TrustedAccessMethod.UNKNOWN.value,
        server_default=TrustedAccessMethod.UNKNOWN.value,
    )

    # Method-derived permission labels only — NEVER tokens/secrets.
    permissions_granted: Mapped[list | None] = mapped_column(sa.JSON, default=list)
    evidence: Mapped[list | None] = mapped_column(sa.JSON, default=list)

    validated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    website: Mapped["Website"] = relationship("Website")
