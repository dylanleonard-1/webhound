# WebHound — apps/api/models/access_validation.py
# Phase 3.5 — latest access-validation result for a website (1:1, updated in
# place). DERIVED from existing scan metadata (browser yield / challenge /
# discovery counts) — this stores the classification, not a new measurement.

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin
from apps.api.models.enums import AccessValidationStatus

if TYPE_CHECKING:
    from apps.api.models.website import Website


class AccessValidationResult(Base, UpdatedAtMixin):
    __tablename__ = "access_validation_results"
    __table_args__ = (
        sa.UniqueConstraint("website_id", name="uq_access_validation_website_id"),
        sa.Index("ix_access_validation_org_id", "org_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    website_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("websites.id", ondelete="CASCADE"),
        nullable=False,
    )
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("orgs.id", ondelete="SET NULL"), nullable=True
    )
    domain: Mapped[str] = mapped_column(sa.String(255), nullable=False, index=True)

    # String-backed status (see enums.AccessValidationStatus).
    validation_status: Mapped[str] = mapped_column(
        sa.String(20), nullable=False,
        default=AccessValidationStatus.PENDING.value,
        server_default=AccessValidationStatus.PENDING.value,
    )

    pages_found: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0, server_default="0")
    scripts_found: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0, server_default="0")
    apis_found: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0, server_default="0")
    third_parties_found: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=0, server_default="0")
    browser_rendered: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default=sa.false()
    )
    # tri-state: True / False / None(unknown) — mirrors the browser yield assessment.
    challenge_detected: Mapped[bool | None] = mapped_column(sa.Boolean)
    challenge_provider: Mapped[str | None] = mapped_column(sa.String(64))

    evidence: Mapped[list | None] = mapped_column(sa.JSON, default=list)
    validated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    website: Mapped["Website"] = relationship("Website")
