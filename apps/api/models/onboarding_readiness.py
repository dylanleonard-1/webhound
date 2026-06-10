# WebHound — apps/api/models/onboarding_readiness.py
# Phase 3.6 — per-website monitoring readiness (1:1, updated in place). An
# activation DECISION derived from the 3.1-3.5 signals (provider / verification
# / trusted access / access validation) — NOT a new scoring or discovery
# engine. Distinct from platform/onboarding/onboarding_state, which is the
# account-level setup checklist.

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin
from apps.api.models.enums import OnboardingReadinessStatus

if TYPE_CHECKING:
    from apps.api.models.website import Website


class OnboardingReadiness(Base, UpdatedAtMixin):
    __tablename__ = "onboarding_readiness"
    __table_args__ = (
        sa.UniqueConstraint("website_id", name="uq_onboarding_readiness_website_id"),
        sa.Index("ix_onboarding_readiness_org_id", "org_id"),
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

    # String-backed status (see enums.OnboardingReadinessStatus).
    status: Mapped[str] = mapped_column(
        sa.String(20), nullable=False,
        default=OnboardingReadinessStatus.NOT_READY.value,
        server_default=OnboardingReadinessStatus.NOT_READY.value,
    )
    # Per-check results: {check_name: pass|warning|fail}.
    checks: Mapped[dict | None] = mapped_column(sa.JSON, default=dict)

    # Activation decisions derived from status (blocked only when NOT_READY).
    monitoring_allowed: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default=sa.false()
    )
    deep_scan_allowed: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default=sa.false()
    )
    baseline_allowed: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default=sa.false()
    )

    evidence: Mapped[list | None] = mapped_column(sa.JSON, default=list)
    evaluated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    website: Mapped["Website"] = relationship("Website")
