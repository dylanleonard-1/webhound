# WebHound — apps/api/models/onboarding_wizard.py
# Phase 3.7 — onboarding wizard state snapshot (1:1 per website). A lightweight
# roll-up of the 3.1-3.6 step statuses for the guided flow + audit trail + event
# deltas. The actual PROGRESS lives in the reused 3.1-3.6 records; this is the
# wizard-level summary (current step, overall status, timestamps).

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin
from apps.api.models.enums import WizardStatus

if TYPE_CHECKING:
    from apps.api.models.website import Website


class OnboardingWizardState(Base, UpdatedAtMixin):
    __tablename__ = "onboarding_wizard_state"
    __table_args__ = (
        sa.UniqueConstraint("website_id", name="uq_onboarding_wizard_website_id"),
        sa.Index("ix_onboarding_wizard_org_id", "org_id"),
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

    current_step: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=1, server_default="1")
    overall_status: Mapped[str] = mapped_column(
        sa.String(20), nullable=False,
        default=WizardStatus.NOT_STARTED.value,
        server_default=WizardStatus.NOT_STARTED.value,
    )
    provider: Mapped[str | None] = mapped_column(sa.String(64))

    # Per-step snapshot (the source of truth is the underlying 3.1-3.6 records).
    verification_status: Mapped[str | None] = mapped_column(sa.String(24))
    trusted_access_status: Mapped[str | None] = mapped_column(sa.String(24))
    validation_status: Mapped[str | None] = mapped_column(sa.String(24))
    readiness_status: Mapped[str | None] = mapped_column(sa.String(24))
    monitoring_status: Mapped[str | None] = mapped_column(sa.String(24))

    completed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))

    website: Mapped["Website"] = relationship("Website")
