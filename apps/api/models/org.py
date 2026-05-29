# WebHound — apps/api/models/org.py
# Phase-4 multi-tenancy: Org + OrgMembership scaffolding.
#
# Additive-only by design: existing customer-scoped tables get a
# *nullable* org_id column so already-stored rows continue to validate.
# Backfill, NOT-NULL enforcement, and per-query scoping land in
# subsequent migrations — this module ships the schema + the helpers
# downstream services need to start writing org_id when an org context
# is available.
#
# Distinct from AdminRole (which is platform-wide internal-SOC RBAC):
# OrgRole is tenant-scoped. A user can be OWNER of org A, ANALYST of
# org B, and have AdminRole.NONE platform-wide. has_org_role(min_role)
# is the canonical access check.

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Enum as SAEnum, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin, UpdatedAtMixin
from apps.api.models.enums import OrgRole, PlanTier

if TYPE_CHECKING:
    from apps.api.models.user import User


class Org(Base, UpdatedAtMixin):
    """One tenant — a customer organisation that owns one or more
    websites, scans, incidents, and members.

    On a multi-tenant deployment every customer-scoped row carries an
    ``org_id`` pointing here. ``slug`` is the URL-safe handle used in
    routes (``/orgs/{slug}``); ``name`` is the human-readable label.

    ``is_active=False`` soft-deletes the org without removing data, so
    audit trails and incident history survive an offboarding."""

    __tablename__ = "orgs"
    __table_args__ = (
        sa.UniqueConstraint("slug", name="uq_orgs_slug"),
        sa.Index("ix_orgs_is_active", "is_active"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    slug: Mapped[str] = mapped_column(sa.String(63), nullable=False)
    name: Mapped[str] = mapped_column(sa.String(255), nullable=False)
    billing_email: Mapped[str | None] = mapped_column(sa.String(255))
    plan_tier: Mapped[PlanTier] = mapped_column(
        SAEnum(PlanTier, name="plantier",
               values_callable=lambda e: [v.value for v in e]),
        nullable=False, default=PlanTier.FREE,
    )
    is_active: Mapped[bool] = mapped_column(
        sa.Boolean, default=True, nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        default=lambda: datetime.now(),
        nullable=False,
    )

    memberships: Mapped[list["OrgMembership"]] = relationship(
        "OrgMembership", back_populates="org",
        cascade="all, delete-orphan",
    )


class OrgMembership(Base, TimestampMixin):
    """Join table linking a User to an Org with a role.

    UNIQUE(org_id, user_id) so a user can't hold two roles in the same
    org. ``accepted_at`` is set when an invitation is accepted (when
    None, the row represents a pending invite and the user shouldn't
    yet see the org). ``invited_by`` is the user who issued the invite —
    optional so first-owner self-creation works without bootstrapping."""

    __tablename__ = "org_memberships"
    __table_args__ = (
        sa.UniqueConstraint(
            "org_id", "user_id", name="uq_org_memberships_org_user",
        ),
        sa.Index("ix_org_memberships_user_id", "user_id"),
        sa.Index("ix_org_memberships_role", "role"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("orgs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[OrgRole] = mapped_column(
        SAEnum(OrgRole, name="orgrole",
               values_callable=lambda e: [v.value for v in e]),
        nullable=False, default=OrgRole.VIEWER,
    )
    invited_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="SET NULL"),
    )
    accepted_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
    )

    org: Mapped["Org"] = relationship("Org", back_populates="memberships")
    user: Mapped["User"] = relationship(
        "User", foreign_keys=[user_id],
    )
