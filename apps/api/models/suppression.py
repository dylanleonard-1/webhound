# WebHound — apps/api/models/suppression.py
# Phase-5F: false-positive suppression model.
#
# A suppression hides a finding (or a class of findings) from the
# user-facing scan output. Operators add suppressions when an
# engine systematically flags a known-benign pattern that doesn't
# warrant a code change to the engine itself.
#
# Four scopes:
#   * domain          — hide every finding whose evidence URL is
#                        on this domain
#   * vendor          — hide every finding whose metadata.host
#                        belongs to this vendor / registrable domain
#   * finding_title   — hide every finding whose title contains
#                        this substring (engine-scoped via
#                        ``scanner_engine`` filter)
#   * site            — hide every finding for this website
#
# Each suppression carries a reason + creator_email + created_at +
# optional expires_at. The expires_at lets operators add temporary
# suppressions (e.g. "ignore until vendor ships the fix"). The
# audit log records every create / delete via admin_audit_log.

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy import Enum as SAEnum, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.database import Base
from apps.api.models._mixins import TimestampMixin

if TYPE_CHECKING:
    from apps.api.models.user import User
    from apps.api.models.org import Org


import enum


class SuppressionScope(str, enum.Enum):
    DOMAIN = "domain"
    VENDOR = "vendor"
    FINDING_TITLE = "finding_title"
    SITE = "site"


class Suppression(Base, TimestampMixin):
    __tablename__ = "suppressions"
    __table_args__ = (
        sa.Index("ix_suppressions_org_scope_active",
                 "org_id", "scope", "is_active"),
        sa.Index("ix_suppressions_expires_at", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    # Tenant scope. Nullable for platform-wide suppressions managed
    # via the /control admin panel.
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("orgs.id", ondelete="CASCADE"),
        index=True,
    )
    scope: Mapped[SuppressionScope] = mapped_column(
        SAEnum(SuppressionScope, name="suppressionscope",
               values_callable=lambda e: [v.value for v in e]),
        nullable=False,
    )
    # The pattern interpreted per ``scope``: a hostname for DOMAIN,
    # a registrable domain for VENDOR, a title substring for
    # FINDING_TITLE, a website UUID for SITE.
    pattern: Mapped[str] = mapped_column(sa.String(512), nullable=False)
    # When scope is FINDING_TITLE we typically pair with a
    # scanner_engine filter so 'Missing CSP' on cookies engine
    # doesn't accidentally hide 'Missing CSP' on security_headers.
    scanner_engine: Mapped[str | None] = mapped_column(sa.String(64))
    reason: Mapped[str] = mapped_column(sa.Text, nullable=False)
    creator_email: Mapped[str | None] = mapped_column(sa.String(320))
    creator_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        sa.ForeignKey("users.id", ondelete="SET NULL"),
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        sa.DateTime(timezone=True),
    )
    is_active: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=True, server_default=sa.true(),
    )

    creator: Mapped["User | None"] = relationship(
        "User", foreign_keys=[creator_user_id],
    )

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        from datetime import datetime, timezone
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) >= expires

    @property
    def is_live(self) -> bool:
        return self.is_active and not self.is_expired
