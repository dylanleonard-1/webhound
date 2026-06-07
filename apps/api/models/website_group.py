# WebHound API — apps/api/models/website_group.py
# Phase-16: client/location groups for the agency/MSP portfolio. A group
# belongs to an org and bundles that org's websites (via
# Website.group_id) into a client, location, brand, franchise, or
# business unit.

from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.models._mixins import UpdatedAtMixin
from apps.api.database import Base


class WebsiteGroup(Base, UpdatedAtMixin):
    """A portfolio client/location group scoped to one organization."""

    __tablename__ = "website_groups"

    id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4,
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("orgs.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    name: Mapped[str] = mapped_column(sa.String(200), nullable=False)
    # client | location | brand | franchise | business_unit | agency_client
    group_type: Mapped[str] = mapped_column(
        sa.String(40), nullable=False, default="agency_client",
    )
    parent_group_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.Uuid(as_uuid=True),
        sa.ForeignKey("website_groups.id", ondelete="SET NULL"),
        nullable=True,
    )
