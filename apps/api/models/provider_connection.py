# WebHound — apps/api/models/provider_connection.py
# Phase 4.2 — provider connection storage (Cloudflare is the reference provider;
# the table is generic so future providers reuse it). Stores ONLY encrypted-
# secret REFERENCES (the Phase-4.1 EncryptedSecret ids) — never raw OAuth tokens.

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin
from apps.api.models.enums import ProviderConnectionStatus


class ProviderConnection(Base, UpdatedAtMixin):
    __tablename__ = "provider_connections"
    __table_args__ = (
        sa.UniqueConstraint("website_id", "provider", name="uq_provider_connection_site_provider"),
        sa.Index("ix_provider_connections_lookup", "org_id", "provider", "connection_status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    website_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("websites.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("orgs.id", ondelete="SET NULL"), nullable=True)

    provider: Mapped[str] = mapped_column(sa.String(32), nullable=False)  # "cloudflare"
    # Cloudflare: account id / zone id / matched zone name (e.g. example.com).
    account_id: Mapped[str | None] = mapped_column(sa.String(128))
    zone_id: Mapped[str | None] = mapped_column(sa.String(128))
    zone_name: Mapped[str | None] = mapped_column(sa.String(255))

    connection_status: Mapped[str] = mapped_column(
        sa.String(24), nullable=False,
        default=ProviderConnectionStatus.NOT_CONNECTED.value,
        server_default=ProviderConnectionStatus.NOT_CONNECTED.value)
    match_confidence: Mapped[str | None] = mapped_column(sa.String(16))  # "high" | "none"

    permissions_granted: Mapped[list | None] = mapped_column(sa.JSON, default=list)
    # Phase-4.1 EncryptedSecret ids — NEVER the raw token.
    access_secret_reference: Mapped[str | None] = mapped_column(sa.String(64))
    refresh_secret_reference: Mapped[str | None] = mapped_column(sa.String(64))
    # Safe, non-secret capability metadata (zone status, plan name, feature flags).
    connection_metadata: Mapped[dict | None] = mapped_column(sa.JSON, default=dict)
    evidence: Mapped[list | None] = mapped_column(sa.JSON, default=list)

    connected_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    disconnected_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_sync_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
