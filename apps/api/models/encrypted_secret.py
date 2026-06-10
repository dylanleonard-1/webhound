# WebHound — apps/api/models/encrypted_secret.py
# Phase 4.1 — at-rest encrypted secret store (OAuth access/refresh tokens, API
# keys, provider credentials). Stores ONLY ciphertext + the key version that
# produced it — NEVER plaintext. All provider integrations must store via
# SecretStorageService; no provider tokens in any other column anywhere.

from __future__ import annotations

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.database import Base
from apps.api.models._mixins import UpdatedAtMixin
from apps.api.models.enums import SecretClassification, SecretStatus


class EncryptedSecret(Base, UpdatedAtMixin):
    __tablename__ = "encrypted_secrets"
    __table_args__ = (
        sa.Index("ix_encrypted_secrets_org_id", "org_id"),
        sa.Index("ix_encrypted_secrets_lookup", "org_id", "resource_type",
                 "secret_type", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Ownership / tenancy (nullable — a secret may be org-, user-, or site-scoped).
    org_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("orgs.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    website_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), sa.ForeignKey("websites.id", ondelete="CASCADE"), nullable=True
    )

    # What this secret is for.
    resource_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)  # e.g. "cloudflare"
    secret_type: Mapped[str] = mapped_column(sa.String(64), nullable=False)    # e.g. "oauth_access_token"
    classification: Mapped[str] = mapped_column(
        sa.String(24), nullable=False,
        default=SecretClassification.LEVEL_3_CONFIDENTIAL.value,
        server_default=SecretClassification.LEVEL_3_CONFIDENTIAL.value,
    )

    # The encrypted payload + the key version that produced it. NEVER plaintext.
    key_version: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    ciphertext: Mapped[str] = mapped_column(sa.Text, nullable=False)
    # Non-secret metadata only (scopes, expiry, provider account id). Redacted on store.
    secret_metadata: Mapped[dict | None] = mapped_column(sa.JSON, default=dict)

    status: Mapped[str] = mapped_column(
        sa.String(16), nullable=False,
        default=SecretStatus.ACTIVE.value, server_default=SecretStatus.ACTIVE.value,
    )
    access_count: Mapped[int] = mapped_column(
        sa.Integer, nullable=False, default=0, server_default="0"
    )
    rotated_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
    last_accessed_at: Mapped[datetime | None] = mapped_column(sa.DateTime(timezone=True))
