"""encrypted_secrets — Phase-4.1 encryption & secret management foundation

Revision ID: 0041
Revises: 0040
Create Date: 2026-06-10

Phase-4.1. Pure additive — NEW table ``encrypted_secrets`` storing provider
secrets (OAuth/refresh tokens, API keys) as Fernet ciphertext + the key version
that produced it. NEVER plaintext. Plain create_table (same pattern as
0037-0040). NOT a native-enum ALTER (no autocommit_block — see 0036 lesson).

Idempotent (table-exists guard). Reversible.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0041"
down_revision: Union[str, None] = "0040"
branch_labels = None
depends_on = None


def _has_table(bind, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "encrypted_secrets"):
        return
    op.create_table(
        "encrypted_secrets",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("website_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("secret_type", sa.String(64), nullable=False),
        sa.Column("classification", sa.String(24), nullable=False,
                  server_default="level_3_confidential"),
        sa.Column("key_version", sa.String(32), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("secret_metadata", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("access_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_accessed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_encrypted_secrets_org_id", "encrypted_secrets", ["org_id"])
    op.create_index("ix_encrypted_secrets_lookup", "encrypted_secrets",
                    ["org_id", "resource_type", "secret_type", "status"])


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "encrypted_secrets"):
        return
    for ix in ("ix_encrypted_secrets_lookup", "ix_encrypted_secrets_org_id"):
        try:
            op.drop_index(ix, table_name="encrypted_secrets")
        except Exception:  # noqa: BLE001
            pass
    op.drop_table("encrypted_secrets")
