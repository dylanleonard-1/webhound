"""trusted_access_profiles — Phase-3.4 trusted scanner access foundation

Revision ID: 0037
Revises: 0036
Create Date: 2026-06-10

Phase-3.4. Pure additive — NEW table ``trusted_access_profiles`` (1:1 per
website, org/user scoped) holding the trusted-access record (status / method /
provider + scanner-identity evidence). Stores NO provider tokens or secrets.
``access_status`` / ``access_method`` are String columns (not native enums) so
the vocabulary can grow without ALTER TYPE migrations.

Idempotent (table-exists guard). Reversible.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0037"
down_revision: Union[str, None] = "0036"
branch_labels = None
depends_on = None


def _has_table(bind, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "trusted_access_profiles"):
        return
    op.create_table(
        "trusted_access_profiles",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("website_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("provider", sa.String(64), nullable=True),
        sa.Column("provider_profile_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("verification_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("scanner_identity_version", sa.String(32), nullable=True),
        sa.Column("scanner_user_agent", sa.String(255), nullable=True),
        sa.Column("access_status", sa.String(32), nullable=False,
                  server_default="not_configured"),
        sa.Column("access_method", sa.String(40), nullable=False,
                  server_default="unknown"),
        sa.Column("permissions_granted", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["provider_profile_id"], ["provider_profiles.id"],
                                ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["verification_id"], ["domain_verifications.id"],
                                ondelete="SET NULL"),
        sa.UniqueConstraint("website_id", name="uq_trusted_access_website_id"),
    )
    op.create_index("ix_trusted_access_org_id", "trusted_access_profiles", ["org_id"])
    op.create_index("ix_trusted_access_domain", "trusted_access_profiles", ["domain"])


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "trusted_access_profiles"):
        return
    for ix in ("ix_trusted_access_domain", "ix_trusted_access_org_id"):
        try:
            op.drop_index(ix, table_name="trusted_access_profiles")
        except Exception:  # noqa: BLE001
            pass
    op.drop_table("trusted_access_profiles")
