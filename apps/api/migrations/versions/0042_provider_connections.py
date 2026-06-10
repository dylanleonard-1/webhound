"""provider_connections + verificationmethod.provider_connection — Phase 4.2

Revision ID: 0042
Revises: 0041
Create Date: 2026-06-10

Adds the provider-connection table (Cloudflare is the reference provider) and a
new native-enum value 'provider_connection' on verificationmethod so a connected
provider can serve as an ownership-verification method.

NO autocommit_block (the 0036 lesson): ALTER TYPE ... ADD VALUE is safe inside
the async single transaction because the value is NOT used in this migration
(the create_table doesn't reference it). Idempotent + reversible (the table;
the additive enum value is left in place on downgrade — Postgres cannot drop an
enum value without recreating the type).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0042"
down_revision: Union[str, None] = "0041"
branch_labels = None
depends_on = None


def _has_table(bind, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TYPE verificationmethod ADD VALUE IF NOT EXISTS 'provider_connection'")
    if _has_table(bind, "provider_connections"):
        return
    op.create_table(
        "provider_connections",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("website_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("account_id", sa.String(128), nullable=True),
        sa.Column("zone_id", sa.String(128), nullable=True),
        sa.Column("zone_name", sa.String(255), nullable=True),
        sa.Column("connection_status", sa.String(24), nullable=False,
                  server_default="not_connected"),
        sa.Column("match_confidence", sa.String(16), nullable=True),
        sa.Column("permissions_granted", sa.JSON(), nullable=True),
        sa.Column("access_secret_reference", sa.String(64), nullable=True),
        sa.Column("refresh_secret_reference", sa.String(64), nullable=True),
        sa.Column("connection_metadata", sa.JSON(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("connected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disconnected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("website_id", "provider", name="uq_provider_connection_site_provider"),
    )
    op.create_index("ix_provider_connections_lookup", "provider_connections",
                    ["org_id", "provider", "connection_status"])


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "provider_connections"):
        return
    try:
        op.drop_index("ix_provider_connections_lookup", table_name="provider_connections")
    except Exception:  # noqa: BLE001
        pass
    op.drop_table("provider_connections")
