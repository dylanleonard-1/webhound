"""access_validation_results — Phase-3.5 access validation foundation

Revision ID: 0038
Revises: 0037
Create Date: 2026-06-10

Phase-3.5. Pure additive — NEW table ``access_validation_results`` (1:1 per
website) holding the latest visibility classification (READY/LIMITED/FAILED)
DERIVED from existing scan metadata. ``validation_status`` is a String column
(not a native enum). Stores no secrets.

Idempotent (table-exists guard). Reversible.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0038"
down_revision: Union[str, None] = "0037"
branch_labels = None
depends_on = None


def _has_table(bind, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "access_validation_results"):
        return
    op.create_table(
        "access_validation_results",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("website_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("validation_status", sa.String(20), nullable=False,
                  server_default="pending"),
        sa.Column("pages_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("scripts_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("apis_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("third_parties_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("browser_rendered", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
        sa.Column("challenge_detected", sa.Boolean(), nullable=True),
        sa.Column("challenge_provider", sa.String(64), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("website_id", name="uq_access_validation_website_id"),
    )
    op.create_index("ix_access_validation_org_id", "access_validation_results", ["org_id"])
    op.create_index("ix_access_validation_domain", "access_validation_results", ["domain"])


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "access_validation_results"):
        return
    for ix in ("ix_access_validation_domain", "ix_access_validation_org_id"):
        try:
            op.drop_index(ix, table_name="access_validation_results")
        except Exception:  # noqa: BLE001
            pass
    op.drop_table("access_validation_results")
