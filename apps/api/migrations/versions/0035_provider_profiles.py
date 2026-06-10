"""provider_profiles — Phase-3.1 provider discovery foundation

Revision ID: 0035
Revises: 0034
Create Date: 2026-06-09

Phase-3.1 Provider Discovery. Pure additive — no existing table/column changes,
no scanner behaviour change:

  * NEW table ``provider_profiles`` — one current profile per website (1:1),
    org-scoped, storing the detected provider stack
    (registrar/dns/hosting/cdn/waf/cms/framework) + confidence + evidence.

Idempotent (table-exists guard). Reversible.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0035"
down_revision: Union[str, None] = "0034"
branch_labels = None
depends_on = None


def _has_table(bind, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "provider_profiles"):
        return
    op.create_table(
        "provider_profiles",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("website_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("registrar", sa.String(120), nullable=True),
        sa.Column("dns_provider", sa.String(120), nullable=True),
        sa.Column("hosting_provider", sa.String(120), nullable=True),
        sa.Column("cdn_provider", sa.String(120), nullable=True),
        sa.Column("waf_provider", sa.String(120), nullable=True),
        sa.Column("cms", sa.String(120), nullable=True),
        sa.Column("framework", sa.String(120), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("website_id", name="uq_provider_profiles_website_id"),
    )
    op.create_index("ix_provider_profiles_org_id", "provider_profiles", ["org_id"])
    op.create_index("ix_provider_profiles_domain", "provider_profiles", ["domain"])


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "provider_profiles"):
        return
    for ix in ("ix_provider_profiles_domain", "ix_provider_profiles_org_id"):
        try:
            op.drop_index(ix, table_name="provider_profiles")
        except Exception:  # noqa: BLE001
            pass
    op.drop_table("provider_profiles")
