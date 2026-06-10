"""onboarding_readiness — Phase-3.6 onboarding readiness & activation

Revision ID: 0039
Revises: 0038
Create Date: 2026-06-10

Phase-3.6. Pure additive — NEW table ``onboarding_readiness`` (1:1 per website)
holding the activation decision (READY/LIMITED/NOT_READY) DERIVED from the
3.1-3.5 signals + the monitoring/deep-scan/baseline allow flags. ``status`` is a
String column (not a native enum). No secrets.

Idempotent (table-exists guard). Reversible.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0039"
down_revision: Union[str, None] = "0038"
branch_labels = None
depends_on = None


def _has_table(bind, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "onboarding_readiness"):
        return
    op.create_table(
        "onboarding_readiness",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("website_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="not_ready"),
        sa.Column("checks", sa.JSON(), nullable=True),
        sa.Column("monitoring_allowed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("deep_scan_allowed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("baseline_allowed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("website_id", name="uq_onboarding_readiness_website_id"),
    )
    op.create_index("ix_onboarding_readiness_org_id", "onboarding_readiness", ["org_id"])
    op.create_index("ix_onboarding_readiness_domain", "onboarding_readiness", ["domain"])


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "onboarding_readiness"):
        return
    for ix in ("ix_onboarding_readiness_domain", "ix_onboarding_readiness_org_id"):
        try:
            op.drop_index(ix, table_name="onboarding_readiness")
        except Exception:  # noqa: BLE001
            pass
    op.drop_table("onboarding_readiness")
