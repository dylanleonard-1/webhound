"""threat intel: threat_indicators

Revision ID: 0024
Revises: 0023
Create Date: 2026-05-28

Phase 9A of the internal /control platform — Threat Intelligence:
  - threat_indicators — known-bad atoms (ip / domain / url / hash / cve),
                        deduped per (kind, value, source)

Idempotent (safe to re-run).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0024"
down_revision: Union[str, None] = "0023"
branch_labels = None
depends_on = None


def _has_table(inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "threat_indicators"):
        op.create_table(
            "threat_indicators",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("kind", sa.String(length=16), nullable=False),
            sa.Column("value", sa.String(length=512), nullable=False),
            sa.Column("source", sa.String(length=64), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default="medium"),
            sa.Column("confidence", sa.Integer(), nullable=False, server_default="80"),
            sa.Column("tags", postgresql.JSONB(), nullable=False, server_default="[]"),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_unique_constraint("uq_threat_indicator_kvs", "threat_indicators",
                                    ["kind", "value", "source"])
        op.create_index("ix_threat_indicators_kind", "threat_indicators", ["kind"])
        op.create_index("ix_threat_indicators_source", "threat_indicators", ["source"])
        op.create_index("ix_threat_indicators_kind_value", "threat_indicators",
                        ["kind", "value"])
        op.create_index("ix_threat_indicators_severity", "threat_indicators", ["severity"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_table(inspector, "threat_indicators"):
        op.drop_table("threat_indicators")
