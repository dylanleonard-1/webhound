"""log explorer: logs table

Revision ID: 0023
Revises: 0022
Create Date: 2026-05-28

Phase 8 of the internal /control platform — Log Explorer + Audit UI:
  - logs   — queryable application log store (separate from admin_audit_logs)

The audit UI reuses admin_audit_logs (Phase 1) — no schema change there.
Idempotent (safe to re-run).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels = None
depends_on = None


def _has_table(inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "logs"):
        op.create_table(
            "logs",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
            sa.Column("source", sa.String(length=32), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column("message", sa.Text(), nullable=False),
            sa.Column("context", postgresql.JSONB(), nullable=False, server_default="{}"),
            sa.Column("request_id", sa.String(length=64), nullable=True),
            sa.Column("actor_email", sa.String(length=320), nullable=True),
        )
        op.create_index("ix_logs_timestamp", "logs", ["timestamp"])
        op.create_index("ix_logs_source", "logs", ["source"])
        op.create_index("ix_logs_severity", "logs", ["severity"])
        op.create_index("ix_logs_source_severity", "logs", ["source", "severity"])
        op.create_index("ix_logs_request_id", "logs", ["request_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_table(inspector, "logs"):
        op.drop_table("logs")
