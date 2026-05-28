"""SOC alerting: alerts + alert_comments

Revision ID: 0018
Revises: 0017
Create Date: 2026-05-27

Phase 3 of the internal /control platform — SOC alerting:
  - alerts          — deduped operational alerts (scan failures, engine
                      degradation, worker/queue/infra health)
  - alert_comments  — per-alert timeline (human notes + automated entries)

Idempotent (safe to re-run).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels = None
depends_on = None


def _has_table(inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "alerts"):
        op.create_table(
            "alerts",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("dedup_key", sa.String(length=200), nullable=False),
            sa.Column("source", sa.String(length=48), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column("status", sa.String(length=16), server_default="open", nullable=False),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("target_type", sa.String(length=48), nullable=True),
            sa.Column("target_id", sa.String(length=64), nullable=True),
            sa.Column("detail", postgresql.JSONB(), server_default="{}", nullable=False),
            sa.Column("occurrences", sa.Integer(), server_default="1", nullable=False),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("assignee_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("acknowledged_by_email", sa.String(length=320), nullable=True),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_by_email", sa.String(length=320), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_alerts_dedup_key", "alerts", ["dedup_key"], unique=True)
        op.create_index("ix_alerts_source", "alerts", ["source"])
        op.create_index("ix_alerts_severity", "alerts", ["severity"])
        op.create_index("ix_alerts_status", "alerts", ["status"])
        op.create_index("ix_alerts_status_severity", "alerts", ["status", "severity"])
        op.create_index("ix_alerts_last_seen_at", "alerts", ["last_seen_at"])

    if not _has_table(inspector, "alert_comments"):
        op.create_table(
            "alert_comments",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("alert_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False),
            sa.Column("kind", sa.String(length=24), nullable=False),
            sa.Column("author_email", sa.String(length=320), nullable=True),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_alert_comments_alert_id", "alert_comments", ["alert_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_table(inspector, "alert_comments"):
        op.drop_table("alert_comments")
    if _has_table(inspector, "alerts"):
        op.drop_table("alerts")
