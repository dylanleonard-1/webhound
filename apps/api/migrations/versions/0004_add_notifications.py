"""add notifications table

Revision ID: 0004
Revises: 0003
Create Date: 2026-05-08
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "website_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("websites.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "scan_job_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "scan_result_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scan_results.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "type",
            sa.Enum(
                "scan_completed",
                "scan_failed",
                "high_risk_finding",
                "critical_finding",
                "wade_anomaly",
                "schedule_failed",
                name="notificationtype",
            ),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "severity",
            sa.Enum(
                "info", "low", "medium", "high", "critical",
                name="notificationseverity",
            ),
            nullable=False,
            index=True,
        ),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("is_read", sa.Boolean, nullable=False, default=False, index=True),
        sa.Column("metadata", sa.JSON, nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("notifications")
    op.execute("DROP TYPE IF EXISTS notificationtype")
    op.execute("DROP TYPE IF EXISTS notificationseverity")
