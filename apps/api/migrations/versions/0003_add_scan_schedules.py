"""add scan_schedules table

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-07
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
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
            sa.ForeignKey("websites.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "profile",
            sa.Enum("quick", "standard", "deep", "monitor", name="scanprofile"),
            nullable=False,
        ),
        sa.Column(
            "frequency",
            sa.Enum("daily", "weekly", "monthly", name="schedulefrequency"),
            nullable=False,
        ),
        sa.Column("is_enabled", sa.Boolean, nullable=False, default=True),
        sa.Column("use_latest_baseline", sa.Boolean, nullable=False, default=True),
        sa.Column("save_baseline", sa.Boolean, nullable=False, default=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("scan_schedules")
    op.execute("DROP TYPE IF EXISTS schedulefrequency")
