"""performance indexes, unique constraints, cascade fix

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-12

Changes:
  - Fix websites.user_id FK from SET NULL to CASCADE (aligns DB with ORM)
  - Add UNIQUE(url) on websites
  - Add UNIQUE(website_id, baseline_version) on baselines
  - ix_scan_jobs_created_at
  - ix_scan_results_risk_level
  - ix_scan_results_created_at
  - ix_websites_url  (backing the unique constraint)
  - ix_websites_created_at
  - ix_notifications_user_created  (user_id, created_at)
  - ix_notifications_user_read     (user_id, is_read)
  - ix_scan_schedules_enabled_next (is_enabled, next_run_at)
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. Fix websites → users cascade: SET NULL → CASCADE
    # ------------------------------------------------------------------
    op.drop_constraint("websites_user_id_fkey", "websites", type_="foreignkey")
    op.create_foreign_key(
        "websites_user_id_fkey",
        "websites",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )

    # ------------------------------------------------------------------
    # 2. Unique constraint: websites.url (globally unique normalised URL)
    # ------------------------------------------------------------------
    op.create_index("ix_websites_url", "websites", ["url"], unique=True)

    # ------------------------------------------------------------------
    # 3. Unique constraint: baselines(website_id, baseline_version)
    # ------------------------------------------------------------------
    op.create_index(
        "uq_baselines_website_version",
        "baselines",
        ["website_id", "baseline_version"],
        unique=True,
    )

    # ------------------------------------------------------------------
    # 4. Single-column indexes used in sort / filter queries
    # ------------------------------------------------------------------
    op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])
    op.create_index("ix_scan_results_risk_level", "scan_results", ["risk_level"])
    op.create_index("ix_scan_results_created_at", "scan_results", ["created_at"])
    op.create_index("ix_websites_created_at", "websites", ["created_at"])

    # ------------------------------------------------------------------
    # 5. Composite indexes for notification queries
    # ------------------------------------------------------------------
    op.create_index(
        "ix_notifications_user_created",
        "notifications",
        ["user_id", "created_at"],
    )
    op.create_index(
        "ix_notifications_user_read",
        "notifications",
        ["user_id", "is_read"],
    )

    # ------------------------------------------------------------------
    # 6. Composite index for the scheduled-scan worker poll
    #    WHERE is_enabled = true AND next_run_at <= :now
    # ------------------------------------------------------------------
    op.create_index(
        "ix_scan_schedules_enabled_next",
        "scan_schedules",
        ["is_enabled", "next_run_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_schedules_enabled_next", table_name="scan_schedules")
    op.drop_index("ix_notifications_user_read", table_name="notifications")
    op.drop_index("ix_notifications_user_created", table_name="notifications")
    op.drop_index("ix_websites_created_at", table_name="websites")
    op.drop_index("ix_scan_results_created_at", table_name="scan_results")
    op.drop_index("ix_scan_results_risk_level", table_name="scan_results")
    op.drop_index("ix_scan_jobs_created_at", table_name="scan_jobs")
    op.drop_index("uq_baselines_website_version", table_name="baselines")
    op.drop_index("ix_websites_url", table_name="websites")

    op.drop_constraint("websites_user_id_fkey", "websites", type_="foreignkey")
    op.create_foreign_key(
        "websites_user_id_fkey",
        "websites",
        "users",
        ["user_id"],
        ["id"],
        ondelete="SET NULL",
    )
