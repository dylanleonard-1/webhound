"""scan_jobs reliability columns: heartbeat_at + cancellation_requested

Revision ID: 0034
Revises: 0033
Create Date: 2026-06-07

Worker-reliability columns (FIX 9 + FIX 10). Pure additive + idempotent
(column-exists guards). Existing rows are unaffected:

  * scan_jobs.heartbeat_at            TIMESTAMPTZ NULL
      Worker liveness stamp. The stale-job reaper marks a RUNNING job whose
      heartbeat stopped advancing as failed. NULL for legacy/queued rows.
  * scan_jobs.cancellation_requested  BOOLEAN NOT NULL DEFAULT FALSE
      Cooperative-cancellation flag the worker checks between scan phases.

Reversible.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0034"
down_revision: Union[str, None] = "0033"
branch_labels = None
depends_on = None


def _has_column(bind, table: str, column: str) -> bool:
    insp = sa.inspect(bind)
    if table not in insp.get_table_names():
        return False
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, "scan_jobs", "heartbeat_at"):
        op.add_column(
            "scan_jobs",
            sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        )
    if not _has_column(bind, "scan_jobs", "cancellation_requested"):
        op.add_column(
            "scan_jobs",
            sa.Column(
                "cancellation_requested", sa.Boolean(), nullable=False,
                server_default=sa.false(),
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    for col in ("cancellation_requested", "heartbeat_at"):
        if _has_column(bind, "scan_jobs", col):
            op.drop_column("scan_jobs", col)
