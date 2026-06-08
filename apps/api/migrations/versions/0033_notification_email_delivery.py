"""notification email-delivery tracking columns (FIX 6)

Revision ID: 0033
Revises: 0032
Create Date: 2026-06-07

Adds outbound-email delivery tracking to ``notifications`` so the worker can
record whether a customer notification was also delivered by email. Pure
additive + idempotent (column-exists guards). Existing rows default to
``email_status='skipped'`` so nothing retroactively claims an email was sent.

  * notifications.email_status      VARCHAR(16) NOT NULL DEFAULT 'skipped'
  * notifications.email_attempts    INTEGER     NOT NULL DEFAULT 0
  * notifications.email_sent_at     TIMESTAMPTZ NULL
  * notifications.email_last_error  TEXT        NULL
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0033"
down_revision: Union[str, None] = "0032"
branch_labels = None
depends_on = None


def _has_column(bind, table: str, column: str) -> bool:
    insp = sa.inspect(bind)
    if table not in insp.get_table_names():
        return False
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, "notifications", "email_status"):
        op.add_column(
            "notifications",
            sa.Column("email_status", sa.String(16), nullable=False,
                      server_default="skipped"),
        )
    if not _has_column(bind, "notifications", "email_attempts"):
        op.add_column(
            "notifications",
            sa.Column("email_attempts", sa.Integer(), nullable=False,
                      server_default="0"),
        )
    if not _has_column(bind, "notifications", "email_sent_at"):
        op.add_column(
            "notifications",
            sa.Column("email_sent_at", sa.DateTime(timezone=True), nullable=True),
        )
    if not _has_column(bind, "notifications", "email_last_error"):
        op.add_column(
            "notifications",
            sa.Column("email_last_error", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    for col in ("email_last_error", "email_sent_at", "email_attempts",
                "email_status"):
        if _has_column(bind, "notifications", col):
            op.drop_column("notifications", col)
