"""customer ops: users.last_login/banned columns + internal_notes

Revision ID: 0019
Revises: 0018
Create Date: 2026-05-28

Phase 4 of the internal /control platform — Customer + Billing Ops:
  - users.last_login_at  — stamped by the auth flow
  - users.banned_at      — set when staff suspend an account
  - users.banned_reason  — free-form reason
  - internal_notes       — free-form staff notes on any target (users, scans, …)

Idempotent (safe to re-run).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: Union[str, None] = "0018"
branch_labels = None
depends_on = None


def _has_column(inspector, table: str, column: str) -> bool:
    try:
        return column in {c["name"] for c in inspector.get_columns(table)}
    except sa.exc.NoSuchTableError:
        return False


def _has_table(inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    for col, type_ in (
        ("last_login_at", sa.DateTime(timezone=True)),
        ("banned_at", sa.DateTime(timezone=True)),
        ("banned_reason", sa.Text()),
    ):
        if not _has_column(inspector, "users", col):
            op.add_column("users", sa.Column(col, type_, nullable=True))

    if not _has_table(inspector, "internal_notes"):
        op.create_table(
            "internal_notes",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("target_type", sa.String(length=48), nullable=False),
            sa.Column("target_id", sa.String(length=64), nullable=False),
            sa.Column("author_email", sa.String(length=320), nullable=True),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_internal_notes_target", "internal_notes",
                        ["target_type", "target_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_table(inspector, "internal_notes"):
        op.drop_table("internal_notes")
    for col in ("last_login_at", "banned_at", "banned_reason"):
        if _has_column(inspector, "users", col):
            op.drop_column("users", col)
