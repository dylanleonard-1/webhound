"""add terms_agreed_at to users

Revision ID: 0016
Revises: 0015
Create Date: 2026-05-24

Tracks when (and whether) a user agreed to the Terms / Privacy / AUP.
NULL means they haven't agreed yet — the AuthProvider will redirect
those users to /agreement on first dashboard load and block access
until they accept.

Existing users predating this column have NULL by design — they need
to click through the agreement screen once to continue using the app.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: Union[str, None] = "0015"
branch_labels = None
depends_on = None


def _has_column(inspector: sa.engine.reflection.Inspector,
                table_name: str, column_name: str) -> bool:
    try:
        cols = {c["name"] for c in inspector.get_columns(table_name)}
    except sa.exc.NoSuchTableError:
        return False
    return column_name in cols


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not _has_column(inspector, "users", "terms_agreed_at"):
        op.add_column(
            "users",
            sa.Column(
                "terms_agreed_at", sa.DateTime(timezone=True), nullable=True,
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_column(inspector, "users", "terms_agreed_at"):
        op.drop_column("users", "terms_agreed_at")
