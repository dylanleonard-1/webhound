"""verificationstatus: add EXPIRED + REVOKED — Phase-3.2 ownership lifecycle

Revision ID: 0036
Revises: 0035
Create Date: 2026-06-09

Phase-3.2. Adds two values to the ``verificationstatus`` enum so a website's
ownership can be REVOKED (owner withdrew access; monitoring paused) or EXPIRED
(proof lapsed). PostgreSQL only — SQLite test DBs build the enum from the model
via create_all. ``ADD VALUE`` runs in an autocommit block (it cannot execute
inside a transaction on older PostgreSQL). Postgres has no ``DROP VALUE``, so
downgrade is an intentional no-op.
"""
from __future__ import annotations

from typing import Union

from alembic import op


revision: str = "0036"
down_revision: Union[str, None] = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE verificationstatus ADD VALUE IF NOT EXISTS 'expired'")
        op.execute("ALTER TYPE verificationstatus ADD VALUE IF NOT EXISTS 'revoked'")


def downgrade() -> None:
    # PostgreSQL cannot remove a value from an enum type; leaving 'expired' and
    # 'revoked' in place is harmless. Intentional no-op.
    pass
