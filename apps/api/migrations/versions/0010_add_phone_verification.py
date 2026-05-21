"""add phone verification fields

Revision ID: 0010
Revises: 0009
Create Date: 2026-05-21
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("phone_number", sa.String(32), nullable=True))
    op.add_column("users", sa.Column("phone_verified", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("users", sa.Column("phone_otp", sa.String(10), nullable=True))
    op.add_column("users", sa.Column("phone_otp_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "phone_otp_expires_at")
    op.drop_column("users", "phone_otp")
    op.drop_column("users", "phone_verified")
    op.drop_column("users", "phone_number")
