"""add login OTP fields

Revision ID: 0012
Revises: 0011
Create Date: 2026-05-22
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("login_otp", sa.String(10), nullable=True))
    op.add_column("users", sa.Column("login_otp_expires_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "login_otp_expires_at")
    op.drop_column("users", "login_otp")
