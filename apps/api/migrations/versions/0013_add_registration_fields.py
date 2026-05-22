"""add company name and use case to users

Revision ID: 0013
Revises: 0012
Create Date: 2026-05-22
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("company_name", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("use_case", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "use_case")
    op.drop_column("users", "company_name")
