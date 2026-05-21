"""add description to grouped_findings

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-12

Changes:
  - Add description (TEXT, nullable) to grouped_findings table
    The scanner already produces description on GroupedFinding but it was
    not being persisted to the database.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "grouped_findings",
        sa.Column("description", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("grouped_findings", "description")
