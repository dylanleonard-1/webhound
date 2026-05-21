"""add OAuth fields to users

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-21

Changes:
  - Add oauth_provider (varchar 50, nullable) to users
  - Add oauth_provider_id (varchar 255, nullable, indexed) to users
  - Add full_name (varchar 255, nullable) to users
  - Add avatar_url (varchar 500, nullable) to users
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("oauth_provider", sa.String(50), nullable=True))
    op.add_column("users", sa.Column("oauth_provider_id", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("full_name", sa.String(255), nullable=True))
    op.add_column("users", sa.Column("avatar_url", sa.String(500), nullable=True))
    op.create_index("ix_users_oauth_provider_id", "users", ["oauth_provider_id"])


def downgrade() -> None:
    op.drop_index("ix_users_oauth_provider_id", table_name="users")
    op.drop_column("users", "avatar_url")
    op.drop_column("users", "full_name")
    op.drop_column("users", "oauth_provider_id")
    op.drop_column("users", "oauth_provider")
