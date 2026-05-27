"""internal platform RBAC: users.admin_role + admin_audit_logs

Revision ID: 0017
Revises: 0016
Create Date: 2026-05-27

Adds the internal /control command center foundation:
  - users.admin_role  (string, default "none") — RBAC role for staff
  - admin_audit_logs  — immutable trail of privileged actions

Backfill: existing is_admin=True accounts become "super_admin" so the
current owner keeps full access. Idempotent (safe to re-run).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017"
down_revision: Union[str, None] = "0016"
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

    if not _has_column(inspector, "users", "admin_role"):
        op.add_column(
            "users",
            sa.Column("admin_role", sa.String(length=32),
                      server_default="none", nullable=False),
        )
        # Existing admins keep full access under the new RBAC model.
        op.execute("UPDATE users SET admin_role = 'super_admin' WHERE is_admin = true")

    if not _has_table(inspector, "admin_audit_logs"):
        op.create_table(
            "admin_audit_logs",
            sa.Column("id", sa.UUID(as_uuid=True), primary_key=True),
            sa.Column("actor_user_id", sa.UUID(as_uuid=True),
                      sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("actor_email", sa.String(length=320), nullable=True),
            sa.Column("actor_role", sa.String(length=32), nullable=True),
            sa.Column("action", sa.String(length=80), nullable=False),
            sa.Column("target_type", sa.String(length=48), nullable=True),
            sa.Column("target_id", sa.String(length=64), nullable=True),
            sa.Column("detail", postgresql.JSONB(), server_default="{}", nullable=False),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("request_id", sa.String(length=64), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_admin_audit_logs_actor_user_id", "admin_audit_logs", ["actor_user_id"])
        op.create_index("ix_admin_audit_logs_action", "admin_audit_logs", ["action"])
        op.create_index("ix_admin_audit_logs_target", "admin_audit_logs", ["target_type", "target_id"])
        op.create_index("ix_admin_audit_logs_created_at", "admin_audit_logs", ["created_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_table(inspector, "admin_audit_logs"):
        op.drop_table("admin_audit_logs")
    if _has_column(inspector, "users", "admin_role"):
        op.drop_column("users", "admin_role")
