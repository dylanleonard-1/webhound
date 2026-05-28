"""fraud & abuse: abuse_flags + ip_device_fingerprints

Revision ID: 0020
Revises: 0019
Create Date: 2026-05-28

Phase 5 of the internal /control platform — Fraud & Abuse:
  - abuse_flags             — flagged users / IPs with score, reasons, status
  - ip_device_fingerprints  — (user, ip, user_agent) tuples observed on login

Idempotent (safe to re-run).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels = None
depends_on = None


def _has_table(inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "abuse_flags"):
        op.create_table(
            "abuse_flags",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("dedup_key", sa.String(length=200), nullable=False),
            sa.Column("user_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
            sa.Column("reasons", postgresql.JSONB(), nullable=False, server_default="[]"),
            sa.Column("detail", postgresql.JSONB(), nullable=False, server_default="{}"),
            sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("resolved_by_email", sa.String(length=320), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolution_note", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_abuse_flags_dedup_key", "abuse_flags", ["dedup_key"], unique=True)
        op.create_index("ix_abuse_flags_user_id", "abuse_flags", ["user_id"])
        op.create_index("ix_abuse_flags_severity", "abuse_flags", ["severity"])
        op.create_index("ix_abuse_flags_status", "abuse_flags", ["status"])
        op.create_index("ix_abuse_flags_status_severity", "abuse_flags", ["status", "severity"])

    if not _has_table(inspector, "ip_device_fingerprints"):
        op.create_table(
            "ip_device_fingerprints",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("user_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("ip_address", sa.String(length=64), nullable=False),
            sa.Column("user_agent", sa.String(length=500), nullable=False),
            sa.Column("occurrences", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_unique_constraint(
            "uq_fingerprint_user_ip_ua", "ip_device_fingerprints",
            ["user_id", "ip_address", "user_agent"],
        )
        op.create_index("ix_fingerprint_user_id", "ip_device_fingerprints", ["user_id"])
        op.create_index("ix_fingerprint_last_seen_at", "ip_device_fingerprints", ["last_seen_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_table(inspector, "ip_device_fingerprints"):
        op.drop_table("ip_device_fingerprints")
    if _has_table(inspector, "abuse_flags"):
        op.drop_table("abuse_flags")
