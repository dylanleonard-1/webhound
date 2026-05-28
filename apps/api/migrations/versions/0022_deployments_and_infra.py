"""team/deploys/infra: deployments + infrastructure_samples

Revision ID: 0022
Revises: 0021
Create Date: 2026-05-28

Phase 7 of the internal /control platform — Team Mgmt + Deploys + Infra:
  - deployments              — manual deploy history with actor + status
  - infrastructure_samples   — periodic snapshots for trend charts

Idempotent (safe to re-run).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels = None
depends_on = None


def _has_table(inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "deployments"):
        op.create_table(
            "deployments",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("service", sa.String(length=32), nullable=False),
            sa.Column("sha", sa.String(length=64), nullable=False),
            sa.Column("status", sa.String(length=24), nullable=False, server_default="succeeded"),
            sa.Column("actor_email", sa.String(length=320), nullable=True),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_deployments_service", "deployments", ["service"])
        op.create_index("ix_deployments_sha", "deployments", ["sha"])
        op.create_index("ix_deployments_status", "deployments", ["status"])
        op.create_index("ix_deployments_service_started_at", "deployments",
                        ["service", "started_at"])

    if not _has_table(inspector, "infrastructure_samples"):
        op.create_table(
            "infrastructure_samples",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("taken_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("queue_depth", sa.Integer(), nullable=True),
            sa.Column("worker_alive", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("worker_heartbeat_age_s", sa.Float(), nullable=True),
            sa.Column("redis_used_memory_mb", sa.Float(), nullable=True),
            sa.Column("active_scans", sa.Integer(), nullable=True),
        )
        op.create_index("ix_infra_samples_taken_at", "infrastructure_samples", ["taken_at"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_table(inspector, "infrastructure_samples"):
        op.drop_table("infrastructure_samples")
    if _has_table(inspector, "deployments"):
        op.drop_table("deployments")
