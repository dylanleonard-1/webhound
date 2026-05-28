"""engines registry + SOC incidents

Revision ID: 0025
Revises: 0024
Create Date: 2026-05-28

Phase 10 of the internal /control platform — SOC operational uplift:
  - engines           — per-engine maintenance flag + auto-disable threshold
  - incidents         — correlated grouping of alerts with status/SLA/MTTR
  - incident_events   — per-incident timeline (alert_attached/status/note/system)

Idempotent (safe to re-run).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0025"
down_revision: Union[str, None] = "0024"
branch_labels = None
depends_on = None


def _has_table(inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "engines"):
        op.create_table(
            "engines",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("name", sa.String(length=64), nullable=False),
            sa.Column("maintenance_mode", sa.Boolean(), nullable=False,
                      server_default=sa.text("false")),
            sa.Column("auto_disable_at_failure_pct", sa.Integer(), nullable=True),
            sa.Column("auto_disabled_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("updated_by_email", sa.String(length=320), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_engines_name", "engines", ["name"], unique=True)

    if not _has_table(inspector, "incidents"):
        op.create_table(
            "incidents",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("number", sa.Integer(), nullable=False),
            sa.Column("correlation_key", sa.String(length=220), nullable=False),
            sa.Column("source", sa.String(length=48), nullable=False),
            sa.Column("title", sa.String(length=220), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False),
            sa.Column("status", sa.String(length=20), nullable=False, server_default="open"),
            sa.Column("target_type", sa.String(length=48), nullable=True),
            sa.Column("target_id", sa.String(length=64), nullable=True),
            sa.Column("detail", postgresql.JSONB(), nullable=False, server_default="{}"),
            sa.Column("alert_count", sa.Integer(), nullable=False, server_default="1"),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("assignee_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("acknowledged_by_email", sa.String(length=320), nullable=True),
            sa.Column("mitigated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_by_email", sa.String(length=320), nullable=True),
            sa.Column("mttr_seconds", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_incidents_number", "incidents", ["number"], unique=True)
        op.create_index("ix_incidents_correlation_key", "incidents", ["correlation_key"])
        op.create_index("ix_incidents_source", "incidents", ["source"])
        op.create_index("ix_incidents_severity", "incidents", ["severity"])
        op.create_index("ix_incidents_status", "incidents", ["status"])
        op.create_index("ix_incidents_status_severity", "incidents", ["status", "severity"])
        op.create_index("ix_incidents_last_seen_at", "incidents", ["last_seen_at"])

    if not _has_table(inspector, "incident_events"):
        op.create_table(
            "incident_events",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("incident_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
            sa.Column("kind", sa.String(length=24), nullable=False, server_default="note"),
            sa.Column("author_email", sa.String(length=320), nullable=True),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("alert_id", sa.Uuid(as_uuid=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_incident_events_incident_id", "incident_events", ["incident_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_table(inspector, "incident_events"):
        op.drop_table("incident_events")
    if _has_table(inspector, "incidents"):
        op.drop_table("incidents")
    if _has_table(inspector, "engines"):
        op.drop_table("engines")
