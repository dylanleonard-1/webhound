"""support / fix service: support_tickets + support_ticket_events

Revision ID: 0021
Revises: 0020
Create Date: 2026-05-28

Phase 6 of the internal /control platform — Support / Fix Service:
  - support_tickets         — work units for staff (remediation, questions,
                              bugs, billing). SLA computed at creation.
  - support_ticket_events   — per-ticket timeline (comments / status changes
                              / system entries) with public|internal visibility

Idempotent (safe to re-run).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels = None
depends_on = None


def _has_table(inspector, table: str) -> bool:
    return table in inspector.get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if not _has_table(inspector, "support_tickets"):
        op.create_table(
            "support_tickets",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("number", sa.Integer(), nullable=False),
            sa.Column("user_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("subject", sa.String(length=200), nullable=False),
            sa.Column("description", sa.Text(), nullable=True),
            sa.Column("category", sa.String(length=32), nullable=False, server_default="remediation"),
            sa.Column("priority", sa.String(length=16), nullable=False, server_default="medium"),
            sa.Column("status", sa.String(length=24), nullable=False, server_default="open"),
            sa.Column("assignee_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
            sa.Column("source_scan_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True),
            sa.Column("verification_scan_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True),
            sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("first_response_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_support_tickets_number", "support_tickets", ["number"], unique=True)
        op.create_index("ix_support_tickets_status_priority", "support_tickets", ["status", "priority"])
        op.create_index("ix_support_tickets_assignee_id", "support_tickets", ["assignee_id"])
        op.create_index("ix_support_tickets_user_id", "support_tickets", ["user_id"])
        op.create_index("ix_support_tickets_status", "support_tickets", ["status"])
        op.create_index("ix_support_tickets_priority", "support_tickets", ["priority"])
        op.create_index("ix_support_tickets_sla_due_at", "support_tickets", ["sla_due_at"])

    if not _has_table(inspector, "support_ticket_events"):
        op.create_table(
            "support_ticket_events",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("ticket_id", sa.Uuid(as_uuid=True),
                      sa.ForeignKey("support_tickets.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("kind", sa.String(length=24), nullable=False, server_default="comment"),
            sa.Column("visibility", sa.String(length=16), nullable=False, server_default="public"),
            sa.Column("author_email", sa.String(length=320), nullable=True),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_support_ticket_events_ticket_id",
                        "support_ticket_events", ["ticket_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if _has_table(inspector, "support_ticket_events"):
        op.drop_table("support_ticket_events")
    if _has_table(inspector, "support_tickets"):
        op.drop_table("support_tickets")
