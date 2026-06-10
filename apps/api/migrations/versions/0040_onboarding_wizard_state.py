"""onboarding_wizard_state — Phase-3.7 onboarding wizard

Revision ID: 0040
Revises: 0039
Create Date: 2026-06-10

Phase-3.7. Pure additive — NEW table ``onboarding_wizard_state`` (1:1 per
website): a lightweight roll-up of the 3.1-3.6 step statuses for the guided
onboarding flow (current step, overall status, per-step snapshot, completed_at).
No secrets.

Idempotent (table-exists guard). Reversible.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0040"
down_revision: Union[str, None] = "0039"
branch_labels = None
depends_on = None


def _has_table(bind, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "onboarding_wizard_state"):
        return
    op.create_table(
        "onboarding_wizard_state",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("website_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("domain", sa.String(255), nullable=False),
        sa.Column("current_step", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("overall_status", sa.String(20), nullable=False, server_default="not_started"),
        sa.Column("provider", sa.String(64), nullable=True),
        sa.Column("verification_status", sa.String(24), nullable=True),
        sa.Column("trusted_access_status", sa.String(24), nullable=True),
        sa.Column("validation_status", sa.String(24), nullable=True),
        sa.Column("readiness_status", sa.String(24), nullable=True),
        sa.Column("monitoring_status", sa.String(24), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["website_id"], ["websites.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["orgs.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("website_id", name="uq_onboarding_wizard_website_id"),
    )
    op.create_index("ix_onboarding_wizard_org_id", "onboarding_wizard_state", ["org_id"])
    op.create_index("ix_onboarding_wizard_domain", "onboarding_wizard_state", ["domain"])


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "onboarding_wizard_state"):
        return
    for ix in ("ix_onboarding_wizard_domain", "ix_onboarding_wizard_org_id"):
        try:
            op.drop_index(ix, table_name="onboarding_wizard_state")
        except Exception:  # noqa: BLE001
            pass
    op.drop_table("onboarding_wizard_state")
