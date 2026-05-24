"""add billing: plan + stripe_customer_id on users, subscriptions table

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-24
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels = None
depends_on = None


_PLAN_VALUES = ("free", "starter", "pro", "enterprise")
_SUB_STATUS_VALUES = (
    "trialing", "active", "past_due", "unpaid",
    "canceled", "incomplete", "incomplete_expired", "paused",
)


def upgrade() -> None:
    # Plan-tier enum (shared by users.plan and subscriptions.plan)
    plan_enum = sa.Enum(*_PLAN_VALUES, name="plantier")
    plan_enum.create(op.get_bind(), checkfirst=True)

    # users.plan + users.stripe_customer_id
    op.add_column(
        "users",
        sa.Column(
            "plan", sa.Enum(*_PLAN_VALUES, name="plantier", create_type=False),
            nullable=False, server_default="free",
        ),
    )
    op.add_column(
        "users",
        sa.Column("stripe_customer_id", sa.String(64), nullable=True),
    )
    op.create_index(
        "ix_users_stripe_customer_id", "users", ["stripe_customer_id"],
        unique=True,
    )

    # Subscription-status enum
    sub_status_enum = sa.Enum(*_SUB_STATUS_VALUES, name="subscriptionstatus")
    sub_status_enum.create(op.get_bind(), checkfirst=True)

    # subscriptions table
    op.create_table(
        "subscriptions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id", sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False, index=True,
        ),
        sa.Column("stripe_subscription_id", sa.String(64),
                  nullable=False, unique=True, index=True),
        sa.Column("stripe_customer_id", sa.String(64),
                  nullable=False, index=True),
        sa.Column("stripe_price_id", sa.String(64), nullable=True),
        sa.Column(
            "status",
            sa.Enum(*_SUB_STATUS_VALUES, name="subscriptionstatus",
                    create_type=False),
            nullable=False, index=True,
        ),
        sa.Column(
            "plan",
            sa.Enum(*_PLAN_VALUES, name="plantier", create_type=False),
            nullable=False,
        ),
        sa.Column("current_period_start", sa.DateTime(timezone=True),
                  nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True),
                  nullable=True, index=True),
        sa.Column("cancel_at_period_end", sa.Boolean(),
                  nullable=False, server_default=sa.text("false")),
        sa.Column("canceled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("subscriptions")
    op.drop_index("ix_users_stripe_customer_id", table_name="users")
    op.drop_column("users", "stripe_customer_id")
    op.drop_column("users", "plan")
    sa.Enum(name="subscriptionstatus").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="plantier").drop(op.get_bind(), checkfirst=True)
