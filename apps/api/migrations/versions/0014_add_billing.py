"""add billing: plan + stripe_customer_id on users, subscriptions table

Revision ID: 0014
Revises: 0013
Create Date: 2026-05-24

Idempotent against a partially-applied state. A previous deploy attempt
left the `subscriptionstatus` enum in the database while the table
creation failed; replaying the migration would then crash on the enum-
create step. This file uses:

  - postgresql.ENUM(..., create_type=False) for explicit type identity
  - .create(bind, checkfirst=True) to no-op when the type already exists
  - inspector checks before add_column / create_table / create_index so
    re-runs against partial state succeed

The migration is therefore safe to apply N times against any prior
state in {nothing applied, enum exists but no table, columns exist but
no table, fully applied}.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels = None
depends_on = None


_PLAN_VALUES = ("free", "starter", "pro", "enterprise")
_SUB_STATUS_VALUES = (
    "trialing", "active", "past_due", "unpaid",
    "canceled", "incomplete", "incomplete_expired", "paused",
)


# Module-level enum identities. create_type=False keeps SQLAlchemy from
# trying to emit CREATE TYPE during op.add_column / op.create_table —
# we manage the lifecycle explicitly below with checkfirst=True so the
# whole migration is idempotent.
plan_tier_enum = postgresql.ENUM(
    *_PLAN_VALUES, name="plantier", create_type=False,
)
subscription_status_enum = postgresql.ENUM(
    *_SUB_STATUS_VALUES, name="subscriptionstatus", create_type=False,
)


def _has_column(inspector: sa.engine.reflection.Inspector,
                table_name: str, column_name: str) -> bool:
    try:
        cols = {c["name"] for c in inspector.get_columns(table_name)}
    except sa.exc.NoSuchTableError:
        return False
    return column_name in cols


def _has_index(inspector: sa.engine.reflection.Inspector,
               table_name: str, index_name: str) -> bool:
    try:
        idxs = {i["name"] for i in inspector.get_indexes(table_name)}
    except sa.exc.NoSuchTableError:
        return False
    return index_name in idxs


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # 1. Enums — create only if missing.
    plan_tier_enum.create(bind, checkfirst=True)
    subscription_status_enum.create(bind, checkfirst=True)

    # 2. users.plan + users.stripe_customer_id — add only if missing.
    if not _has_column(inspector, "users", "plan"):
        op.add_column(
            "users",
            sa.Column(
                "plan", plan_tier_enum,
                nullable=False, server_default="free",
            ),
        )
    if not _has_column(inspector, "users", "stripe_customer_id"):
        op.add_column(
            "users",
            sa.Column("stripe_customer_id", sa.String(64), nullable=True),
        )

    # 3. Unique index on stripe_customer_id — only if missing.
    if not _has_index(inspector, "users", "ix_users_stripe_customer_id"):
        op.create_index(
            "ix_users_stripe_customer_id", "users",
            ["stripe_customer_id"], unique=True,
        )

    # 4. subscriptions table — create only if it doesn't exist.
    if not inspector.has_table("subscriptions"):
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
                "status", subscription_status_enum,
                nullable=False, index=True,
            ),
            sa.Column("plan", plan_tier_enum, nullable=False),
            sa.Column("current_period_start", sa.DateTime(timezone=True),
                      nullable=True),
            sa.Column("current_period_end", sa.DateTime(timezone=True),
                      nullable=True, index=True),
            sa.Column("cancel_at_period_end", sa.Boolean(),
                      nullable=False, server_default=sa.text("false")),
            sa.Column("canceled_at", sa.DateTime(timezone=True),
                      nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      nullable=False, server_default=sa.func.now()),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # 1. Drop the subscriptions table first (it references both enums via
    #    its `status` and `plan` columns, so the enums can't be dropped
    #    while the table exists).
    if inspector.has_table("subscriptions"):
        op.drop_table("subscriptions")

    # 2. Drop the unique index + columns from users, if present.
    inspector = sa.inspect(bind)  # refresh after the table drop
    if _has_index(inspector, "users", "ix_users_stripe_customer_id"):
        op.drop_index("ix_users_stripe_customer_id", table_name="users")
    if _has_column(inspector, "users", "stripe_customer_id"):
        op.drop_column("users", "stripe_customer_id")
    if _has_column(inspector, "users", "plan"):
        op.drop_column("users", "plan")

    # 3. Drop the enums with checkfirst — no-op if they were never created.
    subscription_status_enum.drop(bind, checkfirst=True)
    plan_tier_enum.drop(bind, checkfirst=True)
