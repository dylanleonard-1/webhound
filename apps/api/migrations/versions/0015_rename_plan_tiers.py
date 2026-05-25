"""rename plan tiers: drop starter, add shield

Revision ID: 0015
Revises: 0014
Create Date: 2026-05-24

The Stripe products are: WebHound Pro ($29), WebHound Shield ($79),
WebHound Enterprise ($129). The Phase 1 scaffold used 'starter' instead
of 'shield' and assumed enterprise was contact-sales (no checkout).
This migration rebuilds the plantier enum to match the real products.

Safe because no production users are on paid plans yet — the upgrade
defensively maps any starter rows to free.
"""
from __future__ import annotations

from typing import Union

from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Defensive: migrate any existing starter rows down to free. With the
    # Phase 1 deploy fresh, this should be a no-op.
    op.execute("UPDATE users SET plan = 'free' WHERE plan = 'starter'")
    op.execute(
        "UPDATE subscriptions SET plan = 'free' WHERE plan = 'starter'"
    )

    # Build a new enum with the corrected value set, swap the columns over
    # to it, drop the old one. PG doesn't allow DROP VALUE on an in-use
    # enum so the swap-and-rename dance is the standard pattern.
    op.execute(
        "CREATE TYPE plantier_new AS ENUM "
        "('free', 'pro', 'shield', 'enterprise')"
    )
    op.execute(
        "ALTER TABLE users ALTER COLUMN plan DROP DEFAULT"
    )
    op.execute(
        "ALTER TABLE users ALTER COLUMN plan "
        "TYPE plantier_new USING plan::text::plantier_new"
    )
    op.execute(
        "ALTER TABLE subscriptions ALTER COLUMN plan "
        "TYPE plantier_new USING plan::text::plantier_new"
    )
    op.execute(
        "ALTER TABLE users ALTER COLUMN plan SET DEFAULT 'free'::plantier_new"
    )
    op.execute("DROP TYPE plantier")
    op.execute("ALTER TYPE plantier_new RENAME TO plantier")


def downgrade() -> None:
    # Reverse: migrate any shield rows back to free, then swap back.
    op.execute("UPDATE users SET plan = 'free' WHERE plan = 'shield'")
    op.execute(
        "UPDATE subscriptions SET plan = 'free' WHERE plan = 'shield'"
    )
    op.execute(
        "CREATE TYPE plantier_old AS ENUM "
        "('free', 'starter', 'pro', 'enterprise')"
    )
    op.execute("ALTER TABLE users ALTER COLUMN plan DROP DEFAULT")
    op.execute(
        "ALTER TABLE users ALTER COLUMN plan "
        "TYPE plantier_old USING plan::text::plantier_old"
    )
    op.execute(
        "ALTER TABLE subscriptions ALTER COLUMN plan "
        "TYPE plantier_old USING plan::text::plantier_old"
    )
    op.execute(
        "ALTER TABLE users ALTER COLUMN plan SET DEFAULT 'free'::plantier_old"
    )
    op.execute("DROP TYPE plantier")
    op.execute("ALTER TYPE plantier_old RENAME TO plantier")
