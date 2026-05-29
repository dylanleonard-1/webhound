"""false-positive suppression table

Revision ID: 0030
Revises: 0029
Create Date: 2026-05-29

Phase-5F: persistent suppression records. New table only — no
existing schema touched. Idempotent: re-runs detect the table and
skip creation. SQLite path uses sa.Enum (CHECK constraint) so the
test fixture can still build the schema from ``Base.metadata``.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0030"
down_revision: Union[str, None] = "0029"
branch_labels = None
depends_on = None


_SCOPE_VALUES = ("domain", "vendor", "finding_title", "site")


def _has_table(bind, name: str) -> bool:
    return name in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    if dialect == "postgresql":
        op.execute(
            "DO $$ BEGIN CREATE TYPE suppressionscope AS ENUM "
            + str(_SCOPE_VALUES) + "; "
            "EXCEPTION WHEN duplicate_object THEN null; END $$;"
        )
        scope_type = postgresql.ENUM(
            *_SCOPE_VALUES, name="suppressionscope", create_type=False,
        )
    else:
        scope_type = sa.Enum(*_SCOPE_VALUES, name="suppressionscope")

    if _has_table(bind, "suppressions"):
        return

    op.create_table(
        "suppressions",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "org_id", sa.Uuid(as_uuid=True),
            sa.ForeignKey("orgs.id", ondelete="CASCADE"),
        ),
        sa.Column("scope", scope_type, nullable=False),
        sa.Column("pattern", sa.String(512), nullable=False),
        sa.Column("scanner_engine", sa.String(64)),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("creator_email", sa.String(320)),
        sa.Column(
            "creator_user_id", sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column(
            "is_active", sa.Boolean(), nullable=False,
            server_default=sa.true(),
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_suppressions_org_id", "suppressions", ["org_id"])
    op.create_index(
        "ix_suppressions_org_scope_active",
        "suppressions", ["org_id", "scope", "is_active"],
    )
    op.create_index(
        "ix_suppressions_expires_at",
        "suppressions", ["expires_at"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "suppressions"):
        return
    for ix in ("ix_suppressions_expires_at",
                "ix_suppressions_org_scope_active",
                "ix_suppressions_org_id"):
        try:
            op.drop_index(ix, table_name="suppressions")
        except Exception:  # noqa: BLE001
            pass
    op.drop_table("suppressions")
    if bind.dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS suppressionscope")
