"""website_groups + websites.group_id for the Phase-16 portfolio

Revision ID: 0032
Revises: 0031
Create Date: 2026-06-07

Phase-16 Agency/MSP portfolio. Pure additive — single-site users are
unaffected (group_id stays NULL):

  * NEW table ``website_groups`` (org-scoped client/location groups).
  * NEW NULLABLE column ``websites.group_id`` (FK → website_groups,
    ON DELETE SET NULL, indexed).

Idempotent (table/column-exists guards). Reversible.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0032"
down_revision: Union[str, None] = "0031"
branch_labels = None
depends_on = None


def _has_table(bind, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def _has_column(bind, table: str, column: str) -> bool:
    insp = sa.inspect(bind)
    if table not in insp.get_table_names():
        return False
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "website_groups"):
        op.create_table(
            "website_groups",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("org_id", sa.Uuid(as_uuid=True), nullable=False),
            sa.Column("name", sa.String(200), nullable=False),
            sa.Column("group_type", sa.String(40), nullable=False,
                      server_default="agency_client"),
            sa.Column("parent_group_id", sa.Uuid(as_uuid=True),
                      nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True),
                      nullable=True),
            sa.ForeignKeyConstraint(["org_id"], ["orgs.id"],
                                    ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["parent_group_id"],
                                    ["website_groups.id"],
                                    ondelete="SET NULL"),
        )
        op.create_index("ix_website_groups_org_id", "website_groups",
                        ["org_id"])

    if not _has_column(bind, "websites", "group_id"):
        op.add_column(
            "websites",
            sa.Column("group_id", sa.Uuid(as_uuid=True), nullable=True))
        op.create_index("ix_websites_group_id", "websites", ["group_id"])
        op.create_foreign_key(
            "fk_websites_group_id", "websites", "website_groups",
            ["group_id"], ["id"], ondelete="SET NULL")


def downgrade() -> None:
    bind = op.get_bind()
    if _has_column(bind, "websites", "group_id"):
        try:
            op.drop_constraint("fk_websites_group_id", "websites",
                               type_="foreignkey")
        except Exception:  # noqa: BLE001
            pass
        try:
            op.drop_index("ix_websites_group_id", table_name="websites")
        except Exception:  # noqa: BLE001
            pass
        op.drop_column("websites", "group_id")
    if _has_table(bind, "website_groups"):
        try:
            op.drop_index("ix_website_groups_org_id",
                          table_name="website_groups")
        except Exception:  # noqa: BLE001
            pass
        op.drop_table("website_groups")
