"""scan_jobs.guest_token for the public /public/scan flow

Revision ID: 0031
Revises: 0030
Create Date: 2026-05-29

Phase-rebuild Slice 4.A. Adds the column the public/guest scan
flow needs to look up a scan without authentication. Pure additive:

  * NEW NULLABLE column ``scan_jobs.guest_token`` (UUID, unique,
    indexed).
  * No backfill — every existing row stays NULL (they're
    authenticated scans). The public router only consults this
    column; authenticated scans continue to look up by id.

Idempotent (table-exists / column-exists guards). Reversible.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0031"
down_revision: Union[str, None] = "0030"
branch_labels = None
depends_on = None


def _has_column(bind, table: str, column: str) -> bool:
    insp = sa.inspect(bind)
    if table not in insp.get_table_names():
        return False
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if _has_column(bind, "scan_jobs", "guest_token"):
        return
    op.add_column(
        "scan_jobs",
        sa.Column("guest_token", sa.Uuid(as_uuid=True), nullable=True),
    )
    op.create_index(
        "ix_scan_jobs_guest_token", "scan_jobs", ["guest_token"],
        unique=True,
    )


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, "scan_jobs", "guest_token"):
        return
    try:
        op.drop_index("ix_scan_jobs_guest_token", table_name="scan_jobs")
    except Exception:  # noqa: BLE001
        pass
    op.drop_column("scan_jobs", "guest_token")
