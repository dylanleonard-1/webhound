"""visibility_reports — crawler visibility layer persistence

Revision ID: 0043
Revises: 0042
Create Date: 2026-06-12

Pure additive. NEW tables:
  * ``visibility_reports`` (1:1 per scan_result) — headline coverage metrics in
    columns + the full report JSON (sections / score breakdown / page tree).
  * ``discovered_urls`` (N per visibility_report) — the canonical discovery
    inventory with provenance + the explainable skip reason.

Written only when a scan ran with the visibility layer enabled AND the operator
opted into table persistence (WEBHOUND_PERSIST_VISIBILITY=1); the report also
remains available in scan_results.scanner_metadata regardless. No secrets.

Idempotent (table-exists guard). Reversible.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op


revision: str = "0043"
down_revision: Union[str, None] = "0042"
branch_labels = None
depends_on = None


def _has_table(bind, table: str) -> bool:
    return table in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_table(bind, "visibility_reports"):
        op.create_table(
            "visibility_reports",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("scan_result_id", sa.Uuid(as_uuid=True), nullable=False),
            sa.Column("domain", sa.String(255), nullable=True),
            sa.Column("crawl_mode", sa.String(32), nullable=True),
            sa.Column("pages_found", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("pages_crawled", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("visibility_score", sa.Integer(), nullable=True),
            sa.Column("forms_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("api_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("js_routes_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("assets_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("third_party_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("site_graph_generated", sa.Boolean(), nullable=False,
                      server_default=sa.false()),
            sa.Column("report", sa.JSON(), nullable=True),
            sa.Column("limitations", sa.JSON(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["scan_result_id"], ["scan_results.id"],
                                    ondelete="CASCADE"),
            sa.UniqueConstraint("scan_result_id",
                                name="uq_visibility_reports_scan_result_id"),
        )
        op.create_index("ix_visibility_reports_scan_result_id",
                        "visibility_reports", ["scan_result_id"])
        op.create_index("ix_visibility_reports_domain",
                        "visibility_reports", ["domain"])
        op.create_index("ix_visibility_reports_visibility_score",
                        "visibility_reports", ["visibility_score"])

    if not _has_table(bind, "discovered_urls"):
        op.create_table(
            "discovered_urls",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("visibility_report_id", sa.Uuid(as_uuid=True), nullable=False),
            sa.Column("url", sa.Text(), nullable=False),
            sa.Column("normalized", sa.Text(), nullable=True),
            sa.Column("discovered_via", sa.String(32), nullable=True),
            sa.Column("sources", sa.JSON(), nullable=True),
            sa.Column("tags", sa.JSON(), nullable=True),
            sa.Column("depth", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("parent", sa.Text(), nullable=True),
            sa.Column("status", sa.String(16), nullable=True),
            sa.Column("skip_reason", sa.Text(), nullable=True),
            sa.Column("in_scope", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("status_code", sa.Integer(), nullable=True),
            sa.Column("content_type", sa.String(128), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                      server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["visibility_report_id"], ["visibility_reports.id"],
                                    ondelete="CASCADE"),
        )
        op.create_index("ix_discovered_urls_visibility_report_id",
                        "discovered_urls", ["visibility_report_id"])
        op.create_index("ix_discovered_urls_status", "discovered_urls", ["status"])
        op.create_index("ix_discovered_urls_report_status",
                        "discovered_urls", ["visibility_report_id", "status"])


def downgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "discovered_urls"):
        op.drop_table("discovered_urls")
    if _has_table(bind, "visibility_reports"):
        op.drop_table("visibility_reports")
