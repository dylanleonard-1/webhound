"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-05-07
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Enum type names used in PostgreSQL
_VERIFICATION_STATUS = sa.Enum(
    "unverified", "pending", "verified", "failed", name="verificationstatus"
)
_VERIFICATION_METHOD = sa.Enum(
    "dns_txt", "meta_tag", "html_file", name="verificationmethod"
)
_SCAN_STATUS = sa.Enum(
    "queued", "running", "completed", "failed", "cancelled", name="scanstatus"
)
_SCAN_PROFILE = sa.Enum(
    "quick", "standard", "deep", "monitor", name="scanprofile"
)
_REPORT_FORMAT = sa.Enum(
    "json", "sarif", "csv", "markdown", name="reportformat"
)


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_email", "users", ["email"])

    op.create_table(
        "websites",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("scheme", sa.String(16), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column(
            "verification_status",
            _VERIFICATION_STATUS,
            nullable=False,
            server_default="unverified",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_websites_user_id", "websites", ["user_id"])
    op.create_index("ix_websites_hostname", "websites", ["hostname"])

    op.create_table(
        "domain_verifications",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("website_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("method", _VERIFICATION_METHOD, nullable=False),
        sa.Column("token", sa.String(255), nullable=False),
        sa.Column(
            "status",
            _VERIFICATION_STATUS,
            nullable=False,
            server_default="pending",
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["website_id"], ["websites.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_domain_verifications_website_id", "domain_verifications", ["website_id"]
    )

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("website_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column(
            "status", _SCAN_STATUS, nullable=False, server_default="queued"
        ),
        sa.Column(
            "profile", _SCAN_PROFILE, nullable=False, server_default="standard"
        ),
        sa.Column("requested_url", sa.String(2048), nullable=False),
        sa.Column(
            "use_latest_baseline", sa.Boolean, nullable=False, server_default="false"
        ),
        sa.Column(
            "save_baseline", sa.Boolean, nullable=False, server_default="true"
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["website_id"], ["websites.id"], ondelete="CASCADE"
        ),
    )
    op.create_index("ix_scan_jobs_website_id", "scan_jobs", ["website_id"])
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])

    op.create_table(
        "scan_results",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("scan_job_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_id", sa.String(255), nullable=True),
        sa.Column("risk_score", sa.Integer, nullable=False),
        sa.Column("risk_level", sa.String(32), nullable=False),
        sa.Column("duration_seconds", sa.Float, nullable=True),
        sa.Column("pages_crawled", sa.Integer, nullable=False, server_default="0"),
        sa.Column("total_findings", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "actionable_findings", sa.Integer, nullable=False, server_default="0"
        ),
        sa.Column("severity_breakdown", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("scanner_metadata", sa.JSON, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"], ["scan_jobs.id"], ondelete="CASCADE"
        ),
        sa.UniqueConstraint("scan_job_id"),
    )
    op.create_index("ix_scan_results_scan_job_id", "scan_results", ["scan_job_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("scan_result_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scanner_finding_id", sa.String(255), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("scanner_engine", sa.String(64), nullable=False),
        sa.Column("affected_url", sa.String(2048), nullable=True),
        sa.Column("confidence", sa.Float, nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column("evidence", sa.JSON, nullable=True),
        sa.Column("framework", sa.JSON, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_result_id"], ["scan_results.id"], ondelete="CASCADE"
        ),
    )
    op.create_index("ix_findings_scan_result_id", "findings", ["scan_result_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])

    op.create_table(
        "grouped_findings",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("scan_result_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("scanner_engine", sa.String(64), nullable=False),
        sa.Column("affected_url_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("affected_urls", sa.JSON, nullable=True),
        sa.Column("evidence_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("confidence", sa.Float, nullable=True),
        sa.Column("remediation", sa.Text, nullable=True),
        sa.Column("framework", sa.JSON, nullable=True),
        sa.Column("finding_ids", sa.JSON, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_result_id"], ["scan_results.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_grouped_findings_scan_result_id", "grouped_findings", ["scan_result_id"]
    )
    op.create_index("ix_grouped_findings_severity", "grouped_findings", ["severity"])

    op.create_table(
        "engine_diagnostics",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("scan_result_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("engine_name", sa.String(64), nullable=False),
        sa.Column("category", sa.String(64), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("findings_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("severity_counts", sa.JSON, nullable=True),
        sa.Column("duration_ms", sa.Float, nullable=True),
        sa.Column("skipped_reason", sa.Text, nullable=True),
        sa.Column("error_message", sa.Text, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_result_id"], ["scan_results.id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_engine_diagnostics_scan_result_id",
        "engine_diagnostics",
        ["scan_result_id"],
    )

    op.create_table(
        "baselines",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("website_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("baseline_id", sa.String(255), nullable=False),
        sa.Column("baseline_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("baseline_json", sa.JSON, nullable=False, server_default="{}"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["website_id"], ["websites.id"], ondelete="CASCADE"
        ),
    )
    op.create_index("ix_baselines_website_id", "baselines", ["website_id"])

    op.create_table(
        "reports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("scan_result_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("format", _REPORT_FORMAT, nullable=False),
        sa.Column("path", sa.String(2048), nullable=True),
        sa.Column("content_json", sa.JSON, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_result_id"], ["scan_results.id"], ondelete="CASCADE"
        ),
    )
    op.create_index("ix_reports_scan_result_id", "reports", ["scan_result_id"])


def downgrade() -> None:
    op.drop_table("reports")
    op.drop_table("baselines")
    op.drop_table("engine_diagnostics")
    op.drop_table("grouped_findings")
    op.drop_table("findings")
    op.drop_table("scan_results")
    op.drop_table("scan_jobs")
    op.drop_table("domain_verifications")
    op.drop_table("websites")
    op.drop_table("users")
    _VERIFICATION_STATUS.drop(op.get_bind(), checkfirst=True)
    _VERIFICATION_METHOD.drop(op.get_bind(), checkfirst=True)
    _SCAN_STATUS.drop(op.get_bind(), checkfirst=True)
    _SCAN_PROFILE.drop(op.get_bind(), checkfirst=True)
    _REPORT_FORMAT.drop(op.get_bind(), checkfirst=True)
