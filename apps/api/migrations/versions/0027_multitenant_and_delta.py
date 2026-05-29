"""multi-tenancy scaffolding + scan-delta table

Revision ID: 0027
Revises: 0026
Create Date: 2026-05-29

Phase-4 platform evolution. Additive-only — designed so a running
production deployment can apply this migration with zero downtime and
zero data risk:

  * NEW tables: ``orgs``, ``org_memberships``, ``scan_deltas``
  * NEW NULLABLE columns: ``org_id`` on websites, scan_jobs, incidents,
    alerts, scan_schedules
  * NEW indexes on each ``org_id``
  * No NOT NULL enforcement, no backfill, no destructive drops.

Subsequent migrations will (1) backfill ``org_id`` from existing
``user_id`` after every customer has an owning org and (2) flip
``org_id NOT NULL`` once 100% of rows are backfilled.

Idempotent on re-run.
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0027"
down_revision: Union[str, None] = "0026"
branch_labels = None
depends_on = None


_ORG_ROLE_VALUES = ("viewer", "billing", "analyst", "admin", "owner")
_DRIFT_SEVERITY_VALUES = ("none", "low", "medium", "high", "critical")


def _has_table(bind, name: str) -> bool:
    insp = sa.inspect(bind)
    return name in insp.get_table_names()


def _has_column(bind, table: str, column: str) -> bool:
    insp = sa.inspect(bind)
    if table not in insp.get_table_names():
        return False
    return column in {c["name"] for c in insp.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # ------------------------------------------------------------------
    # Enums — Postgres uses real enum types; SQLite uses CHECK constraints
    # via SQLAlchemy's native_enum=False fallback. We declare them
    # idempotently so re-runs don't trip the "already exists" error.
    # ------------------------------------------------------------------
    if dialect == "postgresql":
        op.execute(
            "DO $$ BEGIN "
            "CREATE TYPE orgrole AS ENUM " + str(_ORG_ROLE_VALUES) + "; "
            "EXCEPTION WHEN duplicate_object THEN null; "
            "END $$;"
        )
        op.execute(
            "DO $$ BEGIN "
            "CREATE TYPE driftseverity AS ENUM "
            + str(_DRIFT_SEVERITY_VALUES) + "; "
            "EXCEPTION WHEN duplicate_object THEN null; "
            "END $$;"
        )
        org_role_type = postgresql.ENUM(
            *_ORG_ROLE_VALUES, name="orgrole", create_type=False,
        )
        drift_severity_type = postgresql.ENUM(
            *_DRIFT_SEVERITY_VALUES, name="driftseverity", create_type=False,
        )
    else:
        org_role_type = sa.Enum(*_ORG_ROLE_VALUES, name="orgrole")
        drift_severity_type = sa.Enum(
            *_DRIFT_SEVERITY_VALUES, name="driftseverity",
        )

    # ------------------------------------------------------------------
    # orgs
    # ------------------------------------------------------------------
    if not _has_table(bind, "orgs"):
        # plantier was already created by an earlier migration (users
        # table). Reuse it via the dialect-specific reference with
        # create_type=False so this migration doesn't fail with
        # DuplicateObjectError on environments that already have it.
        # SQLite tests round-trip the same way via the generic Enum.
        if dialect == "postgresql":
            plan_tier_type = postgresql.ENUM(
                "free", "starter", "pro", "business", "enterprise",
                name="plantier", create_type=False,
            )
        else:
            plan_tier_type = sa.Enum(
                "free", "starter", "pro", "business", "enterprise",
                name="plantier",
            )
        op.create_table(
            "orgs",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column("slug", sa.String(63), nullable=False),
            sa.Column("name", sa.String(255), nullable=False),
            sa.Column("billing_email", sa.String(255)),
            sa.Column(
                "plan_tier", plan_tier_type,
                nullable=False, server_default="free",
            ),
            sa.Column(
                "is_active", sa.Boolean(), nullable=False, server_default=sa.true(),
            ),
            sa.Column(
                "created_at", sa.DateTime(timezone=True), nullable=False,
                server_default=sa.func.now(),
            ),
            sa.Column(
                "updated_at", sa.DateTime(timezone=True), nullable=False,
                server_default=sa.func.now(),
            ),
            sa.UniqueConstraint("slug", name="uq_orgs_slug"),
        )
        op.create_index("ix_orgs_is_active", "orgs", ["is_active"])

    # ------------------------------------------------------------------
    # org_memberships
    # ------------------------------------------------------------------
    if not _has_table(bind, "org_memberships"):
        op.create_table(
            "org_memberships",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column(
                "org_id", sa.Uuid(as_uuid=True),
                sa.ForeignKey("orgs.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "user_id", sa.Uuid(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("role", org_role_type, nullable=False,
                      server_default="viewer"),
            sa.Column(
                "invited_by_user_id", sa.Uuid(as_uuid=True),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
            ),
            sa.Column("accepted_at", sa.DateTime(timezone=True)),
            sa.Column(
                "created_at", sa.DateTime(timezone=True), nullable=False,
                server_default=sa.func.now(),
            ),
            sa.UniqueConstraint(
                "org_id", "user_id", name="uq_org_memberships_org_user",
            ),
        )
        op.create_index("ix_org_memberships_org_id",
                        "org_memberships", ["org_id"])
        op.create_index("ix_org_memberships_user_id",
                        "org_memberships", ["user_id"])
        op.create_index("ix_org_memberships_role",
                        "org_memberships", ["role"])

    # ------------------------------------------------------------------
    # scan_deltas
    # ------------------------------------------------------------------
    if not _has_table(bind, "scan_deltas"):
        json_col = (postgresql.JSONB() if dialect == "postgresql"
                    else sa.JSON())
        op.create_table(
            "scan_deltas",
            sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
            sa.Column(
                "org_id", sa.Uuid(as_uuid=True),
                sa.ForeignKey("orgs.id", ondelete="CASCADE"),
            ),
            sa.Column(
                "website_id", sa.Uuid(as_uuid=True),
                sa.ForeignKey("websites.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "current_scan_job_id", sa.Uuid(as_uuid=True),
                sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"),
                nullable=False, unique=True,
            ),
            sa.Column(
                "previous_scan_job_id", sa.Uuid(as_uuid=True),
                sa.ForeignKey("scan_jobs.id", ondelete="SET NULL"),
            ),
            sa.Column("new_domains", json_col, nullable=False,
                      server_default=sa.text("'[]'")),
            sa.Column("removed_domains", json_col, nullable=False,
                      server_default=sa.text("'[]'")),
            sa.Column("changed_headers", json_col, nullable=False,
                      server_default=sa.text("'[]'")),
            sa.Column("changed_tls", json_col, nullable=False,
                      server_default=sa.text("'{}'")),
            sa.Column("new_technologies", json_col, nullable=False,
                      server_default=sa.text("'[]'")),
            sa.Column("removed_technologies", json_col, nullable=False,
                      server_default=sa.text("'[]'")),
            sa.Column("new_forms", json_col, nullable=False,
                      server_default=sa.text("'[]'")),
            sa.Column("new_apis", json_col, nullable=False,
                      server_default=sa.text("'[]'")),
            sa.Column("new_third_party_dependencies", json_col,
                      nullable=False, server_default=sa.text("'[]'")),
            sa.Column("new_findings_summary", json_col, nullable=False,
                      server_default=sa.text("'{}'")),
            sa.Column("drift_severity", drift_severity_type,
                      nullable=False, server_default="none"),
            sa.Column("drift_summary", sa.Text()),
            sa.Column("risk_score_delta", sa.Integer()),
            sa.Column("created_at", sa.DateTime(timezone=True),
                      nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_scan_deltas_website_created", "scan_deltas",
                        ["website_id", "created_at"])
        op.create_index("ix_scan_deltas_drift_severity", "scan_deltas",
                        ["drift_severity"])
        op.create_index("ix_scan_deltas_org_id", "scan_deltas", ["org_id"])

    # ------------------------------------------------------------------
    # org_id columns on existing tenant-scoped tables. All NULLABLE.
    # ------------------------------------------------------------------
    _add_org_id_if_missing(bind, "websites")
    _add_org_id_if_missing(bind, "scan_jobs")
    _add_org_id_if_missing(bind, "incidents")
    _add_org_id_if_missing(bind, "alerts")
    _add_org_id_if_missing(bind, "scan_schedules")


def _add_org_id_if_missing(bind, table: str) -> None:
    """Add a nullable ``org_id UUID`` FK + index on ``table`` if absent."""
    if not _has_table(bind, table):
        return
    if _has_column(bind, table, "org_id"):
        return
    op.add_column(
        table,
        sa.Column(
            "org_id", sa.Uuid(as_uuid=True),
            sa.ForeignKey("orgs.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(f"ix_{table}_org_id", table, ["org_id"])


def downgrade() -> None:
    """Reverse the additive migration. Safe because nothing is yet
    enforcing ``org_id`` non-null and no production code path requires
    these tables to exist (org tenancy is dormant until a follow-up
    migration backfills + cuts over)."""
    bind = op.get_bind()
    for table in ("scan_schedules", "alerts", "incidents", "scan_jobs", "websites"):
        if _has_column(bind, table, "org_id"):
            try:
                op.drop_index(f"ix_{table}_org_id", table_name=table)
            except Exception:  # noqa: BLE001
                pass
            op.drop_column(table, "org_id")

    if _has_table(bind, "scan_deltas"):
        for ix in ("ix_scan_deltas_org_id", "ix_scan_deltas_drift_severity",
                   "ix_scan_deltas_website_created"):
            try:
                op.drop_index(ix, table_name="scan_deltas")
            except Exception:  # noqa: BLE001
                pass
        op.drop_table("scan_deltas")

    if _has_table(bind, "org_memberships"):
        for ix in ("ix_org_memberships_role", "ix_org_memberships_user_id",
                   "ix_org_memberships_org_id"):
            try:
                op.drop_index(ix, table_name="org_memberships")
            except Exception:  # noqa: BLE001
                pass
        op.drop_table("org_memberships")

    if _has_table(bind, "orgs"):
        try:
            op.drop_index("ix_orgs_is_active", table_name="orgs")
        except Exception:  # noqa: BLE001
            pass
        op.drop_table("orgs")

    if bind.dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS driftseverity")
        op.execute("DROP TYPE IF EXISTS orgrole")
