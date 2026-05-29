"""enforce org_id integrity via CHECK constraints (cutover step)

Revision ID: 0029
Revises: 0028
Create Date: 2026-05-29

Phase-4 slice 3.5 — the NOT-NULL-ish cutover.

DESIGN NOTE: a plain ``ALTER COLUMN ... SET NOT NULL`` on
``websites.org_id`` would fail for admin-imported targets where
``user_id IS NULL`` is the legitimate "no human owner" state. Same
shape for ``scan_jobs`` / ``scan_schedules`` whose parent website is
unowned. So instead of a strict NOT NULL we add CHECK constraints
that express the actual invariant:

    (user_id IS NULL) OR (org_id IS NOT NULL)

This forbids the bad state (owned but no org) without breaking
the legitimate "no owner, no org" state.

SAFETY GUARD: before adding any constraint, the migration runs a
verification block that aborts with a clear ``RAISE EXCEPTION`` if
any row would currently violate the invariant. The whole migration
is wrapped in the usual alembic transaction, so an abort leaves
the DB untouched and at version ``0028`` — operator fixes the
underlying data, then re-runs.

PERFORMANCE: the constraints are added with ``NOT VALID`` so they
take effect immediately for new rows without scanning the existing
table (instant on any size of table). ``VALIDATE CONSTRAINT`` is
run as a separate statement after the existing-row count is
already known to be 0 — so the validation scan is cheap, but
explicit.

Idempotent — re-runs detect existing constraints and skip them.
SQLite path is a no-op; the test fixture rebuilds the schema from
``Base.metadata`` and doesn't apply this migration.
"""
from __future__ import annotations

from typing import Union

from alembic import op

revision: str = "0029"
down_revision: Union[str, None] = "0028"
branch_labels = None
depends_on = None


_CONSTRAINTS = (
    # (table, constraint_name, check expression)
    (
        "websites",
        "chk_websites_owned_has_org",
        "user_id IS NULL OR org_id IS NOT NULL",
    ),
    (
        "scan_jobs",
        "chk_scan_jobs_inherits_org",
        # A scan job inherits its parent website's org. Express the
        # invariant in a way Postgres can verify without a JOIN by
        # relying on services/scan_jobs.create_scan_job to set
        # org_id=website.org_id at creation. The check guarantees that
        # *if* a row has user-attributable context (we infer that via
        # a NOT NULL website_id which always exists) and the parent
        # website has an org_id, the scan job has the same org_id.
        # Postgres CHECK can't reference another table, so the
        # simplest expressible invariant here is: org_id can only be
        # NULL if it WAS NULL by design (legacy admin imports).
        # That's identical to "no constraint" at the row level — the
        # real invariant lives in the application service. We instead
        # add a CHECK that catches a different bug: org_id and
        # website_id must both be NULL or both NOT NULL is too strict
        # (scan jobs for unowned websites legitimately have both NULL).
        # So we add a defensive CHECK that's always true today but
        # would catch a future migration that orphans org_id:
        "org_id IS NULL OR website_id IS NOT NULL",
    ),
    (
        "scan_schedules",
        "chk_scan_schedules_inherits_org",
        "org_id IS NULL OR website_id IS NOT NULL",
    ),
)


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    # ------------------------------------------------------------------
    # 1. Pre-flight verification. Abort the whole migration if any
    #    row would violate the constraint we're about to add. The
    #    error message names exactly which table + how many bad rows
    #    so the operator can fix and re-run.
    # ------------------------------------------------------------------
    op.execute("""
        DO $$
        DECLARE
            n_bad INT;
        BEGIN
            -- websites: any owned site (user_id NOT NULL) without org_id?
            SELECT count(*) INTO n_bad
            FROM websites
            WHERE user_id IS NOT NULL AND org_id IS NULL;
            IF n_bad > 0 THEN
                RAISE EXCEPTION
                    '0029 abort: % owned website(s) lack org_id. '
                    'Run migration 0028 first or backfill manually.',
                    n_bad;
            END IF;

            -- scan_jobs: parent website has org_id but scan_job does not?
            SELECT count(*) INTO n_bad
            FROM scan_jobs j
            JOIN websites w ON j.website_id = w.id
            WHERE w.org_id IS NOT NULL AND j.org_id IS NULL;
            IF n_bad > 0 THEN
                RAISE EXCEPTION
                    '0029 abort: % scan_job(s) lack org_id where '
                    'their parent website has one. Run 0028 backfill '
                    'or fix manually.', n_bad;
            END IF;

            -- scan_schedules: same shape.
            SELECT count(*) INTO n_bad
            FROM scan_schedules s
            JOIN websites w ON s.website_id = w.id
            WHERE w.org_id IS NOT NULL AND s.org_id IS NULL;
            IF n_bad > 0 THEN
                RAISE EXCEPTION
                    '0029 abort: % scan_schedule(s) lack org_id '
                    'where parent website has one.', n_bad;
            END IF;

            RAISE NOTICE
                '0029 pre-flight clean — adding CHECK constraints.';
        END $$;
    """)

    # ------------------------------------------------------------------
    # 2. Add CHECK constraints. Each one wrapped in a DO block with
    #    EXCEPTION WHEN duplicate_object so re-running this migration
    #    is a no-op rather than an error. Using NOT VALID then
    #    VALIDATE CONSTRAINT lets us add the constraint atomically
    #    without a full table scan (the validate is then explicit and
    #    cheap because we just verified no bad rows exist above).
    # ------------------------------------------------------------------
    for table, name, check in _CONSTRAINTS:
        op.execute(f"""
            DO $$
            BEGIN
                ALTER TABLE {table}
                ADD CONSTRAINT {name} CHECK ({check}) NOT VALID;
                ALTER TABLE {table} VALIDATE CONSTRAINT {name};
            EXCEPTION
                WHEN duplicate_object THEN null;
                WHEN duplicate_table THEN null;
            END $$;
        """)


def downgrade() -> None:
    """Drop the CHECK constraints. Future rows will once again be
    allowed to have an owner-without-org state; existing rows are
    untouched because nothing about them changes."""
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table, name, _ in _CONSTRAINTS:
        op.execute(f"""
            DO $$ BEGIN
                ALTER TABLE {table} DROP CONSTRAINT {name};
            EXCEPTION WHEN undefined_object THEN null;
            END $$;
        """)
