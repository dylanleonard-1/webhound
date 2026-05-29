"""backfill org_id on websites / scan_jobs / scan_schedules

Revision ID: 0028
Revises: 0027
Create Date: 2026-05-29

Phase-4 slice 3 (backfill half).

Operations performed, all Postgres-only + all idempotent:

  1. CREATE a personal org for every user that doesn't already have one.
     The slug is deterministic from the user UUID
     (`personal-<uuid-no-dashes>`) so re-running this migration is a
     no-op rather than creating duplicate orgs.

  2. ATTACH each user to their personal org as :class:`OrgRole.OWNER`
     with ``accepted_at=now()`` so they immediately satisfy
     ``check_ownership(min_role=OWNER)``.

  3. BACKFILL ``websites.org_id`` to the owner's personal-org id, but
     only for rows where ``user_id IS NOT NULL`` (admin-imported
     unowned websites stay NULL by design).

  4. BACKFILL ``scan_jobs.org_id`` and ``scan_schedules.org_id`` from
     the joined ``websites.org_id``. Rows whose source website has no
     org_id stay NULL — they continue to be visible under the
     single-tenant-legacy clause of ``tenant.org_scope_filter``.

The migration logs verification counts via ``RAISE NOTICE`` so an
operator running ``alembic upgrade head`` sees how many rows landed in
each table.

THE NOT NULL FLIP IS DELIBERATELY HELD OUT of this migration.

Reasoning: a botched NOT NULL constraint causes *every subsequent
INSERT* to fail until reverted, while a botched backfill just leaves
some rows with unexpected org_id. Different blast radius, different
risk tolerance. The NOT NULL cutover gets its own follow-up migration
(0029) once an operator has verified production data with the
post-backfill counters this one emits.

SQLite is skipped via dialect guard — tests use ``Base.metadata
.create_all`` and don't apply this migration. If a future test ever
runs the migration on SQLite, the dialect guard makes it a no-op
rather than an error.

Down-migration nulls out the backfilled org_id on websites + scan_jobs
+ scan_schedules. Personal orgs and memberships are LEFT IN PLACE —
deleting an org with related rows risks ON-DELETE cascade surprises;
operators can clean those up out-of-band if needed.
"""
from __future__ import annotations

from typing import Union

from alembic import op

revision: str = "0028"
down_revision: Union[str, None] = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return   # SQLite tests use create_all; nothing to backfill.

    # ------------------------------------------------------------------
    # 1. Personal-org creation. Idempotent via slug uniqueness.
    # ------------------------------------------------------------------
    op.execute("""
        INSERT INTO orgs (id, slug, name, plan_tier, is_active,
                          created_at, updated_at)
        SELECT
            gen_random_uuid(),
            'personal-' || replace(u.id::text, '-', ''),
            COALESCE(NULLIF(u.email, ''), 'Personal') || '''s Workspace',
            COALESCE(u.plan, 'free')::text::plantier,
            true,
            now(),
            now()
        FROM users u
        WHERE NOT EXISTS (
            SELECT 1 FROM orgs o
            WHERE o.slug = 'personal-' || replace(u.id::text, '-', '')
        );
    """)

    # ------------------------------------------------------------------
    # 2. Owner membership. Idempotent via UNIQUE(org_id, user_id).
    # ------------------------------------------------------------------
    op.execute("""
        INSERT INTO org_memberships (id, org_id, user_id, role,
                                     accepted_at, created_at, updated_at)
        SELECT
            gen_random_uuid(), o.id, u.id, 'owner', now(), now(), now()
        FROM users u
        JOIN orgs o ON o.slug = 'personal-' || replace(u.id::text, '-', '')
        WHERE NOT EXISTS (
            SELECT 1 FROM org_memberships m
            WHERE m.org_id = o.id AND m.user_id = u.id
        );
    """)

    # ------------------------------------------------------------------
    # 3. Websites — backfill org_id from the user's personal org. Only
    #    touches rows where user_id IS NOT NULL AND org_id IS NULL, so
    #    re-runs are safe and admin-imported unowned websites stay NULL.
    # ------------------------------------------------------------------
    op.execute("""
        UPDATE websites w
        SET org_id = (
            SELECT o.id FROM orgs o
            WHERE o.slug = 'personal-' || replace(w.user_id::text, '-', '')
            LIMIT 1
        )
        WHERE w.org_id IS NULL AND w.user_id IS NOT NULL;
    """)

    # ------------------------------------------------------------------
    # 4. scan_jobs + scan_schedules — denormalise from websites.org_id.
    # ------------------------------------------------------------------
    op.execute("""
        UPDATE scan_jobs j
        SET org_id = w.org_id
        FROM websites w
        WHERE j.website_id = w.id
          AND j.org_id IS NULL
          AND w.org_id IS NOT NULL;
    """)
    op.execute("""
        UPDATE scan_schedules s
        SET org_id = w.org_id
        FROM websites w
        WHERE s.website_id = w.id
          AND s.org_id IS NULL
          AND w.org_id IS NOT NULL;
    """)

    # ------------------------------------------------------------------
    # 5. Verification logging — operators see exactly what landed.
    # ------------------------------------------------------------------
    op.execute("""
        DO $$
        DECLARE
            n_orgs_after INT;
            n_memberships INT;
            n_websites_backfilled INT;
            n_websites_remaining_null INT;
            n_scan_jobs_backfilled INT;
            n_scan_jobs_remaining_null INT;
            n_schedules_backfilled INT;
        BEGIN
            SELECT count(*) INTO n_orgs_after FROM orgs;
            SELECT count(*) INTO n_memberships FROM org_memberships;
            SELECT count(*) INTO n_websites_backfilled
                FROM websites WHERE org_id IS NOT NULL;
            SELECT count(*) INTO n_websites_remaining_null
                FROM websites WHERE org_id IS NULL;
            SELECT count(*) INTO n_scan_jobs_backfilled
                FROM scan_jobs WHERE org_id IS NOT NULL;
            SELECT count(*) INTO n_scan_jobs_remaining_null
                FROM scan_jobs WHERE org_id IS NULL;
            SELECT count(*) INTO n_schedules_backfilled
                FROM scan_schedules WHERE org_id IS NOT NULL;

            RAISE NOTICE 'Phase-4 backfill complete:';
            RAISE NOTICE '  orgs total: %', n_orgs_after;
            RAISE NOTICE '  org_memberships total: %', n_memberships;
            RAISE NOTICE '  websites scoped: % (still NULL: %)',
                n_websites_backfilled, n_websites_remaining_null;
            RAISE NOTICE '  scan_jobs scoped: % (still NULL: %)',
                n_scan_jobs_backfilled, n_scan_jobs_remaining_null;
            RAISE NOTICE '  scan_schedules scoped: %', n_schedules_backfilled;
            RAISE NOTICE 'Review remaining-NULL counts before applying '
                         'the NOT NULL cutover migration (0029).';
        END $$;
    """)


def downgrade() -> None:
    """Re-NULL the backfilled org_id values. Leaves personal orgs +
    memberships in place — see module docstring for why."""
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute("""
        UPDATE scan_jobs j
        SET org_id = NULL
        FROM websites w
        WHERE j.website_id = w.id
          AND j.org_id IS NOT NULL
          AND w.user_id IS NOT NULL;
    """)
    op.execute("""
        UPDATE scan_schedules s
        SET org_id = NULL
        FROM websites w
        WHERE s.website_id = w.id
          AND s.org_id IS NOT NULL
          AND w.user_id IS NOT NULL;
    """)
    op.execute("""
        UPDATE websites
        SET org_id = NULL
        WHERE org_id IS NOT NULL AND user_id IS NOT NULL;
    """)
