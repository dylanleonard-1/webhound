# Database migrations runbook

Alembic migrations live in `apps/api/migrations/versions/` as a single linear
chain. This runbook covers how to apply them on Railway and how to confirm the
database is at head. (FIX 7)

## Chain status (static confirmation)

The chain is a single unbranched line from the initial schema to the current
head. Confirmed statically by reading `revision` / `down_revision` from every
file (no DB, no app import — see `apps/api/tests/test_migration_chain.py` and
`scripts/audit_runtime_config.py`):

```
0001 (root, down_revision=None)
  -> 0002 -> 0003 -> ... -> 0031 -> 0032 (website_groups) -> 0033 (notification email delivery)
HEAD = 0033
```

- Exactly **one root** (`0001`, `down_revision = None`).
- Exactly **one head** (`0033`; nobody declares it as their `down_revision`).
- **No duplicate** revision ids, **no cycles**, **no detached branches** — the
  reachable-node count equals the file count.

> The portfolio table `website_groups` (migration `0032`) and its
> `websites.group_id` FK are part of this chain. The ORM `WebsiteGroup` model
> matches `0032`'s columns (`id, org_id, name, group_type, parent_group_id,
> updated_at`). Applying through head brings the portfolio schema online.

## Apply on Railway

Run the upgrade against the Railway service that owns `DATABASE_URL` (the API
service). Either of these works:

```bash
# From a shell attached to the Railway API service:
alembic upgrade head

# Or from a local machine with the Railway CLI (injects the service env):
railway run alembic upgrade head
```

`alembic.ini` lives at `apps/api/alembic.ini`; run from `apps/api/` (or pass
`-c apps/api/alembic.ini`). `scripts/run_migrations.sh` wraps this for CI/Docker.

Migrations are **idempotent** (every `upgrade()` guards with
column-/table-exists checks) and **reversible** (`downgrade()` is defined), so a
re-run on an already-migrated database is a no-op rather than an error.

## Readiness check (confirm at head)

After upgrading, confirm the database revision matches the code head:

```bash
alembic current          # prints the DB's current revision, e.g. "0033 (head)"
alembic heads            # prints the code head, e.g. "0033"
```

Ready when `alembic current` shows the same revision as `alembic heads` (and is
annotated `(head)`). If `current` is behind `heads`, run `alembic upgrade head`
again; if `current` is empty, the migrations have never been applied to that
database.

A static (no-DB) read of the code head is also available without alembic:

```bash
python scripts/audit_runtime_config.py     # prints "migration head (static): 0033"
```

## Notes

- The API opens its DB engine at import time, so `alembic` and any app-importing
  command must run with `DATABASE_URL` reachable. In an offline workspace these
  commands block — apply migrations only where the database is reachable
  (Railway, CI, or a local Postgres).
- New migrations must continue the chain: set `down_revision` to the prior head
  and keep the `00NN_` filename ordering.
