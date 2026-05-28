"""immutable admin audit log — Postgres trigger that rejects UPDATE/DELETE

Revision ID: 0026
Revises: 0025
Create Date: 2026-05-28

Phase 12 — Security & Operations: enforce the "append-only by convention"
guarantee at the database level. A trigger raises an exception on any UPDATE
or DELETE against admin_audit_logs so a compromised app server or stray
migration cannot rewrite history. SQLite tests skip the trigger (dialect
guard) — the test fixture is already throwaway in-memory.

Idempotent (safe to re-run).
"""
from __future__ import annotations

from typing import Union

from alembic import op

revision: str = "0026"
down_revision: Union[str, None] = "0025"
branch_labels = None
depends_on = None


_FN_NAME = "admin_audit_log_immutable_fn"
_TRG_NAME = "admin_audit_log_immutable_trg"


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return  # SQLite + others: trigger language differs; convention enforces this.
    op.execute(f"""
    CREATE OR REPLACE FUNCTION {_FN_NAME}()
    RETURNS trigger AS $$
    BEGIN
        RAISE EXCEPTION 'admin_audit_logs is append-only — % is not permitted', TG_OP
            USING ERRCODE = 'feature_not_supported';
    END;
    $$ LANGUAGE plpgsql;
    """)
    # CREATE TRIGGER doesn't support IF NOT EXISTS in older PG; drop-then-create
    # makes the migration idempotent without depending on version.
    op.execute(f"DROP TRIGGER IF EXISTS {_TRG_NAME} ON admin_audit_logs;")
    op.execute(f"""
    CREATE TRIGGER {_TRG_NAME}
    BEFORE UPDATE OR DELETE ON admin_audit_logs
    FOR EACH ROW EXECUTE FUNCTION {_FN_NAME}();
    """)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(f"DROP TRIGGER IF EXISTS {_TRG_NAME} ON admin_audit_logs;")
    op.execute(f"DROP FUNCTION IF EXISTS {_FN_NAME}();")
