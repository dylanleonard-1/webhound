# WebHound — apps/api/services/tenant.py
# Phase-4 multi-tenancy: query-scoping helpers.
#
# This is the canonical place every list-query service goes through to
# scope rows to the caller's active org. Backwards-compatible by design:
#   * a row with org_id=NULL is treated as single-tenant legacy and is
#     always visible — so the additive migration didn't break anything;
#   * a row with org_id=X is visible only when the caller's active_org_id
#     equals X (or when no active_org_id is supplied — same legacy
#     semantics).
#
# The cutover migration (Phase-4 slice 3) backfills every NULL to a real
# org and flips the column NOT NULL; at that point the NULL branch of
# the filter becomes unreachable but the helper still works without
# code changes.

from __future__ import annotations

import uuid

import sqlalchemy as sa
from sqlalchemy.sql.elements import ColumnElement


def org_scope_filter(
    column: sa.Column | ColumnElement,
    active_org_id: uuid.UUID | None,
) -> ColumnElement | None:
    """Return a WHERE clause that scopes a query to the caller's active org.

    - ``active_org_id is None``: every row is in scope (single-tenant
      legacy). Returns ``None`` so the caller can ``.where(*filters)``
      without adding a redundant TRUE expression.
    - ``active_org_id`` set: scope to legacy NULL rows OR rows belonging
      to the active org. The NULL branch is what makes this safe to
      land before the backfill — rows that don't yet carry an org_id
      remain visible to anyone, exactly as they are today.

    Usage::

        stmt = sa.select(ScanJob)
        scope = org_scope_filter(ScanJob.org_id, active_org_id)
        if scope is not None:
            stmt = stmt.where(scope)
    """
    if active_org_id is None:
        return None
    return sa.or_(column.is_(None), column == active_org_id)


def apply_org_scope(
    stmt: sa.Select,
    column: sa.Column | ColumnElement,
    active_org_id: uuid.UUID | None,
) -> sa.Select:
    """Shortcut: return ``stmt`` with the org scope applied, or unchanged
    when ``active_org_id`` is None. Slightly nicer than the explicit
    if-not-None dance at call sites."""
    scope = org_scope_filter(column, active_org_id)
    if scope is None:
        return stmt
    return stmt.where(scope)
