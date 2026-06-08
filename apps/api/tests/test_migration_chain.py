# WebHound — apps/api/tests/test_migration_chain.py
# FIX 7 — static Alembic migration-chain validator.
#
# Parses revision / down_revision out of every migration file by READING THE
# SOURCE (regex) — it never imports alembic, the app, or opens a DB. That makes
# it safe to reason about the chain without a live database and lets the same
# logic run inside scripts/audit_runtime_config.py.
#
# NOTE: this module imports nothing from apps.api/worker, but it lives under
# apps/api/tests, so the package conftest still loads when pytest collects it.
# In this hardened workspace the API/worker test suite is not executed because
# apps/api/database.py opens a DB engine at import time (hangs offline); CI with
# a real database runs it normally. Verified here via compileall + review.

from __future__ import annotations

import re
from pathlib import Path

import pytest

_VERSIONS_DIR = Path(__file__).resolve().parents[1] / "migrations" / "versions"

_REVISION_RE = re.compile(r'^revision\s*:?.*=\s*["\']([^"\']+)["\']', re.M)
_DOWN_RE = re.compile(
    r'^down_revision\s*:?.*=\s*(?:["\']([^"\']+)["\']|None)', re.M
)


def _parse_migration(path: Path) -> tuple[str, str | None]:
    text = path.read_text(encoding="utf-8")
    rev_m = _REVISION_RE.search(text)
    assert rev_m, f"{path.name}: no `revision = ...` found"
    down_m = _DOWN_RE.search(text)
    assert down_m, f"{path.name}: no `down_revision = ...` found"
    return rev_m.group(1), down_m.group(1)  # group(1) is None for the base


def _load_all() -> dict[str, str | None]:
    files = sorted(p for p in _VERSIONS_DIR.glob("*.py") if p.name[0].isdigit())
    chain: dict[str, str | None] = {}
    for path in files:
        rev, down = _parse_migration(path)
        assert rev not in chain, f"duplicate revision id: {rev}"
        chain[rev] = down
    return chain


def resolve_head(chain: dict[str, str | None]) -> str:
    """Walk the chain and return the single head revision.

    Raises AssertionError on a broken chain (cycle, orphan, multiple roots,
    or multiple heads). Importable by the diagnostic script.
    """
    assert chain, "no migrations found"
    downs = {d for d in chain.values() if d is not None}
    # Heads = revisions nobody points down to.
    heads = [rev for rev in chain if rev not in downs]
    assert len(heads) == 1, f"expected exactly one head, found {sorted(heads)}"
    # Roots = revisions whose down_revision is None.
    roots = [rev for rev, down in chain.items() if down is None]
    assert len(roots) == 1, f"expected exactly one root, found {sorted(roots)}"
    # Walk head -> root, ensuring every link resolves and the length matches
    # the node count (no cycles, no orphan branches).
    seen: list[str] = []
    cur: str | None = heads[0]
    while cur is not None:
        assert cur in chain, f"dangling down_revision: {cur!r}"
        assert cur not in seen, f"cycle detected at {cur!r}"
        seen.append(cur)
        cur = chain[cur]
    assert len(seen) == len(chain), (
        f"chain has {len(seen)} reachable nodes but {len(chain)} files exist "
        f"— there is a detached branch"
    )
    return heads[0]


def test_single_linear_chain_to_head() -> None:
    chain = _load_all()
    head = resolve_head(chain)
    # Head is the lexicographically-greatest numeric id given the 00NN scheme.
    assert head == max(chain), f"head {head!r} is not the max revision {max(chain)!r}"


def test_no_duplicate_or_missing_links() -> None:
    chain = _load_all()
    for rev, down in chain.items():
        if down is not None:
            assert down in chain, f"{rev} -> {down} but {down} has no file"


def test_chain_has_expected_minimum_length() -> None:
    # Guards against accidental wipe of the versions dir in a refactor.
    chain = _load_all()
    assert len(chain) >= 33, f"only {len(chain)} migrations — expected >= 33"


def test_portfolio_migration_0032_linked() -> None:
    # FIX 7 — the Phase-16 portfolio migration must exist and descend from
    # 0031, and the head must be reachable past it (>= 0032).
    chain = _load_all()
    assert "0032" in chain, "portfolio migration 0032 (website_groups) is missing"
    assert chain["0032"] == "0031", "0032 must descend from 0031"
    assert resolve_head(chain) >= "0032", "head is below the portfolio migration"


if __name__ == "__main__":  # pragma: no cover — manual static check
    c = _load_all()
    print(f"migrations={len(c)} head={resolve_head(c)}")
    raise SystemExit(pytest.main([__file__, "-q", "--noconftest"]))
