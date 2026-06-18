"""Test-harness path setup for the apps/api suite (no app behavior changes).

pytest loads this parent conftest before apps/api/tests/conftest.py, so it runs
before any app import. It makes the two packages the suite needs importable,
without putting `apps/api` itself on sys.path (which would let the first-party
`apps/api/platform/` package shadow the stdlib `platform` module and break
SQLAlchemy). Combined with `import-mode=importlib` in apps/api/pytest.ini, a bare
`pytest apps/api/tests` collects and runs with no manual flags / PYTHONPATH.

Paths added (computed from this file's location, so they are invocation- and
CWD-independent):
  * repo root  -> for `apps.api.*` imports
  * scanner/   -> for `webhound.*` imports (e.g. webhound.identity)

This file ONLY adjusts sys.path for test collection. It imports/changes no
production code.
"""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCANNER = _REPO_ROOT / "scanner"

for _p in (_REPO_ROOT, _SCANNER):
    _s = str(_p)
    if _p.is_dir() and _s not in sys.path:
        sys.path.insert(0, _s)
