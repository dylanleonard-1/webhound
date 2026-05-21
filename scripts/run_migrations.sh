#!/usr/bin/env bash
# WebHound — Alembic migration runner
#
# Usage:
#   ./scripts/run_migrations.sh                   # upgrade to head
#   ./scripts/run_migrations.sh downgrade -1      # roll back one step
#   ./scripts/run_migrations.sh current           # show current revision
#   ./scripts/run_migrations.sh history           # show migration history
#
# Requires DATABASE_URL in environment or .env file.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Load .env if present and DATABASE_URL not already set
if [ -z "${DATABASE_URL:-}" ] && [ -f ".env" ]; then
  set -a; source .env; set +a
fi

if [ -z "${DATABASE_URL:-}" ]; then
  echo "ERROR: DATABASE_URL is not set." >&2
  echo "  Set it in .env or export it before running this script." >&2
  exit 1
fi

CMD="${1:-upgrade}"
REVISION="${2:-head}"

echo "Alembic $CMD $REVISION"
exec alembic -c apps/api/alembic.ini "$CMD" "$REVISION"
