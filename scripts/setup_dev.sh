#!/usr/bin/env bash
# WebHound — development environment setup
#
# Usage: ./scripts/setup_dev.sh [--no-e2e] [--frontend] [--pull] [--demo]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RUN_E2E=true
START_FRONTEND=false
PULL_IMAGES=false
SEED_DEMO=false

for arg in "$@"; do
  case $arg in
    --no-e2e)   RUN_E2E=false ;;
    --frontend) START_FRONTEND=true ;;
    --pull)     PULL_IMAGES=true ;;
    --demo)     SEED_DEMO=true ;;
  esac
done

check_cmd() {
  if ! command -v "$1" &>/dev/null; then
    echo "✗ Required: $1 is not installed" >&2; exit 1
  fi
}

check_cmd docker
check_cmd python3

echo "==================================================================="
echo " WebHound — dev stack startup"
echo "==================================================================="

$PULL_IMAGES && docker compose pull postgres redis 2>/dev/null || true

echo "Building containers…"
docker compose build --quiet

echo "Starting services…"
docker compose up -d

echo "Waiting for services to become healthy…"
DEADLINE=$((SECONDS + 120))

wait_healthy() {
  local svc="$1"
  echo -n "  $svc "
  while [ $SECONDS -lt $DEADLINE ]; do
    health=$(docker inspect --format='{{.State.Health.Status}}' \
      "$(docker compose ps -q "$svc" 2>/dev/null)" 2>/dev/null || echo "none")
    [ "$health" = "healthy" ] && { echo "✓"; return 0; }
    echo -n "."; sleep 3
  done
  echo " ✗ timed out"; docker compose logs --tail=30 "$svc"; return 1
}

wait_healthy postgres
wait_healthy redis
wait_healthy api

echo ""
docker compose ps

if $START_FRONTEND; then
  if command -v node &>/dev/null; then
    echo ""
    echo "Starting Next.js dev server on http://localhost:3000 …"
    cd apps/web
    [ ! -d node_modules ] && npm ci --silent
    NEXT_PUBLIC_API_URL=http://localhost:8000 npm run dev &
    cd "$REPO_ROOT"
  else
    echo "⚠  node not found — skipping frontend"
  fi
fi

if $RUN_E2E; then
  echo ""; echo "Running E2E smoke test…"; sleep 5
  python3 scripts/backend_e2e_check.py || echo "⚠  E2E reported failures — check above."
fi

if $SEED_DEMO; then
  echo ""; echo "Seeding demo data…"
  python3 scripts/seed_demo.py || echo "⚠  Demo seed reported failures — check above."
fi

echo ""
echo "==================================================================="
echo " Stack is running"
echo ""
echo "  API      →  http://localhost:8000"
echo "  Docs     →  http://localhost:8000/docs"
echo "  Frontend →  http://localhost:3000   (run with --frontend)"
echo "  Postgres →  localhost:5432          (webhound/webhound)"
echo "  Redis    →  localhost:6379"
echo ""
echo "  Stop:  docker compose down"
echo "  Logs:  docker compose logs -f api"
echo "  E2E:   python3 scripts/backend_e2e_check.py"
echo "  Demo:  python3 scripts/seed_demo.py"
echo "  Guide: docs/first-run.md"
echo "==================================================================="
