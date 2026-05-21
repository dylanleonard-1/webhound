#!/usr/bin/env bash
# WebHound — production stack startup
#
# Prerequisites:
#   1. Copy .env.example to .env.prod and fill in all required values.
#   2. Ensure SECRET_KEY is a strong random value (not the default).
#   3. Set CORS_ORIGINS to your actual frontend URL.
#   4. Set NEXT_PUBLIC_API_URL to your public API address.
#
# Usage:
#   ./scripts/start_prod.sh              # full build + start
#   ./scripts/start_prod.sh --no-build  # skip image rebuild (faster restart)
#   ./scripts/start_prod.sh --down      # stop and remove containers
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ENV_FILE=".env.prod"
COMPOSE_FILE="docker-compose.prod.yml"
BUILD=true
DOWN=false

for arg in "$@"; do
  case $arg in
    --no-build) BUILD=false ;;
    --down)     DOWN=true ;;
  esac
done

if $DOWN; then
  echo "Stopping production stack…"
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" down
  exit 0
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found." >&2
  echo "  Copy .env.example to $ENV_FILE and fill in all required values." >&2
  exit 1
fi

# Validate required variables
check_var() {
  local var="$1"
  local val
  val="$(grep -E "^${var}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- | tr -d '"' || true)"
  # Also check shell environment
  val="${!var:-$val}"
  if [ -z "$val" ]; then
    echo "ERROR: $var is not set in $ENV_FILE" >&2
    exit 1
  fi
}

check_var SECRET_KEY
check_var DATABASE_URL
check_var REDIS_URL
check_var NEXT_PUBLIC_API_URL
check_var CORS_ORIGINS
check_var POSTGRES_PASSWORD

echo "==================================================================="
echo " WebHound — production startup"
echo "==================================================================="

if $BUILD; then
  echo "Building images…"
  docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" build
fi

echo "Starting services…"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d

echo "Waiting for services to become healthy…"
DEADLINE=$((SECONDS + 120))

wait_healthy() {
  local svc="$1"
  echo -n "  $svc "
  while [ $SECONDS -lt $DEADLINE ]; do
    health=$(docker inspect --format='{{.State.Health.Status}}' \
      "$(docker compose -f "$COMPOSE_FILE" ps -q "$svc" 2>/dev/null)" 2>/dev/null || echo "none")
    [ "$health" = "healthy" ] && { echo "✓"; return 0; }
    echo -n "."; sleep 3
  done
  echo " ✗ timed out"
  docker compose -f "$COMPOSE_FILE" logs --tail=30 "$svc"
  return 1
}

wait_healthy postgres
wait_healthy redis
wait_healthy api
wait_healthy worker
wait_healthy web

echo ""
docker compose -f "$COMPOSE_FILE" ps

echo ""
echo "==================================================================="
echo " Production stack is running"
echo ""
echo "  API      →  http://localhost:${API_PORT:-8000}"
echo "  Frontend →  http://localhost:${WEB_PORT:-3000}"
echo ""
echo "  Logs:  docker compose -f $COMPOSE_FILE logs -f api"
echo "  Stop:  ./scripts/start_prod.sh --down"
echo "==================================================================="
