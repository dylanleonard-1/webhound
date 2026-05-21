#!/usr/bin/env bash
# WebHound — development stack startup (alias for setup_dev.sh)
#
# Usage:
#   ./scripts/start_dev.sh              # build + start + E2E check
#   ./scripts/start_dev.sh --no-e2e    # skip E2E smoke test
#   ./scripts/start_dev.sh --frontend  # also start Next.js dev server
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$REPO_ROOT/scripts/setup_dev.sh" "$@"
