#!/usr/bin/env bash
# WebHound — standalone scanner wrapper
#
# Runs the Python scanner directly (no API/Celery required).
# Useful for quick local tests and debugging engine output.
#
# Usage:
#   ./scripts/run_scan.sh https://example.com
#   ./scripts/run_scan.sh https://example.com --profile quick
#   ./scripts/run_scan.sh https://example.com --profile deep --format sarif
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [ $# -eq 0 ]; then
  echo "Usage: $0 <target-url> [--profile quick|standard|deep|monitor] [--format json|sarif|csv|markdown]"
  exit 1
fi

TARGET="$1"; shift

# If scanner venv exists, use it; otherwise fall back to system Python
SCANNER_PYTHON="$REPO_ROOT/scanner/venv/bin/python3"
[ -f "$SCANNER_PYTHON" ] || SCANNER_PYTHON="$(command -v python3)"

PYTHONPATH="$REPO_ROOT/scanner" "$SCANNER_PYTHON" "$REPO_ROOT/scanner/run_scan.py" "$TARGET" "$@"
