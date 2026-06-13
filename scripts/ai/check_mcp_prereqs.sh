#!/usr/bin/env bash
# WebHound AI Knowledge Layer — MCP prerequisite checker (Phase 1).
#
# READ-ONLY. Does NOT install anything, modify .mcp.json, read .env values, or
# print secrets. It reports environment readiness for the candidate MCPs.
#
# Usage:  bash scripts/ai/check_mcp_prereqs.sh
set -u

# Resolve repo root from this script's location (scripts/ai/ -> repo root).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

pass=0
warn=0

ok()   { printf '  [ ok ] %s\n' "$1"; pass=$((pass+1)); }
miss() { printf '  [warn] %s\n' "$1"; warn=$((warn+1)); }

ver() { # ver <cmd> <args...>  -> prints first line of version, or marks missing
  cmd="$1"; shift
  if command -v "$cmd" >/dev/null 2>&1; then
    out="$("$cmd" "$@" 2>&1 | head -n 1)"
    ok "$cmd: ${out}"
  else
    miss "$cmd: not found on PATH"
  fi
}

echo "WebHound MCP prerequisite check (read-only)"
echo "Repo root: ${REPO_ROOT}"
echo "OS:        $(uname -s -r 2>/dev/null || echo unknown)  (${OSTYPE:-unknown})"
echo

echo "Toolchain:"
ver node --version
ver npm --version
ver npx --version
ver python --version
ver git --version
ver docker --version

# Claude CLI is optional (may not be on PATH even when Claude Code is installed).
if command -v claude >/dev/null 2>&1; then
  ok "claude CLI: $(claude --version 2>&1 | head -n 1)"
else
  miss "claude CLI: not on PATH (Claude Code may still be installed as an app)"
fi

# Playwright: report only; never auto-install.
if command -v npx >/dev/null 2>&1 && npx --no-install playwright --version >/dev/null 2>&1; then
  ok "playwright: $(npx --no-install playwright --version 2>&1 | head -n 1)"
else
  miss "playwright: not installed (expected in Phase 1; do NOT auto-install)"
fi

echo
echo "Repo files the knowledge layer relies on:"
[ -f "${REPO_ROOT}/.mcp.json" ] && ok ".mcp.json present (NOT modified by this phase)" || miss ".mcp.json absent"
[ -f "${REPO_ROOT}/scripts/_gen_env_example.py" ] && ok "scripts/_gen_env_example.py present (env source of truth)" || miss "scripts/_gen_env_example.py absent"
[ -f "${REPO_ROOT}/docs/env.md" ] && ok "docs/env.md present (env reference)" || miss "docs/env.md absent"
[ -d "${REPO_ROOT}/docs/ai" ] && ok "docs/ai/ present" || miss "docs/ai/ absent"

echo
echo "Summary: ${pass} ok, ${warn} warning(s)."
echo "Note: warnings are expected in Phase 1 (no MCP servers installed/connected)."
echo "This script changed nothing."
exit 0
