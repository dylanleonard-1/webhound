#!/usr/bin/env bash
# WebHound AI Knowledge Layer — MCP smoke-test describer (Phase 1).
#
# SAFE / NON-DESTRUCTIVE. This prints the smoke checks it WOULD run per MCP and
# SKIPS any MCP whose key/tool is missing. It does NOT:
#   * install or connect any MCP server
#   * modify .mcp.json
#   * read .env files or print any secret/token VALUES
#   * make live MCP calls in Phase 1
#
# Usage:  bash scripts/ai/mcp_smoke_tests.sh
set -u

# Key PRESENCE only — we check whether a var is set, never its value.
have_key() { # have_key VAR_NAME
  name="$1"
  # Indirect expansion to test presence without echoing the value.
  if [ -n "${!name:-}" ]; then return 0; else return 1; fi
}

planned=0
skipped=0

plan() { printf '  [plan] %s\n' "$1"; planned=$((planned+1)); }
skip() { printf '  [skip] %s\n' "$1"; skipped=$((skipped+1)); }

echo "WebHound MCP smoke-test plan (Phase 1 — describe only)"
echo "No MCP servers are installed/connected; no live calls are made."
echo

echo "Filesystem MCP:"
plan "list an in-repo path (docs/ai/) and read one known file — read-only, in-repo"

echo
echo "GitHub MCP:"
if have_key GITHUB_TOKEN; then
  plan "read-only: fetch repo metadata / list 1-3 recent commits (token present; value never printed)"
else
  skip "GITHUB_TOKEN not set — GitHub smoke test skipped"
fi

echo
echo "Playwright MCP:"
if command -v npx >/dev/null 2>&1 && npx --no-install playwright --version >/dev/null 2>&1; then
  plan "launch headless browser -> open https://webhoundsecurity.com -> capture title + HTTP status (optional 1 safe screenshot)"
else
  skip "Playwright not installed — browser smoke test skipped (no auto-install)"
fi

echo
echo "Firecrawl MCP:"
if have_key FIRECRAWL_API_KEY; then
  plan "fetch ONE public, ToS-permitted official-doc URL; record provenance"
else
  skip "FIRECRAWL_API_KEY not set — Firecrawl smoke test skipped"
fi

echo
echo "Perplexity MCP:"
if have_key PERPLEXITY_API_KEY; then
  plan "one benign research query; require source URLs in the answer"
else
  skip "PERPLEXITY_API_KEY not set — Perplexity smoke test skipped"
fi

echo
echo "Summary: ${planned} planned, ${skipped} skipped."
echo "Reminder: .mcp.json was NOT modified. No secrets were read or printed."
echo "Skips are expected in Phase 1. Real smoke tests run only after an MCP is"
echo "approved and enabled (see docs/ai/mcp/MCP_MANUAL_APPROVALS.md)."
exit 0
