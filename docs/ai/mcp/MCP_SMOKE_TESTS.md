# MCP Smoke Tests

Safe, non-destructive checks to confirm an MCP works **once it has been approved
and enabled**. In Phase 1 these are **described, not executed against real keys**;
the companion script `scripts/ai/mcp_smoke_tests.sh` only **prints what it would
test** and skips anything that needs a key or an installed browser.

## Ground rules
- **Never** print API-key/token values.
- **Never** read `.env` values.
- **Skip** any check whose key/tool is missing (don't fail, don't auto-install).
- **Read-only / non-destructive** only.
- The smoke script **does not modify `.mcp.json`** and reminds you of that.

## Per-MCP smoke checks

### Filesystem
- **Check:** list an in-repo path (e.g. `docs/ai/`) and read one known file.
- **Pass:** path lists and file reads back.
- **Must not:** access any path outside the repo; write anything.

### GitHub (skipped if `GITHUB_TOKEN` unset)
- **Check:** a read-only call — repo metadata or "list 1–3 recent commits".
- **Pass:** returns data without write side effects.
- **Must not:** create/modify/delete anything; print the token.

### Playwright (skipped if Playwright/browsers not installed)
- **Check:** launch headless browser → open `https://webhoundsecurity.com`
  (public) or a detected local dev URL → capture **title + HTTP status** →
  optional **one** screenshot only if the page is known-safe.
- **Pass:** title/status captured.
- **Must not:** open customer sites; use real customer accounts; persist
  unsanitized traces.

### Firecrawl (skipped if `FIRECRAWL_API_KEY` unset)
- **Check:** fetch one public, ToS-permitted official-doc URL.
- **Pass:** clean text returned with a recorded source URL.
- **Must not:** crawl private/authed/customer sites; ignore robots/ToS.

### Perplexity (skipped if `PERPLEXITY_API_KEY` unset)
- **Check:** one benign research query.
- **Pass:** answer returns **with source URLs**.
- **Must not:** treat the answer as canonical/operational truth.

## How to run the describer (Phase 1)
```
bash scripts/ai/check_mcp_prereqs.sh     # environment readiness (read-only)
bash scripts/ai/mcp_smoke_tests.sh       # prints planned checks; skips missing keys/tools
```
Both scripts are read-only, never print secrets, and do not change `.mcp.json`.

## Interpreting results
- A **skip** is expected in Phase 1 (no keys, Playwright not installed) — it is
  not a failure.
- A real **pass** is only meaningful **after** the relevant MCP has been approved
  and enabled (a separate step — see `MCP_MANUAL_APPROVALS.md`).
