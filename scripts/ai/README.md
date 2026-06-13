# `scripts/ai/` — AI Knowledge Layer helper scripts

Read-only, non-destructive helpers for the AI Knowledge Layer (Phase 1, MCP
foundation). **Neither script installs anything, modifies `.mcp.json`, reads
`.env` values, or prints secrets.**

## Scripts

### `check_mcp_prereqs.sh`
Reports environment readiness for the candidate MCPs: presence/versions of
`node`, `npm`, `npx`, `python`, `git`, `docker`, the `claude` CLI (if any), and
Playwright (if installed); the current repo path and OS; and the presence of
`.mcp.json`, `scripts/_gen_env_example.py`, and `docs/env.md`. Pure inspection —
no installs, no changes.

```
bash scripts/ai/check_mcp_prereqs.sh
```

### `mcp_smoke_tests.sh`
Prints the **planned**, safe smoke checks per MCP (see
`docs/ai/mcp/MCP_SMOKE_TESTS.md`). It **skips** any MCP whose key/tool is missing
(GitHub if `GITHUB_TOKEN` unset; Firecrawl/Perplexity if their keys unset;
Playwright if not installed), never prints token values, never reads `.env`, and
warns that **`.mcp.json` is not modified** by this phase. In Phase 1 it does not
execute live MCP calls.

```
bash scripts/ai/mcp_smoke_tests.sh
```

## Guarantees
- No network installs, no MCP server installs, no `.mcp.json` edits.
- No reading or printing of secrets / `.env` values.
- Exit 0 with a summary even when tools/keys are absent (skips are expected in
  Phase 1).

Cross-platform note: these are POSIX-ish `bash` scripts. They run under Git Bash
on Windows and under WSL/Linux. They detect-and-report rather than require any
specific tool.
