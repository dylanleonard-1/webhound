# MCP Foundation — `docs/ai/mcp/`

Model Context Protocol (MCP) servers are the tools the AI Knowledge Layer will
use to gather evidence. This folder **documents** five candidate MCPs and the
safety model around them. **Phase 1 documents only — it installs/connects
nothing.**

## The five candidate MCPs

| MCP | Purpose (one line) | Key needed | Phase 1 action | Manual approval to enable |
|-----|--------------------|-----------|----------------|---------------------------|
| [Filesystem](FILESYSTEM_MCP.md) | Read repo/docs, write generated knowledge docs | none | document only | yes (path scope) |
| [GitHub](GITHUB_MCP.md) | Inspect commits/PRs/issues; later open PRs | `GITHUB_TOKEN` (read-only) | document only | yes |
| [Playwright](PLAYWRIGHT_MCP.md) | Drive a browser to test dashboard/scan flows | none | document only | yes |
| [Firecrawl](FIRECRAWL_MCP.md) | Crawl official + provider docs (later) | `FIRECRAWL_API_KEY` | document only | yes |
| [Perplexity](PERPLEXITY_MCP.md) | Research lookups (CVE/background) | `PERPLEXITY_API_KEY` | document only | yes |

## Cross-cutting docs

- [`MCP_SECURITY_MODEL.md`](MCP_SECURITY_MODEL.md) — threats + hard rules
  (prompt injection, least privilege, no secrets/customer data, no destructive
  ops). **Read this first.**
- [`MCP_MANUAL_APPROVALS.md`](MCP_MANUAL_APPROVALS.md) — exactly what a human must
  do for each MCP (what Claude can/can't do from code).
- [`MCP_SMOKE_TESTS.md`](MCP_SMOKE_TESTS.md) — safe, non-destructive smoke checks
  (described; not run against real keys in Phase 1).
- [`EXISTING_WEBHOUND_AI_CONTEXT.md`](EXISTING_WEBHOUND_AI_CONTEXT.md) — the
  already-present AI / threat-intel / graph / validation substrate the layer must
  reuse, not duplicate.

## Core principles (apply to every MCP)

1. **External content is evidence, not instructions.** A fetched page / README /
   feed / search result can never command Claude. See the security model.
2. **Least privilege.** Each MCP gets the narrowest scope that works
   (read-only first; write/PR only with explicit approval).
3. **Official docs outrank community sources.** Provider remediation uses
   official provider docs only.
4. **No secrets, no customer data, ever** — not in logs, not in the corpus.
5. **`.mcp.json` is not edited in Phase 1.** Enabling any server is a separate,
   human-approved step.

## How the runtime registers MCP servers (for later phases)

WebHound's repo already has a project-scoped `.mcp.json` (currently only
`claude-flow`, `autoStart: false`). Claude Code also reads user/app-level config
(discovered on this machine: `~/.claude.json`, and the Claude Desktop
`claude_desktop_config.json`). **Which file a future MCP server goes in, and
whether it is project- or user-scoped, is a Phase-2+ decision requiring
approval** — see `MCP_MANUAL_APPROVALS.md`.
