# MCP Manual Approvals

What a **human** must do to enable each MCP — and what cannot be completed from
code alone. **Phase 1 completes none of these; it only documents them.** Enabling
any MCP server is a separate, explicitly-approved step (and not part of Phase 1).

## Legend
- **Claude can install via terminal?** — can the npm/npx package be fetched by a
  command (still requires approval to *run* and to *register*).
- **User must approve in app/settings?** — requires a human action in Claude
  Code / Claude Desktop config or an OS/app permission dialog.
- **API key needed?** — and where it is stored.

## Matrix

| MCP | Claude can install via terminal? | User must approve in app/settings? | API key needed? | Key storage | Initial permissions | Do NOT enable yet | Waits until |
|-----|----------------------------------|------------------------------------|-----------------|-------------|--------------------|-------------------|-------------|
| **Filesystem** | Yes (`npx @modelcontextprotocol/server-filesystem`) | **Yes** — register the server + the **single repo-root allowlist** in the chosen MCP config | No | n/a | Read-only over repo | Write outside `docs/ai/`; any out-of-repo path | Phase 2 (write to `corpus/`/`knowledge/`) |
| **GitHub** | Yes (`npx`/container github server) | **Yes** — register server; provide `GITHUB_TOKEN` | **Yes** — fine-grained **read-only** PAT (NOT the OAuth client secret) | Local env / MCP env block; **never** in repo | repo-read (commits/PRs/issues/releases) | Any write scope; force-push; auto-merge; org admin | Later phase for PR/issue write (approval-gated) |
| **Playwright** | Yes (`npx microsoft/playwright-mcp`) + `npx playwright install` for browsers | **Yes** — register server; approve browser install | No | n/a | Isolated profile; WebHound/local URLs | Customer sites; real customer accounts; persisting traces | When UI/flow verification is needed (approved) |
| **Firecrawl** | Yes (`npx firecrawl/firecrawl-mcp-server`) | **Yes** — register server; provide `FIRECRAWL_API_KEY` | **Yes** — `FIRECRAWL_API_KEY` | Local env / MCP env block | Crawl named official/provider/standards URLs only | Private/customer/authed sites; ToS-violating sources | Phase 5 (doc ingestion) |
| **Perplexity** | Yes (`npx` perplexity server) | **Yes** — register server; provide `PERPLEXITY_API_KEY` | **Yes** — `PERPLEXITY_API_KEY` | Local env / MCP env block | Read-only research queries | Treating answers as canonical/operational truth | Phase 5+ (research) |

## Cannot be done from code alone (requires the human)
- **Registering an MCP server** in the active config. On this machine the
  discovered config locations are: the repo's `.mcp.json` (project scope, today
  only `claude-flow`), `~/.claude.json` (Claude Code user scope), and
  `~/AppData/Roaming/Claude/claude_desktop_config.json` (Claude Desktop).
  **Which file, and project- vs user-scope, is a human decision** — Phase 1 does
  not edit any of them.
- **Issuing/rotating API keys** (GitHub PAT, Firecrawl, Perplexity).
- **Approving browser installs / OS permission dialogs** (Playwright).
- **Granting filesystem scope** beyond read-only repo access.

## Phase 1 status
- `.mcp.json`: **unchanged.**
- MCP servers installed: **none.**
- MCP servers connected: **none.**
- Keys added: **placeholders only** (blank) via the env generator — no values.

## Recommended enablement order (when approved, later)
1. **Filesystem** (read-only) — lowest risk, immediate evidence value.
2. **GitHub** (read-only PAT) — code-history grounding.
3. **Playwright** — only when UI/flow verification is actually needed.
4. **Firecrawl** / **Perplexity** — at Phase 5 (ingestion/research), with keys +
   per-source ToS sign-off.
