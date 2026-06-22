# MCP Config & Installation Audit — Phase 8Z-A

**Type:** AUDIT (evidence-only). `.mcp.json` read, **not modified**. No installs performed. No secret values read or printed — env-var **names only**.
**Branch:** `feat/mcp-phase-8z-a-master-reconciliation` (off `main` @ `6035da9`).

---

## Part A — Configured MCP servers (GOAL 3)

### `.mcp.json` (project-scoped, the only repo MCP registry)

```jsonc
{
  "mcpServers": {
    "claude-flow": {
      "command": "npx",
      "args": ["-y", "ruflo@latest", "mcp", "start"],
      "env": { /* names only — see table */ },
      "autoStart": false
    }
  }
}
```

| Field | Value |
|-------|-------|
| **Name** | `claude-flow` |
| **Command** | `npx` |
| **Args** | `-y  ruflo@latest  mcp  start` (note: package is `ruflo@latest`, a rename/alias of the claude-flow CLI; `CLAUDE.md` still documents `@claude-flow/cli@latest`) |
| **Env var NAMES** (no values) | `npm_config_update_notifier`, `CLAUDE_FLOW_MODE` (=`v3`), `CLAUDE_FLOW_HOOKS_ENABLED` (=`true`), `CLAUDE_FLOW_TOPOLOGY` (=`hierarchical-mesh`), `CLAUDE_FLOW_MAX_AGENTS` (=`8`), `CLAUDE_FLOW_MEMORY_BACKEND` (=`hybrid`) — **all non-secret config flags; no API keys present** |
| **Enabled** | `autoStart: false` → not auto-started; started on demand by the client |
| **Reachable (locally checkable)** | Runs via `npx`; reachability depends on network/npm at invoke time. `scripts/ai/check_mcp_prereqs.sh` verifies node/npx presence only. Not invoked in this audit. |
| **Used by** | Claude Code + Codex agent coordination (swarm/memory/hooks). Heavily referenced across `CLAUDE.md`, `AGENTS.md`, and `.agents/skills/**`. |

### `.codex/config.toml` (Codex mirror of the same server)

| Field | Value |
|-------|-------|
| **Name** | `claude-flow` (under `[mcp_servers.claude-flow]`) |
| **Command/args** | `npx … mcp …` (mirrors `.mcp.json`) |
| **Env** | `[mcp_servers.claude-flow.env]` — same `CLAUDE_FLOW_*` flag names |

### Other config scopes (out of repo)

- The `docs/ai/mcp/README.md` notes Claude Code also reads **user/app-level** config (`~/.claude.json`, Claude Desktop `claude_desktop_config.json`). Those are **outside the repo**, machine-specific, and explicitly **out of scope** for this audit (no repo evidence; not WebHound-managed). Session-level connectors visible to the assistant (computer-use, chrome, mcp-registry, etc.) are **environment-provided, not WebHound config**.

**Conclusion (GOAL 3):** Exactly **one** MCP server is configured in the repo — `claude-flow` — mirrored in two registries (`.mcp.json`, `.codex/config.toml`). `autoStart:false`. No API-key env vars in either. No other server configured.

---

## Part B — Installation / package audit (GOAL 4) — no installs performed

Searched: `apps/web/package.json`, `apps/web/package-lock.json`, `packages/`, `scanner/requirements.txt`, `scanner/pyproject.toml`, `apps/api/requirements.txt`, Dockerfiles (`infra/docker/*`), `docker-compose*.yml`.

| MCP / tool | npm pkg | python pkg | binary | wrapper/script | Evidence |
|------------|---------|-----------|--------|----------------|----------|
| **claude-flow** (`ruflo`) | ❌ not a dep | ❌ | runs via `npx ruflo@latest` (not vendored) | `.mcp.json`, `.codex/config.toml` | **runnable via npx**, not installed as a dependency |
| Filesystem MCP | ❌ | ❌ | ❌ | doc only | `docs/ai/mcp/FILESYSTEM_MCP.md` |
| GitHub MCP | ❌ | ❌ | ❌ | doc only | `docs/ai/mcp/GITHUB_MCP.md` |
| Playwright MCP | ❌ (`@playwright/*` MCP not present) | ❌ | ❌ | doc only | `docs/ai/mcp/PLAYWRIGHT_MCP.md` — note: Playwright **browser engine** is a prod opt-in (`WEBHOUND_BROWSER_ENABLED`), distinct from the MCP server |
| Firecrawl MCP | ❌ | ❌ | ❌ | doc only | `docs/ai/mcp/FIRECRAWL_MCP.md` |
| Perplexity MCP | ❌ | ❌ | ❌ | doc only | `docs/ai/mcp/PERPLEXITY_MCP.md` |
| LightRAG / Graphiti / Neo4j / Ollama / Graphify | n/a | runtime (local, non-MCP) | local services | `scripts/ai/setup_lightrag.sh`, Ollama | **live as runtimes**, **zero** as MCP servers |
| ZAP / Nuclei / Semgrep / Gitleaks / sqlmap / DalFox / libinjection / Trivy | ❌ | ❌ | ❌ | ingested docs only | `corpus/`, `knowledge/detection-engineering/` — **knowledge, not installed**; Trivy not found at all |
| Stripe / Cloudflare / Vercel / Railway / Resend | n/a (prod SDK/HTTP) | prod integrations in `apps/api` | n/a | n/a as MCP | provider integrations exist in product code; **no MCP server** for any |
| Postgres / Redis | n/a | service deps | `postgres:16-alpine`, `redis:7-alpine` in compose | n/a | **infrastructure**, no DB-MCP |

**Grep results (verbatim):**
- `apps/web/package.json`, `packages/*/package.json`: no `mcp` dependency.
- `apps/web/package-lock.json`: no `"*mcp*"` package key.
- `scanner/requirements.txt`, `apps/api/requirements.txt`, `scanner/pyproject.toml`: no `mcp` package.
- Only one MCP registry file on disk: `./.mcp.json`.

**Conclusion (GOAL 4):**
- **Installed as a package:** 0 MCP servers.
- **Runnable (via `npx`, not vendored):** 1 — `claude-flow`/`ruflo`.
- **Everything else:** documentation, ingested knowledge, or non-MCP runtimes/integrations.

---

## Validation statement

- `.mcp.json` was **read only** and is byte-for-byte unchanged.
- No package, binary, or MCP server was installed.
- No `.env`/secret **values** were read; only env-var **names** are listed.
- Scanner, WADE scoring, provider-access, billing, and auth were not touched.
</content>
