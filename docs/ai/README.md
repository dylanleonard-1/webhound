# WebHound AI Knowledge Layer — `docs/ai/`

This tree documents the **AI Knowledge Layer**: an evidence-based knowledge system
that lets Claude audit WebHound's scanner engines like a detection / appsec /
threat-intel / browser-security engineer rather than a generic programmer.

> **Status: Phase 1 (MCP foundation) — DOCUMENTATION + SAFE SCAFFOLDING ONLY.**
> Nothing in this phase installs, connects, or configures any MCP server, and no
> external content has been ingested. The master plan and phase gates live in
> [`WEBHOUND_AI_KNOWLEDGE_LAYER_MASTER_PLAN.md`](../../WEBHOUND_AI_KNOWLEDGE_LAYER_MASTER_PLAN.md)
> at the repo root.

## What Phase 1 delivered

- `docs/ai/mcp/` — one doc per candidate MCP (Filesystem, GitHub, Playwright,
  Firecrawl, Perplexity), plus a security model, a manual-approvals matrix, a
  smoke-test guide, and a note on the **existing** WebHound AI/TI context.
- `scripts/ai/` — read-only prerequisite checker + a non-destructive smoke-test
  describer. Neither installs anything or touches `.mcp.json`.
- Env-key **placeholders** (`GITHUB_TOKEN`, `FIRECRAWL_API_KEY`,
  `PERPLEXITY_API_KEY`) added via the repo's env generator
  (`scripts/_gen_env_example.py`) — never by hand-editing `.env.example`.

## What Phase 1 did NOT do (hard limits)

- Did **not** edit `.mcp.json` (the only configured MCP today is `claude-flow`).
- Did **not** install or connect any MCP server, Qdrant, or LightRAG.
- Did **not** create the evidence corpus or ingest any external docs/feeds.
- Did **not** touch WADE, scanner, provider-access, billing, or auth logic.
- Did **not** push. (One local commit only.)

## Grounding facts this layer must respect (from the Phase 0 gap report)

- **Reuse, don't rebuild.** WebHound already has substantial substrate — see
  [`mcp/EXISTING_WEBHOUND_AI_CONTEXT.md`](mcp/EXISTING_WEBHOUND_AI_CONTEXT.md).
- The existing Claude path is `WEBHOUND_AI_ENABLED` + `ANTHROPIC_API_KEY`
  (scan-result summarization). The knowledge layer reuses it — **no parallel AI
  config**.
- `.env.example` is **generated**; edit `scripts/_gen_env_example.py` + this
  `docs/env.md`, then regenerate.
- `ruvector.db` is an orphaned claude-flow artifact (redb, unused by WebHound) —
  **ignore it**.
- There is **no CI** (`.github/workflows` absent) — a known gap; tests run
  locally for now.

## Phase order (each is a separate approval gate)

0 inspection → **1 MCP foundation (this)** → 2 evidence store + manifest →
3 knowledge library → 4 RAG/graph/memory → 5 ingestion → 6 playbooks →
7 datasets/goldens → 8 WADE enrichment interface → 9 engine-audit prep →
10 benchmarks → 11 dashboards.

**Do not start Phase 2 without explicit approval.**
