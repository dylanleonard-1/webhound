---
title: WebHound Current State
phase: CONTROL-1
---
<!-- WEBHOUND-GENERATED -->

# WebHound — Current State (Single Source of Truth)

> Canonical baseline produced by **Phase CONTROL-1** (map/document only — no system changes).
> Full detail: `docs/ai/WEBHOUND_CURRENT_STATE.md` in the repo.

## One-line status

Production scanner + customer-facing **Production WADE** are live and wired. A large **advisory AI/brain layer is built but isolated** — none of it reaches production scoring or customer reports. Main tracking pain = duplication (2× WADE, 3× vault, 4× graph runtimes).

## System map (click through)

- [[02-Scanner Engines/index|Scanner Engines]] · [[07-Scanner/index|Scanner]] — 11 production engine families, ~104 tests
- [[03-WADE/index|Production WADE]] vs [[08-WADE/index|Advisory WADE]] — **two distinct systems sharing a name**
- [[13-Knowledge Corpus/index|Knowledge Library]] — 487 manifests · 1,161 chunks · 1,161 embeddings · hybrid 76% top-1
- [[00-Maps/index|Obsidian Maps]] — **3 vaults exist** (this one + KNOWLEGE VAULT + repo stub); pick one canonical
- [[15-Graphiti/index|Graphiti]] · [[16-Neo4j/index|Neo4j]] · [[14-LightRAG/index|LightRAG]] · [[17-Ollama/index|Ollama]] — **LOCAL-ONLY, not production-wired**
- [[11-External Tools/index|Tool Stack]] — most security tools are knowledge-only; Playwright/httpx/dnspython are production
- MCP Ecosystem — `.mcp.json` = claude-flow only; 5 documented; **0 touch production** (see repo `docs/ai/MCP_MASTER_MATRIX.md`)

## Open PRs

- **#22** Phase 9B-B detection hardening (scanner) — **merge first** (only production-relevant PR)
- #23 Phase 8X tooling audit (docs) · #24 Phase 8Z-A MCP reconciliation (docs) · #2 dependabot (dev)

## Next single move

**Merge PR #22** — finish the validated in-flight scanner hardening; then batch-merge the doc PRs. Do not build new systems.

#webhound #dashboard #current-state #baseline
</content>
