# Obsidian Verification — Phase CONTROL-2A

**Type:** VERIFICATION-ONLY (read-only). No installs, no production changes.
**Branch:** `feat/control-2a-brain-verification` off `main` @ `ace3fab`.
**Method:** filesystem scan of `vault/` (note counts, dirs, wikilinks, generated markers).

## Vaults found — THREE (duplication)

| Vault | Path | Notes (.md) | Dirs | Generated-marked | Character |
|-------|------|------------:|-----:|------------------|-----------|
| Stub/operational | `vault/webhound` | 8 | 8 | 0 | repo-native, plain-MD stubs (decisions/runbooks/research) |
| **AI Brain** (primary) | `vault/WebHound AI Brain` | **133** | 40 | **133/133** | fully AI-generated (Phase 8G); 664 wikilinks |
| KNOWLEGE VAULT (typo) | `vault/WEBHOUND KNOWLEGE VAULT` | 114 | 32 | 111/114 | AI-generated, has `.obsidian/` app config |

- **Wikilinks (AI Brain):** 664 `[[...]]` references.
- **Generated markers:** every AI Brain note carries `<!-- WEBHOUND-GENERATED -->` + `phase:` frontmatter → 100% machine-generated (a *mirror*, not hand-curated knowledge).
- **Orphans / broken links:** not exhaustively graph-resolved this phase; the local-equiv graph (`graphify`) reports **0 orphan nodes** across its Markdown set. Wikilink targets are intra-vault by convention. **UNVERIFIED:** exact broken-link count (would need a vault link-resolver run).
- **Duplicate structures:** AI Brain has dual-numbered sections (`03-WADE`+`08-WADE`, `04`+`13 Knowledge Corpus`, `06`+`09 Threat Intelligence`, `08`+`11 External Tools`); AI Brain and KNOWLEGE VAULT overlap heavily (same note titles, e.g. `Nuclei Engine.md`, `WADE Reasoning Engine.md`).

## What % of the ecosystem is represented in Obsidian?

Obsidian represents the **documented architecture as topics** well, but as a generated **doc mirror** — it does not link to live code or runtime state.

| Ecosystem area | In Obsidian? |
|----------------|--------------|
| Scanner engines (as topics) | ✅ (02/07 sections) |
| Production WADE | ✅ (03-WADE) |
| Advisory WADE | ✅ (08-WADE) |
| Knowledge corpus | ✅ (04/13) |
| Providers / threat intel / taxonomy | ✅ |
| Graph runtimes (Neo4j/Graphiti/LightRAG/Ollama/Graphify) | ✅ (14–18) — *status notes only* |
| Reports / infra / billing / auth | ✅ (09/06/21/20) |
| **Production code modules by name** (`cookie_scanner`, `domain_classifier`, `provider_discovery`) | ❌ **0 hits** — topics yes, code-module mapping no |
| Live runtime values (graph counts, service health) | ❌ static snapshots only |

**Estimated coverage: ~70% (topical) / ~0% (code-linked).** Obsidian "sees" the system at the **conceptual/architectural** level, not the code or runtime level. The 3-vault split with no single canonical vault is the main structural defect.

**Score: 70% (B−)** — broad topical mirror; penalised for 3-vault duplication and zero code/runtime linkage.
</content>
