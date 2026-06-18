# Brain Linkage Matrix — Phase CONTROL-2A

**Type:** VERIFICATION-ONLY. Subsystems × capability/visibility. ✅ yes · ⚠️ partial · ❌ no.

| Subsystem | Exists | Operational | Linked | Queryable | Vis. Obsidian | Vis. Graphify | Vis. Neo4j | Vis. Graphiti | Vis. LightRAG |
|-----------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Scanner (production)** | ✅ | ✅ | ⚠️ | ✅ (code) | ⚠️ topics | ❌ | ❌ | ❌ | ⚠️ |
| **WADE Production** (`scanner/webhound/wade`) | ✅ | ✅ | ⚠️ | ✅ (code) | ✅ topic | ❌ | ❌ | ⚠️ 1 ep | ❌ |
| **WADE Advisory** (`scripts/wade`) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ FileNodes | ⚠️ | ⚠️ |
| **Knowledge Corpus** (1161 chunks) | ✅ | ✅ | ✅ | ✅ (hybrid) | ✅ | ⚠️ via MD | ❌ (loader unrun) | ❌ | ⚠️ 52 subset |
| **Obsidian** (3 vaults) | ✅ | ✅ | ⚠️ | ⚠️ (manual) | self | ✅ 58 nodes | ❌ | ❌ | ❌ |
| **Graphify** (local-equiv) | ✅ | ✅ | ✅ | ✅ (json) | ✅ status | self | ✅ =FileNodes | ❌ | ❌ |
| **Neo4j** | ✅ | ✅ | ✅ | ✅ (Cypher) | ✅ status | n/a | self | ✅ (shared DB) | ❌ |
| **Graphiti** | ✅ | ⚠️ (Ollama down) | ✅ (Neo4j) | ❌ (retrieval offline) | ✅ status | ❌ | ✅ 19+27 | self | ❌ |
| **LightRAG** | ✅ | ⚠️ (52-chunk, graph broken) | ⚠️ | ⚠️ vector-only | ✅ status | ❌ | ❌ | ❌ | self |
| **Ollama** | ✅ | ❌ DOWN | ⚠️ | ❌ | ✅ status | ❌ | ❌ | (consumer) | (consumer) |
| **Reports** | ✅ | ✅ | ⚠️ | ✅ (code) | ✅ topic | ❌ | ❌ | ❌ | ❌ |

## Read of the matrix

- **Strong column:** "Exists" (everything is built) and "Vis. Obsidian" (everything has a topic note).
- **Weak columns:** "Vis. Neo4j / Graphiti / LightRAG" — the graph stack sees almost nothing of the product; it mostly sees the advisory scripts + its own memories.
- **Operational gaps:** Ollama ❌, Graphiti ⚠️, LightRAG ⚠️ — the graph/LLM tier is the weak half.
- **The diagonal truth:** production subsystems (Scanner, WADE-prod, Reports) are operational **but invisible to the graph layers**; the graph layers are visible to each other but light on real product content.
</content>
