# Knowledge Trace Tests — Phase CONTROL-2A

**Type:** VERIFICATION-ONLY. End-to-end discoverability of 5 concepts across every brain layer.
**Legend:** PASS = clearly discoverable · PARTIAL = present but weak/indirect/generic-only · FAIL = absent.
**Evidence:** grep counts over `corpus/normalized/unified_chunks.jsonl`, `knowledge/`, `vault/WebHound AI Brain`, `lightrag_storage/`, live Neo4j/Graphiti.

| Concept | Corpus (1161) | Knowledge lib | Obsidian | Graphify graph | Neo4j | Graphiti | LightRAG (52) |
|---------|--------------|---------------|----------|----------------|-------|----------|---------------|
| **cookie_scanner** | PARTIAL (84 "cookie", 0 exact module) | PASS (33 files) | PARTIAL (6 notes) | FAIL (production file not scanned) | FAIL | FAIL (no episode) | PARTIAL (3) |
| **WADE** | PASS (65) | PASS (54 files) | PASS (83 notes) | PARTIAL (advisory `scripts/wade` only) | PARTIAL (FileNodes) | PARTIAL (1 episode) | FAIL (0) |
| **threat_intel** | PASS (62) | PASS (16 files) | PASS (12 notes) | FAIL (production not scanned) | FAIL | PARTIAL (indirect) | PARTIAL (1) |
| **domain_classifier** | FAIL (0) | FAIL (0) | FAIL (0) | FAIL | FAIL | FAIL | FAIL |
| **provider_detection** | PASS (211 "provider", 0 exact) | PASS (68 files) | PASS (51 notes) | PARTIAL (advisory resolvers) | FAIL | PARTIAL ("Vercel gate" episode) | PARTIAL (1) |

## Observations

1. **Generic vs module-exact:** the brain knows topics (`cookie`, `provider`, `threat intel`, `WADE`) strongly in **corpus + knowledge + Obsidian**, but the **exact production module names** (`cookie_scanner`, `domain_classifier`, `provider_detection`) score **0 across corpus/knowledge/vault** — there is no concept→code-module mapping.
2. **`domain_classifier` is a total blind spot** — a real production threat-intel module with **FAIL on every layer**. Nothing in the brain knows it exists.
3. **The three strong layers are corpus, knowledge/, and Obsidian.** The graph stack (Graphify/Neo4j/Graphiti/LightRAG) is PARTIAL/FAIL for every concept — it is not a reliable retrieval path for any of the 5.
4. **No concept is PASS on all layers.** The best (WADE) is PASS on 3 (corpus/knowledge/Obsidian), PARTIAL/FAIL on the graph stack.

## Per-concept layer score (PASS=1, PARTIAL=0.5, FAIL=0, of 7 layers)

| Concept | Score |
|---------|------:|
| WADE | 4.0 / 7 |
| provider_detection | 4.0 / 7 |
| threat_intel | 3.5 / 7 |
| cookie_scanner | 2.5 / 7 |
| domain_classifier | **0 / 7** |

**Knowledge-trace score: ~40%** — solid in the doc/corpus layers, near-zero in the graph layers, with one complete blind spot.
</content>
