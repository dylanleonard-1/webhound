# Graphiti Repair Report — Phase CONTROL-2B

**Type:** KNOWLEDGE-INGESTION on the LOCAL WSL brain DB only. No production data touched.
**Script:** `scripts/ai/graphiti_repair.py` (neo4j driver, `bolt://localhost:7687`).

## ⚠️ HONESTY: Ollama is NOT installed → LLM entity extraction is BLOCKED

A filesystem search of WSL found **no `ollama` binary anywhere** (not merely down). Graphiti's entity-extraction and semantic retrieval require an LLM + embeddings via Ollama, so **they cannot run**. Per the honesty guardrail, **no entities were fabricated**. Production concepts were inserted as **explicit memory nodes** via Cypher (no LLM), and the extraction limitation is reported, not hidden.

## Entity classification & cleanup (clearly-invalid only)

| Result | Count |
|--------|------:|
| Entities before | 27 |
| Classified **HALLUCINATED** (removed) | **26** |
| Classified VALID/kept (conservative) | 1 |
| Entities after | 1 |

Removal rule (conservative — only clearly-invalid): name > 60 chars, or contains newlines/backticks/URLs/image-exts/code-fences, or < 70% alphabetic. Examples removed (verbatim, truncated):
- `"(Ottos', and for a/w. The second-Bankiovirus, on Monday ismand 8…canceled.png"`
- `">![/sporting for each wordCountle to be sold!g.jpg \`\`\`python and also hashing…"`
- `"A:2. The GOP oralgebras, and the right (R=346Craft…"`
- `"https://enlightening**"`, `"http://www. After a|>…"`

The 1 kept entity (`"July in a) MASKS (Federalistle | January 0.1267 calories]"`) is also low quality but fell under the 60-char / 70%-alpha threshold — kept deliberately rather than risk over-deletion. These were all artifacts of prior `phi3:mini` extraction.

## Production concepts seeded (explicit memory nodes)

7 `:Episodic:ProductionConcept` nodes, each linked to its real module path:

| Concept | Module |
|---------|--------|
| cookie_scanner | `scanner/webhound/engines/cookies/cookie_scanner.py` |
| domain_classifier | `scanner/webhound/threat_intel/domain_classifier.py` |
| tls_checker | `scanner/webhound/engines/tls_dns/tls_checker.py` |
| threat_intel | `scanner/webhound/threat_intel/__init__.py` |
| run_scan | `worker/scan_tasks.py` |
| orchestrator | `scanner/webhound/core/orchestrator.py` |
| WADE | `scanner/webhound/wade/` |

Episodic nodes: 19 → **26** (existing 19 seed memories + 7 production concepts). The 13 original coherent seed memories (WADE confidence, Cloudflare-1020, XSS→CWE-79, etc.) are preserved.

## Net state

- Garbage entity graph cleaned (26/27 removed).
- 7 production concepts now queryable as memory nodes (verified in traceability: 6/8 concepts PASS via Graphiti).
- **Semantic/LLM retrieval remains BLOCKED until Ollama is installed** — documented, not faked. Until then Graphiti is a structured memory store, not an LLM retrieval engine.
</content>
