# Graphiti Verification — Phase CONTROL-2A

**Type:** VERIFICATION-ONLY (read-only). No installs.
**Method:** live Neo4j queries against Graphiti's `Episodic` / `Entity` nodes + dependency check on Ollama.

## Status: data present in Neo4j, but extraction/retrieval is broken

| Component | State |
|-----------|-------|
| Episodes loaded (`Episodic`) | **19** (≈13 unique; some re-seeded duplicates) |
| Entities extracted (`Entity`) | 27 — **garbage** |
| Relationships | sparse (~1 meaningful) |
| Backing store (Neo4j) | ✅ linked (lives in the same DB) |
| LLM/embeddings (Ollama) | ❌ **DOWN** (required for extraction + semantic retrieval) |

## Episodes ARE meaningful (the good part)

Sample `Episodic` names (coherent WebHound seed memories):
`Cloudflare 1020 is not a finding` · `Vercel deployment protection gate` · `XSS maps to CWE-79` · `WADE confidence threshold for reporting` · `DalFox confirms XSS active` · `GreyNoise classifies CDN IPs as benign` · `CDN shared IPs suppress TI alerts` · `Hybrid retrieval weight choice (0.35/0.65)` · `Lexical fallback when dense unavailable` · `Phase 8A/8C` status.

## Entities are GARBAGE (the broken part)

Sample `Entity.name` values, verbatim:
`"(Ottos', and for a/w. The second-Bankiovirus…"`, `"July in a) MASKS (Federalistle…"`, `"A:2. The GOP oralgebras…"`, random hashing/calorie/URL fragments.

→ Entity extraction (run via **phi3:mini**, a 3.8B model, through Ollama) produced **hallucinated noise**, not WebHound concepts. The entity graph is unusable.

## Retrieval test (WADE, cookie_scanner, threat_intel, domain_classifier, provider_detection)

Graphiti semantic retrieval requires Ollama embeddings — **Ollama is down**, so live retrieval cannot run now. Static inspection of the loaded data:

| Concept | In episodes? | Clean entity? | Retrievable today? |
|---------|--------------|---------------|--------------------|
| WADE | ✅ ("WADE confidence threshold") | ❌ | ❌ (Ollama down) |
| cookie_scanner | ❌ (no episode) | ❌ | ❌ |
| threat_intel | ⚠️ (indirect: "CDN shared IPs suppress TI alerts") | ❌ | ❌ |
| domain_classifier | ❌ | ❌ | ❌ |
| provider_detection | ⚠️ ("Vercel deployment protection gate") | ❌ | ❌ |

## Can Graphiti retrieve meaningful WebHound knowledge?

**No — not today.** The episode *text* holds ~13 genuine decisions, but (a) the extracted **entity graph is hallucinated garbage**, and (b) **semantic retrieval is offline** because Ollama is down. Even with Ollama up, the entity layer would need re-extraction with a competent model. Coverage is also tiny (13 memories vs a product with dozens of engines).

**Score: 30% (F+)** — good seed episodes, but broken entity extraction + offline retrieval = not a functioning knowledge memory.
</content>
