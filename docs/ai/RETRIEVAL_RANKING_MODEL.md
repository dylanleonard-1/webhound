# Retrieval Ranking Model — Phase CONTROL-2E

How the WebHound brain ranks chunks, and the CONTROL-2E code-symbol improvements.
Ranking logic only — **no chunk content is altered**, no production behavior changes.

## Ranking inputs (per candidate chunk)
| Input | Source |
|-------|--------|
| **lexical score** | BM25-style tf·idf over chunk text (`_lex_score`), normalized 0–1 |
| **dense score** | cosine of query vs chunk MiniLM embedding (`_dense_score`), normalized 0–1 |
| **hybrid base** | `0.35·lexical + 0.65·dense` |
| **chunk type** | `code` (source_type=`production_code`) vs `doc` |
| **symbol metadata** | file stem (e.g. `tls_checker`) + symbol title (class/function) |
| **source type / tags** | `production_code`, `internal_doc`, `official_repo`, … + topic tags |

Final score (CONTROL-2E):
```
final = hybrid_base + symbol_boost + (8 - source_tier) * 0.01
```

## Why tls_checker DOCS used to outrank tls_checker.py (the bug)
For query *“tls checker certificate”*, the Nuclei TLS reference doc
(`corpus/normalized/repos/nuclei--syntax-reference.md`) had dense base **0.828**,
just above `scanner/webhound/engines/tls_dns/tls_checker.py` at **0.804** — a 0.024
margin. Pure semantic similarity favored the verbose doc; nothing rewarded the chunk
whose *module name is literally the query*. So the real engine sat at rank #2.

## Code-symbol boost (generalized, not per-concept)
`_symbol_boost(query_tokens, chunk)` — code chunks only:
- **+0.25** when the query contains ALL tokens of the chunk's **module stem**
  (`tls_checker` → `[tls, checker]` ⊆ query). 
- **+0.12** when the query contains ALL tokens of the chunk's **symbol title**
  (class/function name). 
Driven purely by `file_path` stem + `title` metadata → works for any module
(`cookie_scanner`, `domain_classifier`, `wade_correlation`, `orchestrator`, …) with
no hardcoded concept list.

## Source-priority tie-break
`_source_tier(chunk)` → bonus `(8 - tier)·0.01`:
| Tier | Class | Bonus |
|------|-------|------:|
| 1 | Production code | +0.07 |
| 2 | API code | +0.06 |
| 3 | WADE code | +0.05 |
| 4 | Tests | +0.04 |
| 5 | Technical docs | +0.03 |
| 6 | Knowledge notes | +0.02 |
| 7 | Planning/other | +0.01 |

Small by design — a **tie-break**, so generic knowledge queries (no symbol match)
still let the most semantically relevant doc win; exact symbol matches get the large
+0.25/+0.12 boost so code decisively beats docs.

## Effect
`tls_checker.py`: 0.804 + 0.25 + 0.07 = **1.124**, vs the Nuclei doc 0.828 + 0.03 =
0.858 → code now rank #1. All 10 benchmark concepts are top-ranked as code (see
`TRACEABILITY_BENCHMARK.md`). The CONTROL-2D ≥8/10 gate is unaffected (boosts only add).

## Knowledge-query guard (CONTROL-2E refinement)
The code bias must NOT hijack natural-language security questions. Two safeguards:
- **Query gating** — `_is_symbol_like_query()` only enables the code-symbol/source-tier
  boost when the query looks like a code lookup: a snake_case/CamelCase identifier, a
  `.py`/path token, or a short (≤5-token) noun phrase with no question word
  (`how/what/why/should/does/prevent/help/handle/cause/validate/...`). Prose questions
  → boost OFF → pure semantic ranking.
- **Prose preference** — for prose queries, `_prose_bonus()` demotes **test** chunks
  by −0.30 (tests assert behavior, they don't explain) and gives docs/knowledge +0.06;
  production code stays neutral so it can still win when genuinely dominant.

Why both were needed (real findings): "what causes **Cloudflare** challenge pages…"
wrongly got +0.25 because it contained the module token `cloudflare` (fixed by query
gating); "how does HSTS…" returned a *test file* on pure semantics (fixed by the −0.30
test demotion). After the refinement, all 5 prose guard queries rank docs/knowledge #1
while the 10 code concepts stay 10/10 (`tests/ai/test_code_symbol_ranking.py`).
