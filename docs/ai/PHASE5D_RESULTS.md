# Phase 5D-B — Synonym Expansion, CI, Stub Retirement: Results

Zero-download retrieval follow-ups on the **internal corpus only**. No LightRAG/
torch/embeddings, no model download, no external API, no external ingestion, no
scanner/WADE/provider-access changes, `.mcp.json` untouched.

## 1. Synonym / alias query expansion (zero-dep)
Added a small, **generalizing** domain alias map (`_ALIAS_GROUPS` in
[`scripts/ai/semantic_retrieval.py`](../../scripts/ai/semantic_retrieval.py)) —
concept groups like `ip↔address↔egress↔outbound↔allowlist`,
`wade↔drift↔anomaly↔baseline`, `false↔positive↔fp`, etc. **Not** per-question
hardcoding. **How to extend:** add a `concept: [synonyms…]` group (documented in
the code).

- **Query-side only** (docs are never expanded), **stemmed**, **deduped**.
- **Weighted:** original query terms count 1.0; synonyms count **`ALIAS_WEIGHT=0.25`**
  so exact matches dominate and aliases only add recall (preserves precision).
- **On by default** for the `bm25` backend (`--no-expand` to disable).

### Did it change rankings? (honest)
- **Naive (unweighted) expansion regressed** the 10-query eval (top-1 8→7,
  top-3 10→9) — over-expansion added noise. Fixed by **down-weighting** aliases.
- **Final weighted expansion is net-neutral on the direct-term eval** (top-1 8/10,
  top-3 10/10 — identical to 5C) — it does **not** change those rankings.
- **It does help paraphrase queries** the eval doesn't contain. Demo — *"egress
  addresses the crawler uses"* (no exact "ip"/"scanner"):
  - without expansion → `PLATFORM_ACCESS_FRAMEWORK`, a deployment doc, an unrelated
    Playwright doc.
  - **with expansion → `WEBHOUND_ARCHITECTURE_SUMMARY.md` #1** (the doc that
    actually lists the static scanner IPs).
- A regression guard test locks in "expansion must not drop eval top-1/top-3".

## 2. CI (first workflow in the repo)
[`.github/workflows/ai-knowledge-tests.yml`](../../.github/workflows/ai-knowledge-tests.yml)
— **minimal + safe**:
- `permissions: contents: read` (least privilege, no secrets).
- Installs **only `pytest` + `jsonschema`** — **not** the production
  `requirements.txt` (no fastapi/sqlalchemy/asyncpg/DB).
- Runs `scripts/ai/validate_knowledge_structure.py` + `pytest tests/ai`.
- **Path-filtered** to knowledge-layer files; no app/scanner/integration tests, no
  deploy, no network beyond the PyPI install.
- YAML validated locally; the steps are exactly the (green) local commands.
  *(GitHub Actions can't be executed locally.)*

> **⚠️ NOT pushed (honest):** pushing files under `.github/workflows/` requires the
> **`workflow` OAuth scope**, which the current token lacks — GitHub rejected the
> push (`refusing to allow an OAuth App to create or update workflow … without
> 'workflow' scope`). Per "stop the sub-item and report rather than force it," the
> workflow file is **written + validated and left on disk** at
> `.github/workflows/ai-knowledge-tests.yml` but is **NOT committed/pushed**. To
> enable it, either (a) grant `workflow` scope (`gh auth refresh -s workflow`) and
> re-push, or (b) add the file via the GitHub UI / a PR from a token with the
> scope. The rest of Phase 5D-B pushed normally.

## 3. Empty-stub handling — RETIRED (decision + rationale)
The 6 pre-existing empty 0-byte stubs (`docs/{api-routes, architecture,
database-schema, roadmap, scanner-engines, wade}.md`) were **formally removed**
(`git rm`), not populated.

**Why retire instead of populate:** I first *populated* them as pointer notes to
the canonical `knowledge/` docs — but their **topical filenames** (`docs/wade.md`)
then **outranked the canonical note** via path-match (e.g. "What is WADE?" returned
`docs/wade.md` above `WADE_FOUNDATION.md`), regressing the eval (orig-6 top-1
4→3). They duplicated topics already canonical in `knowledge/` and had **no inbound
links**, so retiring is cleaner: it removes dead weight and the ranking competitor.
- Manifest after: **216 docs, 0 empty stubs, 0 duplicate groups** (the empty-hash
  dup group is gone).
- The `empty_stub` role + chunk-skip mechanism **remain** (tested on synthetic
  input) so any *future* empty doc is still handled.

## 4. Retrieval before / after (10-query set)
| Config | top-1 (10) | top-3 (10) | top tier A/B (10) | top-1 (orig 6) | top-3 (orig 6) |
|--------|:--:|:--:|:--:|:--:|:--:|
| Keyword baseline | 4 | 5 | 8 | 3 | 3 |
| BM25+tier+role+path (5C) | 8 | 10 | 10 | 4 | 6 |
| **+ synonyms (5D-B)** | **8** | **10** | **10** | **4** | **6** |

Net-neutral on the eval (synonyms add paraphrase recall, not eval-metric change);
the 6-stub retirement restored 5C-level quality after the populate experiment.

## 5. Validation
- `pytest tests/ai` → **20 passed** (added: synonym weighting+non-regression;
  updated: empty-stub mechanism on synthetic input).
- `validate_knowledge_structure.py` → exit 0.
- manifest still validates (216 records, 0 schema errors); dead IP `152.55.180.27`
  absent; `.mcp.json` unchanged; **no scanner/WADE/provider-access changes**.

## 6. Lessons learned
- **Weighting beats inclusion** for query expansion — full-weight synonyms hurt
  precision; down-weighted ones add recall safely.
- **Topical filenames are a double-edged sword** — path-match boosts canonical
  notes *and* would boost any same-named stub; better to retire duplicative stubs
  than to create competitors.
- **A regression guard test** is the right way to keep a recall feature from
  silently hurting precision.

## 7. Phase 5D recommendation (unchanged)
Decide dense embeddings explicitly (offline local `sentence-transformers`, flagged
~90 MB download) used as a **hybrid re-ranker** on the strong BM25+role+path+synonym
prior. Only after internal retrieval is solid, begin **gated external ingestion**
(separate approval).
