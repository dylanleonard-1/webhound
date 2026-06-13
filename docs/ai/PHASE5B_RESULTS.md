# Phase 5B — Semantic Retrieval Foundation: Results

Goal: fix the Phase 5A weakness where raw keyword **counts** let verbose docs
(audits, the master plan) outrank the concise canonical note (e.g. "What is WADE?"
surfaced audit docs above `WADE_FOUNDATION.md`). Authority tier + relevance should
outweigh keyword frequency. **Internal corpus only — no external ingestion.**

Retrieval: [`scripts/ai/semantic_retrieval.py`](../../scripts/ai/semantic_retrieval.py).

## 1. Embeddings decision (guardrail honored) — IMPORTANT
The environment has **no** embedding/RAG libraries — not `lightrag`,
`sentence_transformers`, `transformers`, `torch`, `onnxruntime`, `faiss`, **not
even `numpy`**.

True **dense (embedding) semantic** retrieval requires one of:
- an **external embeddings API** (OpenAI/Anthropic/etc.) → **rejected**: sending
  internal WebHound docs out is touching the outside world; or
- **`torch` + a HuggingFace model download** (e.g. `all-MiniLM-L6-v2`, ~90 MB +
  torch, hundreds of MB) → a **large model download**, which the guardrail says to
  **flag, not silently perform**.

Per the guardrail, I did **NOT** install LightRAG/torch and did **NOT** call any
external embeddings API. Instead I implemented an **offline, zero-dependency,
pure-Python sparse-semantic upgrade** that directly fixes the stated weakness:

> **BM25 (Okapi, k1=1.5, b=0.75) + IDF + document-length normalization +
> authority-tier weighting.**

Why this fixes Phase 5A: BM25's **length normalization** removes the "long docs
accumulate more hits" bias, and **IDF** down-weights common terms while
up-weighting distinctive ones (so a canonical note's specific vocabulary wins).
The **authority multiplier** (A=1.15, B=1.0, C=0.85) makes tier break near-ties.
The `Backend` interface is **pluggable**, so a future dense-embedding backend can
drop in as an explicit, cost-flagged Phase-5C opt-in.

**Nothing was installed, downloaded, or sent out. Internal docs never left the
machine.**

## 2. Documents indexed
Same internal corpus as Phase 5A (`docs/`, `knowledge/`, `corpus/`, `vault/`,
`WEBHOUND_*.md` + whitelisted root docs). **890 chunks** over **220 internal
docs** (manifest linkage, authority tiers, source paths, content hashes preserved
from the Phase-5A pipeline; chunks read live, no index blob committed).

## 3. Retrieval comparison (keyword vs BM25+authority) — same 5A test set
| Metric | Keyword (5A baseline, raw counts) | BM25 + authority (5B) |
|--------|-----------------------------------|-----------------------|
| **top-1** | 2 / 6 | 2 / 6 |
| **top-3** | 2 / 6 | **4 / 6** |
| **top-result tier A/B** | 4 / 6 | **6 / 6** |

Per-query (top result shown):

| Query | Keyword #1 | BM25 #1 | Verdict |
|-------|-----------|---------|---------|
| What is WADE? | `WEBHOUND_VISIBILITY_REVIEW.md` (C) | **`knowledge/webhound/wade/WADE_FOUNDATION.md` (A)** | **FIXED** — the exact cited failure |
| Provider access framework | `knowledge/provider-docs/akamai/README.md` (A) | `…/architecture/WEBHOUND_ARCHITECTURE_SUMMARY.md` (A); framework doc at #2 | improved (now top-3) |
| Known false positives | `docs/ai/PHASE5A_RESULTS.md` (A) | `docs/ai/PHASE5A_RESULTS.md` (A); FP vault note #3 | partial (super-doc competes) |
| Scanner IPs approved | `WEBHOUND_VISIBILITY_REVIEW.md` (C) | `docs/ai/PHASE5A_RESULTS.md` (A); `docs/scanner-identity.md` #3 | improved (C demoted; top-3) |
| Threat-intel architecture | `knowledge/threat-intel-library/README.md` (A) | **`…/threat-intel/THREAT_INTEL_CURRENT_STATE.md` (A)** | improved (canonical #1) |
| Corpus vs knowledge | `knowledge/README.md` (A) | `docs/ai/PHASE5A_RESULTS.md` (A) | regressed-to-super-doc (knowledge/README dropped) |

## 4. Ranking improvements (honest)
- **The cited failure is fixed:** "What is WADE?" now returns `WADE_FOUNDATION.md`
  at #1 (audits demoted).
- **Authority preservation: 4/6 → 6/6** — **no tier-C audit/review doc ranks #1
  anymore**. Verbose-doc bias is gone (BM25 length normalization).
- **top-3: 2/6 → 4/6** — the canonical doc now reliably appears in the top 3 for 2
  more queries.
- **Citation quality unchanged-strong:** every result names exact source path +
  tier; nothing fabricated.

## 5. Memory compatibility
`corpus/manifests/memory_summaries.jsonl` is **unchanged and still valid**: 6
records, each with `memory_id`, `summary`, `authority_tier`,
`related_manifest_doc_ids`, `related_paths`, `review_status`. **Summaries +
pointers only — no full docs, no secrets, no customer data** (enforced by
`tests/ai`).

## 6. Quality metrics + remaining weaknesses
- **top-1 stayed 2/6** — honest cause: the new **`PHASE5A_RESULTS.md` super-doc**
  (which deliberately summarizes *every* topic: WADE, FPs, scanner IPs,
  corpus-vs-knowledge) is a genuinely relevant A-tier doc and now competes for #1
  on several queries. It is *correct content*, just not the per-topic canonical
  note. BM25 (lexical) cannot tell "comprehensive summary" from "canonical note".
- **Duplicate-content effects:** the 6 empty 0-byte doc stubs (from 5A) produce no
  useful chunks; they don't pollute results but inflate doc counts.
- **Chunk-size issues:** heading-split chunks vary widely; very short
  README-section chunks can under-rank vs long narrative chunks even with BM25.
- **Authority-weighting opportunity:** the multiplier helps across tiers but cannot
  disambiguate **among** the 188 Tier-A docs (the real top-1 contention). A finer
  signal (doc `source_type`: `internal_doc` vs an "analysis/meta" type for results
  docs) or dense embeddings would resolve this.

## 7. Validation results (real)
- Semantic (BM25) retrieval operational: ✅ (890 chunks, offline).
- Source attribution preserved: ✅ (path + tier on every hit).
- Authority preserved: ✅ (tier travels manifest → chunk → result; top-1 A/B 6/6).
- Schema validation still passes: ✅ (`pytest tests/ai` → **13 passed**; validator exit 0).
- Memory generation still valid: ✅ (6 records, pointers only).
- scanner/WADE/provider-access untouched: ✅; `.mcp.json` unchanged: ✅.
- No installs, no downloads, no external API, no index blob committed: ✅.

## 8. Lessons learned
1. **BM25 alone removes the verbose-doc bias** — length normalization + IDF is the
   single biggest lever, and it needs **zero** model download.
2. **Authority weighting fixes "stale audit on top"** (C demoted) but can't rank
   among same-tier docs.
3. **A comprehensive summary doc behaves like a magnet** — useful, but it competes
   with canonical notes; tagging meta/results docs with a distinct `source_type`
   would help.
4. **Top-1 against a strict canonical gold is the hard metric** — top-3 +
   authority-correctness improved clearly; top-1 needs semantics.

## 9. Phase 5C recommendation
1. **Decide on dense embeddings explicitly (cost-flagged).** Options:
   - **A — offline local model** (`sentence-transformers`, e.g. `all-MiniLM-L6-v2`):
     best quality, **internal docs stay local**, but costs a `torch` install
     (~hundreds of MB) + a ~90 MB model download. **Recommended** if the download
     is acceptable; gate any usage behind a dev-only requirement file.
   - **B — external embeddings API:** **not recommended** (sends internal docs out).
   - **C — stay offline-lexical:** keep BM25; add the refinements below.
2. **Refinements (no download, do first):** tag results/meta docs with a distinct
   `source_type` (de-prioritize for canonical queries); add a chunk min-length
   filter; mark the 6 empty stubs `deprecated`.
3. **Only after retrieval quality is good on the internal corpus**, consider gated
   **external** ingestion (still a separate, later approval).
4. **Promote `tests/ai` into CI** (still no `.github/workflows`).

---
*Scope honored: internal-only, no external/threat-feed/provider/OWASP ingestion, no
embeddings API call, no large download, no scanner/WADE/provider-access changes,
`.mcp.json` untouched.*
