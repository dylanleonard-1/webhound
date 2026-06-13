# Phase 5A — Internal Knowledge Ingestion: Results

Proves the pipeline **Document → Manifest → Chunk → Metadata → Index → Retrieval →
Memory Summary** end-to-end on WebHound's **OWN internal docs only**. **No external
content** (no OWASP/MITRE/NIST/provider docs/threat feeds/GitHub/Firecrawl/
Perplexity/MCP/internet) entered the corpus.

Pipeline: [`scripts/ai/ingest_internal_knowledge.py`](../../scripts/ai/ingest_internal_knowledge.py).
Committed outputs: `corpus/manifests/manifest.jsonl`, `corpus/manifests/memory_summaries.jsonl`.
Chunks + index are written to the OS temp dir (ephemeral, **not committed**).

## 1. Inventory
- **Approved sources (internal only):** `docs/`, `knowledge/`, `corpus/`, `vault/`,
  and root `WEBHOUND_*.md` + `{README, KNOWN_LIMITATIONS, SECURITY_NOTICE,
  ALPHA_TESTING, TESTER_SETUP}.md`. Excluded: `CLAUDE.md` (agent instructions),
  templates, all non-`.md`, all code, all external content.
- **Candidate documents:** **219**.
- **By authority tier (heuristic):** A = **188**, B = **19**, C = **12**.
  - A = curated knowledge-layer + architecture/blueprint/master-plan/readiness docs.
  - B = operational internal docs (deployment, env, onboarding, security, identity).
  - C = historical/reference (audits, reviews, benchmarks, alpha/tester docs) →
    `verification_status: needs_review`.
  - **Honesty note:** tiering is a **path heuristic**, and Tier A is broad (all
    curated knowledge-layer docs). It is a starting classification, not ground truth.
- **By source type:** `internal_doc` = 216, `decision_log` = 3.
- **Duplicates / obsolete (detected, NOT deleted):** **1 duplicate group** — six
  **empty (0-byte)** stubs share the empty-content hash:
  `docs/{api-routes, architecture, database-schema, roadmap, scanner-engines,
  wade}.md`. The pipeline surfaced these automatically. They were **not deleted**
  (per Phase-5A limits); recommend Phase 5B either populate or mark `deprecated`.

## 2. Manifests
- **Records created:** **219**, written to `corpus/manifests/manifest.jsonl`
  (separate from raw content; one JSON object per line, sorted by `doc_id`).
- **Schema validation:** **0 errors** — every record validates against
  `corpus/manifests/manifest.schema.json` (Draft 2020-12).
- Each record carries: `doc_id`, `title`, `source_name` ("WebHound internal"),
  `source_url` (repo-relative local pointer), `source_type`, `authority_tier`,
  `content_hash` (`sha256:…`), `topic_tags`, `verification_status`,
  `retention_class`, `related_docs` (sibling `doc_id`s = graph edges), plus all
  other required fields. `license_terms: internal`, `pii_risk_class: none`,
  `trust_label: trusted_local`.
- **Deterministic / idempotent:** fixed ingest stamp + content hashes ⇒ re-running
  produces an identical `manifest.jsonl` (clean diffs).

## 3. Chunking
- **Chunks created:** **880** (split by H2/H3 headings, context preserved).
- **Traceability:** every chunk carries `doc_id`, `source_path`, `authority_tier`,
  `heading`, and a `chunk_hash`. **Orphan chunks: 0** (every chunk maps to a
  manifest record + source document + hash).
- Chunks live in the ephemeral index work dir (OS temp), not committed.

## 4. Retrieval (mock keyword; LightRAG not installed)
880 chunks indexed; question → relevant chunks → source documents → authority tier.
Examples (top hits, abbreviated):

| Query | Top source(s) | Tier |
|-------|---------------|------|
| What is WADE? | `WEBHOUND_VISIBILITY_REVIEW.md`, master plan, `WEBHOUND_PRODUCT_REVIEW.md` | C/A/C |
| What is the provider access framework? | `WEBHOUND_PROVIDER_AUDIT.md`, master plan, `WEBHOUND_PLATFORM_ACCESS_FRAMEWORK.md` | C/A/A |
| What scanner IPs are currently approved? | `docs/scanner-identity.md`, `WEBHOUND_PLATFORM_ALLOWLISTING_PLAN.md` | B/C |
| What known false positives exist? | master plan, `vault/webhound/false-positives/README.md` | A/A |
| Difference between corpus and knowledge? | `knowledge/README.md`, `knowledge/scanner-engines/README.md` | A/A |
| Current threat-intel architecture? | master plan, `docs/INTERNAL_PLATFORM.md`, `knowledge/threat-intel-library/README.md` | A/B/A |

Every query returned **a relevant internal source with its authority tier + path**.

## 5. Memory generation
- **Memory entries created:** **6** → `corpus/manifests/memory_summaries.jsonl`.
  Topics: architecture-decisions, platform-access-decisions, known-false-positives,
  wade-decisions, ingestion-decisions, roadmap-decisions.
- Each record: `memory_id`, `summary`, `authority_tier`,
  `related_manifest_doc_ids`, `related_paths`, `review_status`, `retention_class`,
  `created_at/updated_at`. **Summaries + pointers ONLY** — no full docs, no secrets,
  no raw scans, no customer data. **Bad pointers: 0** (all paths exist).

## 6. Validation results (real)
- Manifests pass schema: **219/219, 0 errors**.
- Chunks map to source docs: **880/880, 0 orphans**.
- Retrieval returns sources: **6/6 queries returned ≥1 relevant internal source**.
- Memory entries contain pointers (no full docs): **6/6, 0 bad pointers**.
- No orphaned records; **no ingestion outside approved internal sources**.
- `tests/ai` (incl. new manifest.jsonl + memory checks): **13 passed**.

## 7. Retrieval quality assessment (honest)
- **Source attribution: strong.** Every result names the exact source path +
  authority tier; nothing is fabricated.
- **Authority preservation: correct.** Tier travels from manifest → chunk →
  retrieval result.
- **Chunk relevance / ranking: moderate.** Mock **keyword** scoring favors **verbose**
  docs (the master plan, audits) over the **concise canonical** note — e.g. "What is
  WADE?" surfaces review/audit docs above `knowledge/webhound/wade/WADE_FOUNDATION.md`.
  Short queries against short canonical notes underperform.
- **Root cause:** keyword frequency ≠ semantic relevance, and long docs accumulate
  more term hits. This is the expected ceiling of mock retrieval.

## 8. Lessons learned
1. **Empty architecture stubs exist** (`docs/architecture.md`, `docs/wade.md`,
   `docs/scanner-engines.md`, + 3) — the pipeline caught them as a 0-byte duplicate
   group. Inventory is already paying off.
2. **Heuristic tiering is too coarse** — 188/219 landed in Tier A. A real tier needs
   per-doc review, not a path rule.
3. **Keyword retrieval is enough to prove the plumbing, not enough for quality** —
   semantic embeddings (LightRAG/real embeddings) are needed for ranking.
4. **Determinism works** — fixed stamp + content hashes make `manifest.jsonl`
   re-runnable with no diff (good for CI + clean reviews).
5. **Integrity gates work** — the pipeline refuses to write on schema errors, orphan
   chunks, or bad memory pointers (caught the `PHASE5A_RESULTS.md` self-reference
   before it shipped).

## 9. Phase 5B recommendations
1. **Install LightRAG** (dev-only, approved) + real/offline embeddings; re-run the
   *same* internal corpus first to measure ranking lift before any external content.
2. **Refine tiering** — downgrade broad Tier A; review C (historical) docs; mark the
   6 empty stubs `deprecated` (don't delete).
3. **Add chunk de-duplication + min-length filter** so empty/near-empty docs don't
   produce chunks.
4. **Only then** begin **gated external ingestion** (Phase 5B), one Tier-A source at
   a time, with per-source license/ToS sign-off — never before internal retrieval
   quality is acceptable.
5. **Promote `tests/ai` into CI** (still no `.github/workflows`) so manifest/schema
   stays green.

---
*Scope honored: internal-only, no external/threat-feed/provider/OWASP ingestion, no
scanner/WADE/provider-access behavior changes, `.mcp.json` untouched.*
