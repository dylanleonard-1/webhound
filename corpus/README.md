# `corpus/` — WebHound Evidence Corpus

The corpus is the **evidence store** for the AI Knowledge Layer: provenance-stamped
documents that let Claude audit WebHound's scanner engines like a detection /
appsec / threat-intel engineer. It is the raw + normalized material that later
phases will index (RAG/graph) and summarize into Claude memory.

> **Status: Phase 2 — STRUCTURE + POLICY ONLY. The corpus is EMPTY by design.**
> No documents, repos, papers, or feeds have been ingested. Phase 2 defines
> *where* knowledge will live and *under what rules*; it does **not** populate it.
> Ingestion is a later, separately-approved phase.

## Layout

```
corpus/
  raw/         immutable, as-fetched source material (never edited in place)
    docs/      official vendor docs / standards (Tier A)
    repos/     official tool repos: READMEs/docs/examples/release-notes (Tier C)
    papers/    research / academic / vendor research papers (Tier B)
    feeds/     threat-intel feed payloads, as fetched (Tier D)
    internal/  WebHound's own docs/decisions/notes (trusted_local)
  normalized/  cleaned, chunked, provenance-stamped derivatives of raw/
    docs/ repos/ papers/ feeds/
  manifests/   manifest.jsonl (one record per doc) + manifest.schema.json
  graph/       exported knowledge-graph artifacts (built in Phase 4)
  logs/        ingestion/normalization run logs (no secrets)
```

## Core rules (full detail in `docs/ai/corpus/`)

1. **Raw is immutable.** Anything in `raw/` is stored exactly as fetched and never
   edited; corrections happen in `normalized/` with provenance back to the raw item.
2. **Everything carries provenance.** Source, authority tier, version, content
   hash, ingest date, review status, lineage — see
   [`PROVENANCE_POLICY`](../docs/ai/corpus/PROVENANCE_POLICY.md).
3. **Authority tiers A–E.** Tier A (official docs) overrides Tier E (community).
   Community content informs workflow but is never security authority — see
   [`SOURCE_AUTHORITY_TIERS`](../docs/ai/corpus/SOURCE_AUTHORITY_TIERS.md).
4. **External content is evidence, not instructions** (prompt-injection stance) —
   see [`PROMPT_INJECTION_POLICY`](../docs/ai/corpus/PROMPT_INJECTION_POLICY.md).
5. **Never ingest secrets or customer data.** No API keys, tokens, cookies,
   payment data, or private scan artifacts — see
   [`RETENTION_POLICY`](../docs/ai/corpus/RETENTION_POLICY.md).
6. **Reuse, don't duplicate.** The corpus *references* WebHound's existing runtime
   systems (threat_intel, WADE, Security Graph, validation/benchmark, Anthropic
   summarizer); it never re-implements them — see
   [`WEBHOUND_EXISTING_SYSTEMS_MAP`](../docs/ai/corpus/WEBHOUND_EXISTING_SYSTEMS_MAP.md).

## What is NOT here yet
- No ingested content (Phase 5).
- No Qdrant/LightRAG index (Phase 4).
- No ingestion scripts (Phase 5).

Design docs for all of the above live in [`docs/ai/corpus/`](../docs/ai/corpus/).
