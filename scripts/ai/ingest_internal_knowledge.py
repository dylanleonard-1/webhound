#!/usr/bin/env python3
"""Phase 5A — internal-knowledge ingestion pipeline (WebHound's OWN docs only).

Proves: Document -> Manifest -> Chunk -> Metadata -> Index -> Retrieval ->
Memory Summary, end-to-end, on INTERNAL content only.

HARD LIMITS (Phase 5A): NO external ingestion (no OWASP/MITRE/NIST/provider docs/
threat feeds/GitHub/Firecrawl/Perplexity/MCP/internet). LOCAL + READ-ONLY inputs.
No LLM calls, no network, no installs, no secrets, no customer data, no prod DB.

Committed outputs (small metadata): corpus/manifests/manifest.jsonl +
corpus/manifests/memory_summaries.jsonl.
Ephemeral outputs (NOT committed): chunks + index, written under the OS temp dir.

Usage:
  python scripts/ai/ingest_internal_knowledge.py run            # full pipeline + write manifests/memory
  python scripts/ai/ingest_internal_knowledge.py run --dry-run  # compute, write nothing
  python scripts/ai/ingest_internal_knowledge.py query "What is WADE?"
  python scripts/ai/ingest_internal_knowledge.py selftest       # built-in retrieval test queries
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

# Fixed ingestion stamp -> deterministic, idempotent manifests (re-run = no diff).
INGEST_STAMP = "2026-06-13"

MANIFEST_PATH = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
MEMORY_PATH = os.path.join(ROOT, "corpus", "manifests", "memory_summaries.jsonl")
WORK_DIR = os.path.join(tempfile.gettempdir(), "webhound_rag_work")  # NOT in repo

# ---- approved internal sources ONLY -----------------------------------------
SOURCE_DIRS = ["docs", "knowledge", "corpus", "vault"]
ROOT_WHITELIST_PREFIXES = ("WEBHOUND_",)
ROOT_WHITELIST_EXACT = {
    "README.md", "KNOWN_LIMITATIONS.md", "SECURITY_NOTICE.md",
    "ALPHA_TESTING.md", "TESTER_SETUP.md",
}
# Excluded: CLAUDE.md (agent instructions, not knowledge), templates.
ROOT_EXCLUDE = {"CLAUDE.md", "BUG_REPORT_TEMPLATE.md", "FEEDBACK_TEMPLATE.md"}

STOP = set("a an the is are of to and or in on for with not no this that it as by "
           "be at from we you your our".split())


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------
def discover() -> list[str]:
    paths: list[str] = []
    for top in SOURCE_DIRS:
        for dp, _d, files in os.walk(os.path.join(ROOT, top)):
            paths += [os.path.join(dp, fn) for fn in files if fn.endswith(".md")]
    for fn in os.listdir(ROOT):
        if not fn.endswith(".md") or fn in ROOT_EXCLUDE:
            continue
        if fn.startswith(ROOT_WHITELIST_PREFIXES) or fn in ROOT_WHITELIST_EXACT:
            paths.append(os.path.join(ROOT, fn))
    return sorted(set(paths))


def _rel(path: str) -> str:
    return os.path.relpath(path, ROOT).replace(os.sep, "/")


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _title(text: str, rel: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()[:200]
    return os.path.basename(rel)


def _doc_id(rel: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", rel.lower()).strip("-")


def _topic_tags(rel: str) -> list[str]:
    toks = re.split(r"[/_.-]+", rel.lower())
    tags = [t for t in toks if t and t not in STOP and t not in ("md", "readme") and len(t) > 2]
    seen, out = set(), []
    for t in tags:
        if t not in seen:
            seen.add(t); out.append(t)
    return out[:10]


def classify(rel: str) -> dict:
    """Heuristic internal tiering. A=approved architecture, B=operational,
    C=historical/reference. Honest: this is a path heuristic, not ground truth."""
    low = rel.lower()
    base = os.path.basename(low)
    # C: historical / audit / review / benchmark reference docs
    if (base.startswith("webhound_") and any(k in base for k in
            ("audit", "review", "benchmark", "allowlisting_plan", "product_review"))):
        return dict(tier="C", stype="internal_doc", verification="needs_review", retention="long")
    if any(k in low for k in ("known_alpha", "alpha_workflow", "alpha_testing", "tester_setup", "known_limitations")):
        return dict(tier="C", stype="internal_doc", verification="needs_review", retention="long")
    # A: curated knowledge layer + architecture/blueprint/readiness/master-plan
    if (low.startswith("docs/ai/") or low.startswith("knowledge/") or low.startswith("corpus/")
            or low.startswith("vault/")
            or base in ("architecture.md", "scanner-engines.md", "wade.md")
            or "master_plan" in base or "platform_access_framework" in base
            or "production_readiness" in base or base == "project_overview.md"):
        # decisions are decision_log type
        stype = "decision_log" if "decision" in low else "internal_doc"
        return dict(tier="A", stype=stype, verification="verified", retention="permanent")
    # B: operational internal docs (deployment, env, onboarding, security, etc.)
    return dict(tier="B", stype="internal_doc", verification="verified", retention="long")


_CONF = {"A": 0.95, "B": 0.85, "C": 0.7}


def build_records() -> tuple[list[dict], dict]:
    paths = discover()
    records: list[dict] = []
    by_hash: dict[str, list[str]] = {}
    by_dir: dict[str, list[str]] = {}
    for p in paths:
        rel = _rel(p)
        raw = _read(p)
        h = _sha256(raw.encode("utf-8"))
        cls = classify(rel)
        rec = {
            "doc_id": _doc_id(rel),
            "title": _title(raw, rel),
            "source_name": "WebHound internal",
            "source_url": rel,                      # local pointer (no secrets)
            "source_type": cls["stype"],
            "authority_tier": cls["tier"],
            "language": "en",
            "product_or_provider": None,
            "topic_tags": _topic_tags(rel),
            "version": None,
            "last_updated": None,
            "first_ingested": INGEST_STAMP,
            "content_hash": h,
            "confidence_score": _CONF[cls["tier"]],
            "verification_status": cls["verification"],
            "license_terms": "internal",
            "citability": "internal_only",
            "pii_risk_class": "none",
            "retention_class": cls["retention"],
            "related_docs": [],                     # filled below
            "trust_label": "trusted_local",
        }
        records.append(rec)
        by_hash.setdefault(h, []).append(rec["doc_id"])
        by_dir.setdefault(os.path.dirname(rel), []).append(rec["doc_id"])

    # related_docs = sibling docs in the same directory (graph edges), bounded.
    for rec in records:
        d = os.path.dirname(rec["source_url"])
        sibs = [x for x in by_dir.get(d, []) if x != rec["doc_id"]]
        rec["related_docs"] = sorted(sibs)[:5]

    duplicates = {h: ids for h, ids in by_hash.items() if len(ids) > 1}
    records.sort(key=lambda r: r["doc_id"])
    stats = {
        "documents": len(records),
        "by_tier": {t: sum(1 for r in records if r["authority_tier"] == t) for t in "ABC"},
        "by_type": {},
        "duplicate_groups": len(duplicates),
        "duplicates": duplicates,
    }
    for r in records:
        stats["by_type"][r["source_type"]] = stats["by_type"].get(r["source_type"], 0) + 1
    return records, stats


# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------
def chunk_doc(rec: dict, text: str) -> list[dict]:
    """Split a markdown doc by H2/H3 headings, preserving context. Each chunk maps
    back to its manifest doc_id, source path, authority tier, and a chunk hash."""
    parts: list[tuple[str, str]] = []
    cur_head, buf = rec["title"], []
    for line in text.splitlines():
        if re.match(r"^#{2,3}\s", line):
            if buf:
                parts.append((cur_head, "\n".join(buf).strip()))
                buf = []
            cur_head = line.lstrip("#").strip()
        else:
            buf.append(line)
    if buf:
        parts.append((cur_head, "\n".join(buf).strip()))
    # merge tiny chunks; cap very large ones
    chunks = []
    for i, (head, body) in enumerate([p for p in parts if p[1]]):
        body = body[:4000]
        chunks.append({
            "chunk_id": f"{rec['doc_id']}#${i}",
            "doc_id": rec["doc_id"],
            "source_path": rec["source_url"],
            "authority_tier": rec["authority_tier"],
            "heading": head,
            "text": f"{head}\n{body}".strip(),
            "chunk_hash": _sha256((head + body).encode("utf-8")),
        })
    return chunks


def build_chunks(records: list[dict]) -> list[dict]:
    chunks: list[dict] = []
    for rec in records:
        text = _read(os.path.join(ROOT, rec["source_url"]))
        chunks += chunk_doc(rec, text)
    return chunks


# ---------------------------------------------------------------------------
# Index + retrieval (mock keyword; LightRAG not installed)
# ---------------------------------------------------------------------------
def _terms(q: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9_.]+", q.lower()) if t not in STOP and len(t) > 2]


def retrieve(chunks: list[dict], query: str, k: int = 5) -> list[dict]:
    terms = _terms(query)
    scored = []
    for c in chunks:
        low = c["text"].lower()
        score = sum(low.count(t) for t in terms)
        if score:
            scored.append((score, c))
    scored.sort(key=lambda s: (-s[0], s[1]["chunk_id"]))
    return [{"score": s, **c} for s, c in scored[:k]]


# ---------------------------------------------------------------------------
# Memory generation (summaries + pointers only)
# ---------------------------------------------------------------------------
def _find_id(records: list[dict], needle: str) -> list[str]:
    return [r["doc_id"] for r in records if needle in r["source_url"]]


def build_memory(records: list[dict]) -> list[dict]:
    def first(needle):
        ids = _find_id(records, needle)
        return ids[:1]
    mem = [
        ("architecture-decisions",
         "WebHound = API/web/worker/scanner; Railway+Vercel+Postgres+Redis; static scanner IPs "
         "162.220.234.240/152.55.180.240/152.55.180.241.",
         "A", first("knowledge/webhound/architecture/WEBHOUND_ARCHITECTURE_SUMMARY.md"),
         ["knowledge/webhound/architecture/WEBHOUND_ARCHITECTURE_SUMMARY.md"]),
        ("platform-access-decisions",
         "Provider access: Cloudflare API automation; Vercel guided/manual; 8 others guided/manual. "
         "Remediation uses official provider docs only.",
         "A", first("knowledge/webhound/provider-access/PLATFORM_ACCESS_FRAMEWORK.md"),
         ["knowledge/webhound/provider-access/PLATFORM_ACCESS_FRAMEWORK.md"]),
        ("known-false-positives",
         "10 seeded FP lessons (CORS over-severity, social-link-as-API, minified entropy, "
         "correlation w/o attack path, CSP severity, cross-origin isolation, RSC copy, SPA form, "
         "admin shell, CSP-hosts graph).",
         "A", first("knowledge/false-positive-catalog"),
         ["knowledge/false-positive-catalog/"]),
        ("wade-decisions",
         "WADE = baseline/change-intelligence foundation; not yet knowledge-enriched; Phase-8 "
         "enrichment will be suggest-only (no auto-suppress/severity/scoring change).",
         "A", first("knowledge/webhound/wade/WADE_FOUNDATION.md"),
         ["knowledge/webhound/wade/WADE_FOUNDATION.md"]),
        ("ingestion-decisions",
         "Phase 5A ingests INTERNAL docs only end-to-end (manifest->chunk->index->retrieval->memory) "
         "before any external content. corpus=evidence, knowledge=curated.",
         "A", first("docs/ai/corpus/INGESTION_POLICY.md"),
         ["docs/ai/corpus/INGESTION_POLICY.md", "docs/ai/RAG_ARCHITECTURE.md"]),
        ("roadmap-decisions",
         "AI Knowledge Layer phases: 0 inspect, 1 MCP docs, 2 corpus, 3 knowledge, 4 retrieval, "
         "5A internal ingestion (this), 5B external (gated), 6 playbooks, 8 enrichment (suggest-only).",
         "A", first("WEBHOUND_AI_KNOWLEDGE_LAYER_MASTER_PLAN.md"),
         ["WEBHOUND_AI_KNOWLEDGE_LAYER_MASTER_PLAN.md"]),
    ]
    out = []
    for mid, summary, tier, doc_ids, paths in mem:
        out.append({
            "memory_id": mid,
            "summary": summary,
            "authority_tier": tier,
            "related_manifest_doc_ids": doc_ids,
            "related_paths": paths,
            "review_status": "verified",
            "retention_class": "permanent" if "decision" in mid or mid == "known-false-positives" else "long",
            "created_at": INGEST_STAMP,
            "updated_at": INGEST_STAMP,
        })
    return out


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------
def _schema():
    return json.loads(_read(os.path.join(ROOT, "corpus", "manifests", "manifest.schema.json")))


def validate_records(records: list[dict]) -> list[str]:
    errs = []
    try:
        import jsonschema  # type: ignore
        schema = _schema()
        v = jsonschema.Draft202012Validator(schema)
        for r in records:
            for e in v.iter_errors(r):
                errs.append(f"{r['doc_id']}: {e.message}")
    except ImportError:
        # structural fallback: required keys present
        req = set(_schema().get("required", []))
        for r in records:
            miss = req - set(r)
            if miss:
                errs.append(f"{r['doc_id']}: missing {sorted(miss)}")
    return errs


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _write_jsonl(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def cmd_run(args) -> int:
    records, stats = build_records()
    errs = validate_records(records)
    chunks = build_chunks(records)
    memory = build_memory(records)
    # chunk integrity: every chunk maps to a known doc_id
    ids = {r["doc_id"] for r in records}
    orphan_chunks = [c["chunk_id"] for c in chunks if c["doc_id"] not in ids]
    # memory integrity: pointers exist
    bad_ptr = [m["memory_id"] for m in memory
               for p in m["related_paths"] if not os.path.exists(os.path.join(ROOT, p))]

    print(f"[inventory] documents={stats['documents']} by_tier={stats['by_tier']} "
          f"duplicate_groups={stats['duplicate_groups']}")
    print(f"[manifest]  records={len(records)} schema_errors={len(errs)}")
    print(f"[chunks]    chunks={len(chunks)} orphan_chunks={len(orphan_chunks)}")
    print(f"[memory]    entries={len(memory)} bad_pointers={len(bad_ptr)}")
    if errs:
        print("  SCHEMA ERRORS:")
        for e in errs[:10]:
            print("   -", e)

    if args.dry_run:
        print("[dry-run] nothing written.")
        return 1 if (errs or orphan_chunks or bad_ptr) else 0

    if errs or orphan_chunks or bad_ptr:
        print("[abort] integrity errors — refusing to write.")
        return 1

    _write_jsonl(MANIFEST_PATH, records)
    _write_jsonl(MEMORY_PATH, memory)
    # chunks + index -> ephemeral temp dir (NOT committed)
    os.makedirs(WORK_DIR, exist_ok=True)
    _write_jsonl(os.path.join(WORK_DIR, "chunks.jsonl"), chunks)
    print(f"[ok] wrote {os.path.relpath(MANIFEST_PATH, ROOT)} ({len(records)} records)")
    print(f"[ok] wrote {os.path.relpath(MEMORY_PATH, ROOT)} ({len(memory)} records)")
    print(f"[ok] wrote chunks -> {WORK_DIR}/chunks.jsonl (ephemeral, NOT committed)")
    return 0


TEST_QUERIES = [
    "What is WADE?",
    "What is the provider access framework?",
    "What scanner IPs are currently approved?",
    "What known false positives exist?",
    "What is the difference between corpus and knowledge?",
    "What is the current threat-intel architecture?",
]


def _chunks_now():
    records, _ = build_records()
    return build_chunks(records)


def cmd_query(args) -> int:
    chunks = _chunks_now()
    for hit in retrieve(chunks, args.text):
        print(f"  [{hit['score']:>3}] tier={hit['authority_tier']} {hit['source_path']}  «{hit['heading'][:60]}»")
    return 0


def cmd_selftest(args) -> int:
    chunks = _chunks_now()
    print(f"[selftest] {len(chunks)} chunks indexed (mock keyword retrieval)\n")
    for q in TEST_QUERIES:
        hits = retrieve(chunks, q, k=3)
        print(f"Q: {q}")
        if not hits:
            print("   (no match)")
        for h in hits:
            print(f"   [{h['score']:>3}] tier={h['authority_tier']} {h['source_path']}  «{h['heading'][:54]}»")
        print()
    return 0


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="Phase 5A internal ingestion pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run"); r.add_argument("--dry-run", action="store_true"); r.set_defaults(fn=cmd_run)
    q = sub.add_parser("query"); q.add_argument("text"); q.set_defaults(fn=cmd_query)
    s = sub.add_parser("selftest"); s.set_defaults(fn=cmd_selftest)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
