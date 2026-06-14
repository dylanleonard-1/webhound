"""Phase 8A: Prepare WebHound corpus for LightRAG ingestion.

Exports unified_chunks.jsonl → corpus/exports/lightrag/:
  lightrag_documents.jsonl  — one doc per chunk, LightRAG-compatible
  lightrag_metadata.json    — corpus-level stats and field mapping

Local-only. No cloud API calls. No LightRAG installation required to run.

Run: .venv-api/Scripts/python scripts/ai/lightrag_prepare_corpus.py
"""
from __future__ import annotations
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
CHUNKS_PATH = ROOT / "corpus" / "normalized" / "unified_chunks.jsonl"
OUT_DIR = ROOT / "corpus" / "exports" / "lightrag"
DOCS_OUT = OUT_DIR / "lightrag_documents.jsonl"
META_OUT = OUT_DIR / "lightrag_metadata.json"


def load_chunks() -> list[dict]:
    rows: list[dict] = []
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def to_lightrag_doc(chunk: dict, idx: int) -> dict:
    """Convert a WebHound chunk to LightRAG document format."""
    tags = chunk.get("topic_tags") or []
    return {
        "id": chunk.get("chunk_id", f"chunk-{idx}"),
        "doc_id": chunk.get("doc_id", ""),
        "content": chunk.get("text", ""),
        "metadata": {
            "title": chunk.get("title", ""),
            "source_type": chunk.get("source_type", ""),
            "authority_tier": chunk.get("authority_tier", "C"),
            "source_url": chunk.get("source_url", ""),
            "file_path": chunk.get("file_path", ""),
            "phase": chunk.get("phase", ""),
            "topic_tags": tags,
            "chunk_index": chunk.get("chunk_index", 0),
            "total_chunks": chunk.get("total_chunks", 1),
            "verification_status": chunk.get("verification_status", ""),
        },
    }


def build_metadata(chunks: list[dict], docs: list[dict], built_at: str) -> dict:
    phases = Counter(c.get("phase", "") for c in chunks)
    src_types = Counter(c.get("source_type", "") for c in chunks)
    tiers = Counter(c.get("authority_tier", "") for c in chunks)
    avg_len = (
        sum(len(c.get("content", "")) for c in docs) // len(docs) if docs else 0
    )
    return {
        "corpus_version": "phase-8a",
        "built_at": built_at,
        "source_file": str(CHUNKS_PATH.relative_to(ROOT)).replace("\\", "/"),
        "total_documents": len(docs),
        "total_source_chunks": len(chunks),
        "avg_content_length_chars": avg_len,
        "cloud_api_used": False,
        "local_only": True,
        "lightrag_format_version": "1.0",
        "field_mapping": {
            "id": "chunk_id — unique chunk identifier",
            "doc_id": "parent document id from manifest",
            "content": "full chunk text (300–1200 chars target)",
            "metadata.title": "document title",
            "metadata.source_type": "official_doc | internal_doc | reference",
            "metadata.authority_tier": "A (official) | B (curated) | C (reference)",
            "metadata.source_url": "canonical URL or file path",
            "metadata.file_path": "relative repo path for fragment matching",
            "metadata.phase": "ingestion phase (6A–8A)",
            "metadata.topic_tags": "list of classification tags",
        },
        "phase_distribution": dict(phases),
        "source_type_distribution": dict(src_types),
        "authority_tier_distribution": dict(tiers),
        "ingestion_notes": [
            "Content is pre-chunked at ## / ### section boundaries.",
            "Embeddings are NOT included here — use hybrid_retrieval.py for dense search.",
            "LightRAG should use this corpus for graph-enhanced retrieval over WebHound knowledge.",
            "Do NOT send to cloud LightRAG APIs without review — content may include internal docs.",
        ],
    }


def main() -> None:
    print("Loading chunks...")
    chunks = load_chunks()
    print(f"  {len(chunks)} chunks loaded")

    built_at = datetime.utcnow().isoformat() + "Z"
    docs = [to_lightrag_doc(c, i) for i, c in enumerate(chunks)]

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(DOCS_OUT, "w", encoding="utf-8") as f:
        for doc in docs:
            f.write(json.dumps(doc, ensure_ascii=False) + "\n")
    size_kb = DOCS_OUT.stat().st_size // 1024
    print(f"  Wrote {DOCS_OUT.relative_to(ROOT)} ({size_kb} KB, {len(docs)} docs)")

    meta = build_metadata(chunks, docs, built_at)
    with open(META_OUT, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print(f"  Wrote {META_OUT.relative_to(ROOT)}")

    print(f"\nLightRAG corpus summary:")
    print(f"  Documents: {len(docs)}")
    print(f"  Avg content length: {meta['avg_content_length_chars']} chars")
    print(f"  Phases: {meta['phase_distribution']}")
    print(f"  Cloud API: {meta['cloud_api_used']}")
    print("Done.")


if __name__ == "__main__":
    main()
