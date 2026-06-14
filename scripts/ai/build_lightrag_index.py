"""Phase 8C: LightRAG local index builder.

Configures LightRAG with:
  - Local MiniLM embeddings (sentence_transformers, same as Phase 7A)
  - Stub LLM function (returns empty entities — graph extraction skipped)
  - NetworkX graph storage (no Neo4j needed)
  - NanoVectorDB vector storage (local file-based)

This builds the VECTOR/EMBEDDING layer of LightRAG fully.
The GRAPH/ENTITY extraction layer is documented as pending local LLM.

NO cloud APIs are used. NO customer data. Advisory only.

Run: .venv-api/Scripts/python scripts/ai/build_lightrag_index.py [--sample N]
"""
from __future__ import annotations
import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
LIGHTRAG_DIR = ROOT / "lightrag_storage"
CHUNKS_PATH = ROOT / "corpus" / "normalized" / "unified_chunks.jsonl"
RESULTS_PATH = ROOT / "docs" / "ai" / "LIGHTRAG_INDEX_RESULTS.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── Stub LLM (no cloud, no local LLM) ────────────────────────────────────────

async def _stub_llm(prompt: str, **kwargs) -> str:
    """Stub LLM: logs that LLM is unavailable; returns empty entity JSON.

    LightRAG calls this to extract entities/relations from text.
    Without a real LLM, the graph layer is a no-op — only the vector
    storage is populated.
    """
    # Return minimal valid entity extraction response
    return '{"entities": [], "relationships": []}'


# ── Local embedding function (MiniLM) ────────────────────────────────────────

_model = None

def _load_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


class _LocalEmbeddingFunc:
    """Wraps MiniLM for LightRAG's EmbeddingFunc protocol."""
    embedding_dim = 384
    max_token_size = 256

    async def __call__(self, texts: list[str]):
        import numpy as np
        model = _load_model()
        vecs = model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
        return np.array(vecs)


# ── Corpus loader ─────────────────────────────────────────────────────────────

def load_corpus_sample(n: int = 100) -> list[dict]:
    chunks = []
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                chunks.append(json.loads(line))
                if n and len(chunks) >= n:
                    break
    return chunks


def chunk_to_text(chunk: dict) -> str:
    title = chunk.get("title", "")
    text = chunk.get("text", "")
    source_type = chunk.get("source_type", "")
    phase = chunk.get("phase", "")
    return f"[{source_type}/{phase}] {title}\n\n{text}".strip()


# ── Index builder ─────────────────────────────────────────────────────────────

async def build_index(n_chunks: int) -> dict:
    from lightrag import LightRAG
    from lightrag.utils import EmbeddingFunc

    embed_fn = _LocalEmbeddingFunc()
    wrapped = EmbeddingFunc(
        embedding_dim=embed_fn.embedding_dim,
        max_token_size=embed_fn.max_token_size,
        func=embed_fn,
    )

    LIGHTRAG_DIR.mkdir(parents=True, exist_ok=True)

    rag = LightRAG(
        working_dir=str(LIGHTRAG_DIR),
        llm_model_func=_stub_llm,
        embedding_func=wrapped,
    )
    await rag.initialize_storages()

    chunks = load_corpus_sample(n_chunks)
    print(f"Inserting {len(chunks)} chunks into LightRAG vector store...")

    inserted = 0
    errors = 0
    t0 = time.perf_counter()
    for i, chunk in enumerate(chunks):
        text = chunk_to_text(chunk)
        if len(text.strip()) < 20:
            continue
        try:
            await rag.ainsert(text)
            inserted += 1
            if (i + 1) % 20 == 0:
                print(f"  {i+1}/{len(chunks)} ...")
        except Exception as e:
            errors += 1
            if errors <= 3:
                print(f"  [warn] chunk {i}: {e}")

    elapsed = time.perf_counter() - t0
    return {
        "chunks_attempted": len(chunks),
        "chunks_inserted": inserted,
        "errors": errors,
        "elapsed_s": round(elapsed, 2),
        "lightrag_dir": str(LIGHTRAG_DIR),
        "embedding_model": "all-MiniLM-L6-v2",
        "llm_status": "stub (no-op) — graph extraction skipped, vector layer built",
        "cloud_api_used": False,
        "graph_status": "NetworkX in-memory, entities empty (LLM unavailable)",
        "vector_status": "NanoVectorDB local file store — populated",
    }


# ── Query test ────────────────────────────────────────────────────────────────

async def test_query(query: str) -> dict:
    from lightrag import LightRAG, QueryParam
    from lightrag.utils import EmbeddingFunc

    embed_fn = _LocalEmbeddingFunc()
    wrapped = EmbeddingFunc(
        embedding_dim=embed_fn.embedding_dim,
        max_token_size=embed_fn.max_token_size,
        func=embed_fn,
    )
    rag = LightRAG(
        working_dir=str(LIGHTRAG_DIR),
        llm_model_func=_stub_llm,
        embedding_func=wrapped,
    )
    await rag.initialize_storages()

    t0 = time.perf_counter()
    try:
        result = await rag.aquery(query, param=QueryParam(mode="naive"))
        elapsed = time.perf_counter() - t0
        return {"query": query, "result_len": len(result), "elapsed_s": round(elapsed, 3), "error": None}
    except Exception as e:
        elapsed = time.perf_counter() - t0
        return {"query": query, "result_len": 0, "elapsed_s": round(elapsed, 3), "error": str(e)[:200]}


async def _main_async(n: int) -> None:
    result = await build_index(n)
    print(f"\nIndex built: {result}")

    # Test a few queries
    test_queries = [
        "Content Security Policy CSP missing header",
        "Cloudflare WAF challenge page 1020",
        "exposed .env environment file secrets",
    ]
    query_results = []
    for q in test_queries:
        r = await test_query(q)
        query_results.append(r)
        status = "ok" if not r["error"] else "error"
        print(f"  [{status}] {q!r} → {r['result_len']} chars ({r['elapsed_s']}s)")

    result["sample_queries"] = query_results
    RESULTS_PATH.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nWrote {RESULTS_PATH.relative_to(ROOT)}")


def main() -> None:
    n = 100
    for arg in sys.argv[1:]:
        if arg.startswith("--sample"):
            parts = arg.split("=")
            n = int(parts[1]) if len(parts) > 1 else int(sys.argv[sys.argv.index(arg) + 1])
    print(f"LightRAG index build — sample={n} chunks, local embeddings, stub LLM")
    asyncio.run(_main_async(n))


if __name__ == "__main__":
    main()
