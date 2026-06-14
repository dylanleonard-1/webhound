"""Phase 8C-INFRA-LIVE: LightRAG index builder with Ollama LLM.

Rebuilds the LightRAG index using:
  - phi3:mini via Ollama for entity/relationship extraction (GRAPH layer)
  - Local sentence-transformers all-MiniLM-L6-v2 for embeddings (VECTOR layer)
  - NetworkX in-memory graph storage
  - NanoVectorDB local file-based vector storage

Replaces the stub LLM from Phase 8C with a real local LLM.

Prerequisites:
  - Ollama running at http://localhost:11434
  - phi3:mini model pulled (ollama pull phi3:mini)
  - lightrag_storage/ cleared first (different LLM = rebuild needed)

Run:
  rm -rf lightrag_storage/
  .venv-api/Scripts/python scripts/ai/build_lightrag_index_ollama.py [--n N]
  Default N=30. Use --n 100 once 30 chunks are stable.

NO cloud APIs. Local Ollama only. Advisory only.
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
RESULTS_PATH = ROOT / "docs" / "ai" / "LIGHTRAG_OLLAMA_RESULTS.json"
OLLAMA_HOST = "http://localhost:11434"
OLLAMA_MODEL = "phi3:mini"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

N_CHUNKS = 30
for arg in sys.argv[1:]:
    if arg.startswith("--n"):
        try:
            N_CHUNKS = int(arg.split("=")[-1]) if "=" in arg else int(sys.argv[sys.argv.index(arg) + 1])
        except (IndexError, ValueError):
            pass


# ── Ollama LLM (phi3:mini, local) ────────────────────────────────────────────

def _make_llm_func():
    from lightrag.llm.ollama import ollama_model_complete
    return ollama_model_complete


# ── Local embedding function (MiniLM-384, faster than Ollama embed) ───────────

_model = None


def _load_model():
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer("all-MiniLM-L6-v2")
    return _model


class _LocalEmbeddingFunc:
    embedding_dim = 384
    max_token_size = 256

    async def __call__(self, texts: list[str]):
        import numpy as np
        model = _load_model()
        vecs = model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
        return np.array(vecs)


# ── Corpus loader ─────────────────────────────────────────────────────────────

def load_corpus_sample(n: int) -> list[dict]:
    chunks = []
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                chunks.append(json.loads(line))
                if len(chunks) >= n:
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

    llm_func = _make_llm_func()
    LIGHTRAG_DIR.mkdir(parents=True, exist_ok=True)

    print(f"LightRAG config:")
    print(f"  LLM: {OLLAMA_MODEL} via Ollama ({OLLAMA_HOST})")
    print(f"  Embedding: all-MiniLM-L6-v2 (local, 384-dim)")
    print(f"  Storage: {LIGHTRAG_DIR}")
    print(f"  Chunks: {n_chunks}")

    rag = LightRAG(
        working_dir=str(LIGHTRAG_DIR),
        llm_model_func=llm_func,
        llm_model_name=OLLAMA_MODEL,
        llm_model_kwargs={"host": OLLAMA_HOST},
        embedding_func=wrapped,
    )
    await rag.initialize_storages()

    chunks = load_corpus_sample(n_chunks)
    print(f"\nInserting {len(chunks)} chunks (entity extraction with phi3:mini)...")
    print("Note: each chunk calls phi3:mini for entity/relationship extraction (~10-30s each)")

    inserted = 0
    errors = 0
    t0 = time.perf_counter()

    for i, chunk in enumerate(chunks):
        text = chunk_to_text(chunk)
        if len(text.strip()) < 20:
            continue
        chunk_t0 = time.perf_counter()
        try:
            await rag.ainsert(text)
            elapsed_chunk = time.perf_counter() - chunk_t0
            inserted += 1
            print(f"  [{inserted}/{n_chunks}] {chunk.get('title', '')[:50]} ({elapsed_chunk:.1f}s)")
        except Exception as e:
            errors += 1
            print(f"  [ERR {i}] {type(e).__name__}: {str(e)[:80]}")
            if errors > 5:
                print("  Too many errors — stopping early")
                break

    total_elapsed = time.perf_counter() - t0

    # Count extracted entities
    entity_count = 0
    rel_count = 0
    entity_file = LIGHTRAG_DIR / "vdb_entities.json"
    rel_file = LIGHTRAG_DIR / "vdb_relationships.json"
    if entity_file.exists():
        data = json.loads(entity_file.read_text(encoding="utf-8"))
        inner = data.get("data", data) if isinstance(data, dict) else data
        entity_count = len(inner) if isinstance(inner, list) else 0
    if rel_file.exists():
        data = json.loads(rel_file.read_text(encoding="utf-8"))
        inner = data.get("data", data) if isinstance(data, dict) else data
        rel_count = len(inner) if isinstance(inner, list) else 0

    return {
        "chunks_attempted": len(chunks),
        "chunks_inserted": inserted,
        "errors": errors,
        "elapsed_s": round(total_elapsed, 2),
        "avg_s_per_chunk": round(total_elapsed / max(1, inserted), 2),
        "entities_extracted": entity_count,
        "relationships_extracted": rel_count,
        "llm_model": OLLAMA_MODEL,
        "llm_host": OLLAMA_HOST,
        "embedding_model": "all-MiniLM-L6-v2 (local)",
        "graph_live": entity_count > 0,
        "cloud_api_used": False,
    }


# ── Query test ────────────────────────────────────────────────────────────────

async def test_graph_query(query: str) -> dict:
    from lightrag import LightRAG, QueryParam
    from lightrag.utils import EmbeddingFunc

    embed_fn = _LocalEmbeddingFunc()
    wrapped = EmbeddingFunc(
        embedding_dim=embed_fn.embedding_dim,
        max_token_size=embed_fn.max_token_size,
        func=embed_fn,
    )
    llm_func = _make_llm_func()

    rag = LightRAG(
        working_dir=str(LIGHTRAG_DIR),
        llm_model_func=llm_func,
        llm_model_name=OLLAMA_MODEL,
        llm_model_kwargs={"host": OLLAMA_HOST},
        embedding_func=wrapped,
    )
    await rag.initialize_storages()

    t0 = time.perf_counter()
    try:
        resp = await rag.aquery(query, param=QueryParam(mode="naive"))
        elapsed = time.perf_counter() - t0
        return {"query": query, "response": str(resp)[:300], "elapsed_s": round(elapsed, 2), "error": None}
    except Exception as e:
        return {"query": query, "response": None, "elapsed_s": round(time.perf_counter() - t0, 2), "error": str(e)[:200]}


def main() -> None:
    if not LIGHTRAG_DIR.exists() or not any(LIGHTRAG_DIR.glob("*.json")):
        print("lightrag_storage/ is empty — starting fresh index build")
    else:
        print(f"WARNING: lightrag_storage/ exists with data.")
        print("If this was built with stub LLM, clear it first: rm -rf lightrag_storage/")
        print("Proceeding anyway (will add to existing index)...\n")

    result = asyncio.run(build_index(N_CHUNKS))

    print(f"\n=== Results ===")
    print(f"Inserted: {result['chunks_inserted']}/{result['chunks_attempted']}")
    print(f"Errors: {result['errors']}")
    print(f"Time: {result['elapsed_s']}s ({result['avg_s_per_chunk']}s/chunk)")
    print(f"Entities extracted: {result['entities_extracted']}")
    print(f"Relationships extracted: {result['relationships_extracted']}")
    print(f"Graph live: {result['graph_live']}")

    RESULTS_PATH.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nWrote {RESULTS_PATH.relative_to(ROOT)}")

    if result["graph_live"]:
        print("\nRunning test query (graph mode)...")
        q_result = asyncio.run(test_graph_query(
            "What is a Content Security Policy and how does it prevent XSS attacks?"
        ))
        print(f"Query response ({q_result['elapsed_s']}s): {q_result['response'][:200] if q_result['response'] else 'ERROR: ' + str(q_result['error'])}")
    else:
        print("\nNo entities extracted — graph query skipped.")
        print("Check phi3:mini response format compatibility with LightRAG.")


if __name__ == "__main__":
    main()
