"""Phase 7A: Build dense embedding index from unified chunk index.

Output:
  corpus/indexes/dense/chunk_embeddings.npy      (~1.8 MB, safe to commit)
  corpus/indexes/dense/chunk_embedding_meta.json
  corpus/indexes/dense/dense_index_config.json

Run: .venv-api/Scripts/python scripts/ai/build_dense_index.py
LOCAL embeddings only — no cloud API calls. No scanner/WADE/production changes.
"""
from __future__ import annotations
import datetime
import hashlib
import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent.parent
CHUNKS_IN = ROOT / "corpus" / "normalized" / "unified_chunks.jsonl"
OUT_DIR = ROOT / "corpus" / "indexes" / "dense"

MODEL_NAME = "all-MiniLM-L6-v2"
BATCH_SIZE = 64


def load_chunks() -> list[dict]:
    rows: list[dict] = []
    with open(CHUNKS_IN, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def embed_chunks(texts: list[str], model) -> "np.ndarray":
    print(f"  Encoding {len(texts)} chunks (batch={BATCH_SIZE})...")
    return model.encode(
        texts,
        batch_size=BATCH_SIZE,
        show_progress_bar=True,
        normalize_embeddings=True,
        convert_to_numpy=True,
    )


def build_meta(chunks: list[dict], model_name: str, emb_dim: int) -> list[dict]:
    now = datetime.datetime.utcnow().isoformat() + "Z"
    meta: list[dict] = []
    for i, c in enumerate(chunks):
        content_hash = hashlib.sha256(c.get("text", "").encode()).hexdigest()[:16]
        meta.append({
            "idx": i,
            "chunk_id": c.get("chunk_id", ""),
            "doc_id": c.get("doc_id", ""),
            "source_type": c.get("source_type", ""),
            "authority_tier": c.get("authority_tier", "C"),
            "source_url": c.get("source_url", ""),
            "file_path": c.get("file_path", ""),
            "normalized_path": c.get("file_path", ""),
            "phase": c.get("phase", ""),
            "title": c.get("title", ""),
            "content_hash": content_hash,
            "embedding_model": model_name,
            "embedding_dim": emb_dim,
            "created_at": now,
        })
    return meta


def main() -> None:
    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("Installing sentence-transformers to dev env...")
        import subprocess, sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "sentence-transformers", "-q"])
        from sentence_transformers import SentenceTransformer

    print(f"Loading model '{MODEL_NAME}' (first run downloads ~90 MB)...")
    model = SentenceTransformer(MODEL_NAME)
    emb_dim = model.get_sentence_embedding_dimension()
    print(f"  Embedding dim: {emb_dim}")

    print("Loading chunks...")
    chunks = load_chunks()
    print(f"  {len(chunks)} chunks")

    texts = [c.get("text", "") for c in chunks]
    embeddings = embed_chunks(texts, model)
    print(f"  Embeddings shape: {embeddings.shape}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    npy_path = OUT_DIR / "chunk_embeddings.npy"
    np.save(str(npy_path), embeddings)
    size_kb = npy_path.stat().st_size // 1024
    print(f"  Saved {npy_path} ({size_kb} KB)")

    meta = build_meta(chunks, MODEL_NAME, emb_dim)
    meta_path = OUT_DIR / "chunk_embedding_meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(f"  Saved {meta_path}")

    config = {
        "model_name": MODEL_NAME,
        "model_full_path": f"sentence-transformers/{MODEL_NAME}",
        "embedding_dim": emb_dim,
        "chunk_count": len(chunks),
        "normalize_embeddings": True,
        "similarity_metric": "cosine_via_dot_product",
        "hybrid_lexical_weight": 0.35,
        "hybrid_dense_weight": 0.65,
        "chunks_source": str(CHUNKS_IN.relative_to(ROOT)).replace("\\", "/"),
        "built_at": datetime.datetime.utcnow().isoformat() + "Z",
        "local_only": True,
        "cloud_api_used": False,
        "faiss_used": False,
        "similarity_backend": "numpy_dot_product",
    }
    cfg_path = OUT_DIR / "dense_index_config.json"
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    print(f"  Saved {cfg_path}")

    print(f"\nIndex summary:")
    print(f"  Model: {MODEL_NAME} ({emb_dim}-dim)")
    print(f"  Chunks embedded: {len(chunks)}")
    print(f"  Embedding array: {embeddings.shape}, dtype={embeddings.dtype}")
    print(f"  Artifact size: {size_kb} KB ({size_kb//1024:.1f} MB)")
    print(f"  FAISS: NO (numpy dot-product is sufficient for {len(chunks)} chunks)")
    print("Done.")


if __name__ == "__main__":
    main()
