"""Phase 7A: Validate dense index artifacts and embedding integrity.

Structural tests (file existence, metadata count, embedding shape) run
unconditionally in CI. Tests that need the sentence_transformers library skip
gracefully when it is absent.
Run: .venv-api/Scripts/python -m pytest tests/ai -q
"""
from __future__ import annotations
import json
import os
import sys

import numpy as np
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)

INDEX_DIR = os.path.join(ROOT, "corpus", "indexes", "dense")
EMB_PATH = os.path.join(INDEX_DIR, "chunk_embeddings.npy")
META_PATH = os.path.join(INDEX_DIR, "chunk_embedding_meta.json")
CFG_PATH = os.path.join(INDEX_DIR, "dense_index_config.json")
CHUNKS_PATH = os.path.join(ROOT, "corpus", "normalized", "unified_chunks.jsonl")

try:
    import sentence_transformers as _st  # noqa: F401
    _HAS_ST = True
except ImportError:
    _HAS_ST = False


# ── Artifact existence ─────────────────────────────────────────────────────────

def test_dense_index_dir_exists():
    assert os.path.isdir(INDEX_DIR), f"Dense index dir missing: {INDEX_DIR}"


def test_embeddings_npy_exists():
    assert os.path.isfile(EMB_PATH), "chunk_embeddings.npy not found"


def test_embedding_meta_exists():
    assert os.path.isfile(META_PATH), "chunk_embedding_meta.json not found"


def test_dense_config_exists():
    assert os.path.isfile(CFG_PATH), "dense_index_config.json not found"


# ── Config schema ──────────────────────────────────────────────────────────────

def test_config_schema():
    with open(CFG_PATH, encoding="utf-8") as f:
        cfg = json.load(f)
    for field in ["model_name", "embedding_dim", "chunk_count"]:
        assert field in cfg, f"Config missing field {field!r}"
    assert cfg.get("cloud_api_used") is False, "cloud_api_used must be False"
    assert cfg.get("local_only") is True, "local_only must be True"


def test_config_no_cloud_keys():
    with open(CFG_PATH, encoding="utf-8") as f:
        text = f.read().lower()
    for bad in ["openai", "anthropic", "cohere", "api_key", "sk-"]:
        assert bad not in text, f"Config must not reference cloud service: {bad!r}"


def test_config_chunk_count_matches_actual():
    with open(CFG_PATH, encoding="utf-8") as f:
        cfg = json.load(f)
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        chunk_n = sum(1 for l in f if l.strip())
    assert cfg["chunk_count"] == chunk_n, (
        f"Config chunk_count {cfg['chunk_count']} != actual {chunk_n}"
    )


# ── Embedding integrity ────────────────────────────────────────────────────────

def test_embedding_shape():
    emb = np.load(EMB_PATH)
    assert emb.ndim == 2, "Embeddings must be 2D array"
    assert emb.shape[1] == 384, f"Expected 384 dims (all-MiniLM-L6-v2), got {emb.shape[1]}"
    assert emb.shape[0] > 0, "Embedding array must not be empty"


def test_embedding_count_matches_chunks():
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        chunk_n = sum(1 for l in f if l.strip())
    emb = np.load(EMB_PATH)
    assert emb.shape[0] == chunk_n, (
        f"Embedding rows {emb.shape[0]} != chunk count {chunk_n}"
    )


def test_embedding_count_matches_meta():
    with open(META_PATH, encoding="utf-8") as f:
        meta = json.load(f)
    emb = np.load(EMB_PATH)
    assert len(meta) == emb.shape[0], (
        f"Meta entries {len(meta)} != embedding rows {emb.shape[0]}"
    )


def test_no_orphan_embeddings():
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        chunk_ids = {json.loads(l)["chunk_id"] for l in f if l.strip()}
    with open(META_PATH, encoding="utf-8") as f:
        meta = json.load(f)
    orphans = [m["chunk_id"] for m in meta if m["chunk_id"] not in chunk_ids]
    assert not orphans, f"Orphan embeddings (not in chunks.jsonl): {orphans[:5]}"


def test_meta_provenance_fields():
    with open(META_PATH, encoding="utf-8") as f:
        meta = json.load(f)
    required = ["idx", "chunk_id", "doc_id", "source_type", "authority_tier",
                "embedding_model", "embedding_dim", "content_hash", "created_at"]
    for m in meta[:5]:
        for field in required:
            assert field in m, f"Meta entry missing field {field!r}"


def test_embeddings_l2_normalized():
    emb = np.load(EMB_PATH)
    norms = np.linalg.norm(emb[:100], axis=1)  # check first 100 rows
    assert np.allclose(norms, 1.0, atol=1e-4), "Embeddings are not L2-normalized"


# ── Dense retrieval functional (needs sentence_transformers) ───────────────────

@pytest.mark.skipif(not _HAS_ST, reason="sentence_transformers not installed — CI skip")
def test_dense_retrieval_returns_results():
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    assert r.embeddings is not None, "Embeddings must load when .npy exists"
    results = r.retrieve("What is HSTS strict transport security?", k=3, mode="dense_only")
    assert len(results) > 0, "Dense retrieval returned no results"
    assert results[0]["dense_score"] > 0


@pytest.mark.skipif(not _HAS_ST, reason="sentence_transformers not installed — CI skip")
def test_dense_result_has_provenance():
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = r.retrieve("XSS cross-site scripting reflected stored", k=3, mode="dense_only")
    for res in results:
        for field in ["chunk_id", "doc_id", "title", "source_type", "authority_tier",
                      "file_path", "phase", "snippet", "dense_score"]:
            assert field in res, f"Result missing field {field!r}"
