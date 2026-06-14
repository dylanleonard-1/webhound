"""Phase 7A: Hybrid lexical + dense retrieval over the unified chunk index.

Modes:
  lexical_only — TF-IDF BM25-style (no model needed)
  dense_only   — cosine similarity over L2-normalized embeddings
  hybrid       — weighted combination: 0.35 lexical + 0.65 dense (configurable)

Import: from scripts.ai.hybrid_retrieval import load_retriever
No cloud APIs. Requires corpus/indexes/dense/ artifacts for dense modes.
"""
from __future__ import annotations
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent.parent
CHUNKS_PATH = ROOT / "corpus" / "normalized" / "unified_chunks.jsonl"
INDEX_DIR = ROOT / "corpus" / "indexes" / "dense"
EMB_PATH = INDEX_DIR / "chunk_embeddings.npy"
META_PATH = INDEX_DIR / "chunk_embedding_meta.json"
CFG_PATH = INDEX_DIR / "dense_index_config.json"

DEFAULT_LEX_W = 0.35
DEFAULT_DENSE_W = 0.65
SNIPPET_LEN = 200


def _tok(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


class HybridRetriever:
    """Lexical + dense hybrid retriever over chunked knowledge base."""

    def __init__(
        self,
        chunks: list[dict],
        embeddings: "np.ndarray | None",
        meta: list[dict],
        model_name: str = "all-MiniLM-L6-v2",
        lexical_weight: float = DEFAULT_LEX_W,
        dense_weight: float = DEFAULT_DENSE_W,
    ) -> None:
        self.chunks = chunks
        self.embeddings = embeddings
        self.meta = meta
        self.model_name = model_name
        self.lex_w = lexical_weight
        self.dense_w = dense_weight
        self._model = None  # lazy-loaded on first dense call
        self._tf, self._df, self._n = self._build_lex_index()

    # ── Lexical index ─────────────────────────────────────────────────────────

    def _build_lex_index(self):
        tf: dict[int, Counter] = {}
        df: dict[str, int] = defaultdict(int)
        for i, c in enumerate(self.chunks):
            counts = Counter(_tok(c.get("text", "")))
            tf[i] = counts
            for t in counts:
                df[t] += 1
        return tf, df, len(self.chunks)

    def _lex_score(self, query: str, k: int) -> list[tuple[int, float]]:
        scores: dict[int, float] = {}
        for term in _tok(query):
            idf = math.log((self._n + 1) / (self._df.get(term, 0) + 1)) + 1
            for i, counts in self._tf.items():
                if term in counts:
                    scores[i] = scores.get(i, 0.0) + counts[term] * idf
        top = sorted(scores, key=lambda x: scores[x], reverse=True)[:k]
        return [(i, scores[i]) for i in top]

    # ── Dense retrieval ───────────────────────────────────────────────────────

    def _load_model(self) -> bool:
        if self._model is not None:
            return True
        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
            return True
        except ImportError:
            return False

    def _dense_score(self, query: str, k: int) -> list[tuple[int, float]]:
        if self.embeddings is None or not self._load_model():
            return []
        q_emb = self._model.encode(
            [query], normalize_embeddings=True, convert_to_numpy=True
        )[0]
        sims = (self.embeddings @ q_emb).tolist()
        top = sorted(range(len(sims)), key=lambda x: sims[x], reverse=True)[:k]
        return [(i, float(sims[i])) for i in top]

    # ── Score normalization ───────────────────────────────────────────────────

    @staticmethod
    def _norm(scored: list[tuple[int, float]]) -> dict[int, float]:
        if not scored:
            return {}
        max_s = max(s for _, s in scored)
        if max_s <= 0:
            return {i: 0.0 for i, _ in scored}
        return {i: s / max_s for i, s in scored}

    # ── Result assembly ───────────────────────────────────────────────────────

    def _make_result(
        self, rank: int, idx: int, lex_s: float, den_s: float, hyb_s: float, mode: str
    ) -> dict:
        c = self.chunks[idx]
        text = c.get("text", "")
        snippet = text[:SNIPPET_LEN].replace("\n", " ").strip()
        return {
            "rank": rank,
            "score": round(hyb_s, 4),
            "lexical_score": round(lex_s, 4),
            "dense_score": round(den_s, 4),
            "hybrid_score": round(hyb_s, 4),
            "chunk_id": c.get("chunk_id", ""),
            "doc_id": c.get("doc_id", ""),
            "title": c.get("title", ""),
            "source_type": c.get("source_type", ""),
            "authority_tier": c.get("authority_tier", ""),
            "source_url": c.get("source_url", ""),
            "file_path": c.get("file_path", ""),
            "phase": c.get("phase", ""),
            "snippet": snippet,
            "mode": mode,
        }

    # ── Public API ────────────────────────────────────────────────────────────

    def retrieve(self, query: str, k: int = 5, mode: str = "hybrid") -> list[dict]:
        k_cand = k * 4  # wider candidate pool for hybrid merging
        if mode == "lexical_only":
            lex = self._lex_score(query, k)
            lex_n = self._norm(lex)
            return [
                self._make_result(r + 1, i, lex_n[i], 0.0, lex_n[i], mode)
                for r, (i, _) in enumerate(lex)
            ]
        if mode == "dense_only":
            den = self._dense_score(query, k)
            den_n = self._norm(den)
            return [
                self._make_result(r + 1, i, 0.0, den_n[i], den_n[i], mode)
                for r, (i, _) in enumerate(den)
            ]
        # hybrid: lexical + dense, then re-rank
        lex = self._lex_score(query, k_cand)
        den = self._dense_score(query, k_cand)
        lex_n = self._norm(lex)
        den_n = self._norm(den)
        candidates = set(lex_n) | set(den_n)
        hyb = {
            i: self.lex_w * lex_n.get(i, 0.0) + self.dense_w * den_n.get(i, 0.0)
            for i in candidates
        }
        top = sorted(hyb, key=lambda x: hyb[x], reverse=True)[:k]
        return [
            self._make_result(
                r + 1, i, lex_n.get(i, 0.0), den_n.get(i, 0.0), hyb[i], "hybrid"
            )
            for r, i in enumerate(top)
        ]

    @property
    def dense_available(self) -> bool:
        return self.embeddings is not None and self._load_model()


# ── Factory ───────────────────────────────────────────────────────────────────

def load_retriever(
    lexical_weight: float = DEFAULT_LEX_W,
    dense_weight: float = DEFAULT_DENSE_W,
) -> HybridRetriever:
    chunks: list[dict] = []
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                chunks.append(json.loads(line))

    embeddings = None
    meta: list[dict] = []
    model_name = "all-MiniLM-L6-v2"

    if EMB_PATH.exists() and META_PATH.exists():
        embeddings = np.load(str(EMB_PATH))
        with open(META_PATH, encoding="utf-8") as f:
            meta = json.load(f)

    if CFG_PATH.exists():
        with open(CFG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
        model_name = cfg.get("model_name", model_name)

    return HybridRetriever(
        chunks=chunks,
        embeddings=embeddings,
        meta=meta,
        model_name=model_name,
        lexical_weight=lexical_weight,
        dense_weight=dense_weight,
    )


# ── CLI demo ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    query = " ".join(sys.argv[1:]) or "How does HSTS prevent downgrade attacks?"
    mode = "hybrid"
    print(f"Query: {query!r}  mode={mode}")
    r = load_retriever()
    results = r.retrieve(query, k=5, mode=mode)
    for res in results:
        print(f"  #{res['rank']} {res['score']:.4f} [{res['phase']}] "
              f"{res['title']} | lex={res['lexical_score']:.3f} den={res['dense_score']:.3f}")
        print(f"     {res['snippet'][:100]}")
