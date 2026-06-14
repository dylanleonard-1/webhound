"""Phase 8C: LightRAG vs Hybrid Retrieval benchmark.

Compares LightRAG naive mode (local vector search) against the existing
hybrid retrieval system on 5 representative WADE queries.

Metrics: retrieval speed, result count, source attribution, first-hit quality.

NO cloud APIs. Advisory only.

Run: .venv-api/Scripts/python scripts/ai/test_lightrag_queries.py
"""
from __future__ import annotations
import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
LIGHTRAG_DIR = ROOT / "lightrag_storage"
BENCH_OUT = ROOT / "docs" / "ai" / "LIGHTRAG_BENCHMARK.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BENCHMARK_QUERIES = [
    {
        "id": "csp",
        "query": "Content Security Policy CSP missing header browser protection XSS",
        "expect_keywords": ["csp", "content-security", "header"],
    },
    {
        "id": "cloudflare",
        "query": "Cloudflare WAF challenge page 1020 block bot protection",
        "expect_keywords": ["cloudflare", "waf", "challenge"],
    },
    {
        "id": "threat_intel",
        "query": "threat intelligence AbuseIPDB GreyNoise IP reputation classification",
        "expect_keywords": ["threat", "abuseipdb", "greynoise", "ip"],
    },
    {
        "id": "exposed_env",
        "query": "exposed .env environment file secrets credentials disclosure",
        "expect_keywords": ["env", "secret", "credential", "exposure"],
    },
    {
        "id": "provider_blocked",
        "query": "provider blocked scan WAF CDN false positive scanner access denied",
        "expect_keywords": ["waf", "cdn", "block", "scan"],
    },
]


# ── Hybrid retrieval benchmark ────────────────────────────────────────────────

def run_hybrid_benchmarks() -> list[dict]:
    from scripts.ai.hybrid_retrieval import load_retriever
    r = load_retriever()
    results = []
    for bq in BENCHMARK_QUERIES:
        t0 = time.perf_counter()
        hits = r.retrieve(bq["query"], k=5, mode="lexical_only")
        elapsed = time.perf_counter() - t0
        all_text = " ".join(
            h.get("snippet", "") + " " + h.get("title", "") for h in hits
        ).lower()
        kw_hits = [kw for kw in bq["expect_keywords"] if kw in all_text]
        results.append({
            "id": bq["id"],
            "system": "hybrid_retrieval",
            "mode": "lexical_only",
            "elapsed_s": round(elapsed, 4),
            "hit_count": len(hits),
            "top_score": round(hits[0]["score"], 4) if hits else 0.0,
            "top_title": hits[0]["title"] if hits else "",
            "top_authority_tier": hits[0]["authority_tier"] if hits else "",
            "keyword_hits": kw_hits,
            "keyword_recall": round(len(kw_hits) / len(bq["expect_keywords"]), 2),
        })
    return results


# ── LightRAG benchmark ────────────────────────────────────────────────────────

async def _lightrag_bench() -> list[dict]:
    if not LIGHTRAG_DIR.exists():
        return [{"error": "lightrag_storage not found — run build_lightrag_index.py first"}]
    try:
        from lightrag import LightRAG, QueryParam
        from lightrag.utils import EmbeddingFunc
    except ImportError:
        return [{"error": "lightrag-hku not installed"}]

    from sentence_transformers import SentenceTransformer
    _m = SentenceTransformer("all-MiniLM-L6-v2")

    class _Emb:
        embedding_dim = 384
        max_token_size = 256
        async def __call__(self, texts):
            import numpy as np
            vecs = _m.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
            return np.array(vecs)

    async def _stub(prompt, **kw):
        return '{"entities":[],"relationships":[]}'

    emb = _Emb()
    wrapped = EmbeddingFunc(embedding_dim=384, max_token_size=256, func=emb)
    rag = LightRAG(
        working_dir=str(LIGHTRAG_DIR),
        llm_model_func=_stub,
        embedding_func=wrapped,
    )
    await rag.initialize_storages()

    results = []
    for bq in BENCHMARK_QUERIES:
        t0 = time.perf_counter()
        try:
            response = await rag.aquery(bq["query"], param=QueryParam(mode="naive"))
            elapsed = time.perf_counter() - t0
            text_l = response.lower() if response else ""
            kw_hits = [kw for kw in bq["expect_keywords"] if kw in text_l]
            results.append({
                "id": bq["id"],
                "system": "lightrag",
                "mode": "naive",
                "elapsed_s": round(elapsed, 4),
                "result_len": len(response) if response else 0,
                "keyword_hits": kw_hits,
                "keyword_recall": round(len(kw_hits) / len(bq["expect_keywords"]), 2),
                "error": None,
            })
        except Exception as e:
            elapsed = time.perf_counter() - t0
            results.append({
                "id": bq["id"],
                "system": "lightrag",
                "mode": "naive",
                "elapsed_s": round(elapsed, 4),
                "result_len": 0,
                "keyword_hits": [],
                "keyword_recall": 0.0,
                "error": str(e)[:200],
            })
    return results


def run_lightrag_benchmarks() -> list[dict]:
    return asyncio.run(_lightrag_bench())


# ── Comparison table ──────────────────────────────────────────────────────────

def print_comparison(hybrid: list[dict], lr: list[dict]) -> None:
    lr_by_id = {r["id"]: r for r in lr}
    print("\n" + "=" * 72)
    print(f"{'Query':<20} {'System':<20} {'Speed':>8} {'KW Recall':>10} {'Notes'}")
    print("-" * 72)
    for h in hybrid:
        l = lr_by_id.get(h["id"], {})
        lr_speed = f"{l.get('elapsed_s', '?')}s" if l else "N/A"
        lr_recall = l.get("keyword_recall", "?") if l else "?"
        lr_err = l.get("error") if l else None
        lr_note = "error: " + str(lr_err)[:30] if lr_err else "ok"
        print(f"  {h['id']:<18} hybrid-retrieval  {h['elapsed_s']:>7}s {h['keyword_recall']:>10.2f} tier={h['top_authority_tier']}")
        print(f"  {'':18} lightrag-naive   {lr_speed:>8} {lr_recall!s:>10} {lr_note}")
        print()
    print("=" * 72)


def main() -> None:
    print("Running hybrid retrieval benchmarks...")
    hybrid = run_hybrid_benchmarks()

    lr_available = LIGHTRAG_DIR.exists()
    if lr_available:
        print("Running LightRAG benchmarks (naive mode, local embeddings)...")
        lr = run_lightrag_benchmarks()
    else:
        print("LightRAG storage not found — skipping LightRAG benchmarks.")
        print("Run build_lightrag_index.py first.")
        lr = []

    print_comparison(hybrid, lr)

    out = {
        "hybrid_results": hybrid,
        "lightrag_results": lr,
        "lightrag_available": lr_available,
        "lightrag_mode": "naive (vector-only, graph extraction skipped — no LLM)",
        "embedding_model": "all-MiniLM-L6-v2 (local)",
        "cloud_api_used": False,
        "note": (
            "LightRAG graph/entity extraction skipped due to no local LLM. "
            "Naive mode = pure vector retrieval. "
            "Hybrid Retrieval uses lexical_only mode for reproducibility."
        ),
    }
    BENCH_OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nWrote {BENCH_OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
