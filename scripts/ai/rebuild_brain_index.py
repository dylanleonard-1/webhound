"""Phase CONTROL-2B: rebuild the hybrid retrieval index over docs + production code.

Embeds the combined chunk set (corpus docs + production_code_chunks) with the
same local all-MiniLM-L6-v2 model and runs retrieval smoke tests. Writes to a
SEPARATE build-artifact dir so the committed dense index is untouched.

Build artifacts (NOT committed): corpus/indexes/dense_with_code/
Run: .venv-api/Scripts/python scripts/ai/rebuild_brain_index.py
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent.parent
COMBINED = ROOT / "corpus" / "normalized" / "unified_chunks_with_code.jsonl"
OUT = ROOT / "corpus" / "indexes" / "dense_with_code"
MODEL_NAME = "all-MiniLM-L6-v2"

TESTS = ["cookie_scanner", "domain_classifier", "tls_checker", "threat_intel",
         "WADE", "Scanner Orchestrator", "Verification Flow", "API Authentication"]


def main() -> None:
    from sentence_transformers import SentenceTransformer
    rows = [json.loads(l) for l in open(COMBINED, encoding="utf-8") if l.strip()]
    texts = [r.get("text", "") for r in rows]
    n_code = sum(1 for r in rows if r.get("source_type") == "production_code")
    print(f"chunks: {len(rows)} (code={n_code}, doc={len(rows)-n_code})")

    model = SentenceTransformer(MODEL_NAME)
    emb = model.encode(texts, batch_size=64, normalize_embeddings=True,
                       convert_to_numpy=True, show_progress_bar=False)
    OUT.mkdir(parents=True, exist_ok=True)
    np.save(str(OUT / "chunk_embeddings.npy"), emb)
    json.dump({"chunk_count": len(rows), "code_chunks": n_code, "model": MODEL_NAME,
               "dim": int(emb.shape[1])}, open(OUT / "config.json", "w"), indent=2)

    print("\n=== retrieval smoke tests (top-1 hit per concept) ===")
    results = {}
    for q in TESTS:
        qe = model.encode([q], normalize_embeddings=True, convert_to_numpy=True)[0]
        scores = emb @ qe
        top = int(np.argmax(scores))
        r = rows[top]
        hit_code = r.get("source_type") == "production_code"
        results[q] = {"score": round(float(scores[top]), 3),
                      "file": r.get("file_path", ""), "is_code": hit_code}
        print(f"  {q:22s} score={scores[top]:.3f} {'[CODE]' if hit_code else '[DOC] '} {r.get('file_path','')[:60]}")
    json.dump(results, open(OUT / "retrieval_smoke.json", "w"), indent=2)
    print(f"\nartifacts -> {OUT.relative_to(ROOT)}/ (not committed)")


if __name__ == "__main__":
    main()
