"""Phase CONTROL-2C/2D: verify concepts are discoverable from the CANONICAL index.

Modes (CONTROL-2D):
  --mode lexical   BM25-style, no embeddings/network (fresh-clone default)
  --mode dense     cosine over dense embeddings (needs build_dense_brain_embeddings.py)
  --mode hybrid    lexical + dense (best ranking)
  --require-dense  exit non-zero if dense embeddings are unavailable (no silent lexical)
  --json           emit machine-readable JSON only

Run: python scripts/ai/check_brain_traceability.py [--mode hybrid] [--json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from scripts.ai.hybrid_retrieval import load_retriever  # noqa: E402

# concept -> (query, expected-substring in a top hit's file_path)
CONCEPTS = [
    ("cookie_scanner", "cookie scanner security flags", "cookie_scanner"),
    ("domain_classifier", "domain classifier threat reputation", "domain_classifier"),
    ("tls_checker", "tls checker certificate", "tls_checker"),
    ("threat_intel", "threat intelligence feed", "threat_intel"),
    ("production WADE", "WADE baseline diff anomaly scorer", "webhound/wade"),
    ("advisory WADE", "WADE reasoning advisory shadow", "wade"),
    ("scanner orchestrator", "scanner orchestrator run scan engines", "orchestrator"),
    ("verification flow", "domain ownership verification check", "verif"),
    ("API authentication", "login auth token authentication", "auth"),
    ("report rendering", "report json render findings", "report"),
]


_MODE_MAP = {"lexical": "lexical_only", "dense": "dense_only", "hybrid": "hybrid"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=list(_MODE_MAP), default="lexical")
    ap.add_argument("--require-dense", action="store_true",
                    help="fail if dense embeddings are unavailable (no silent lexical fallback)")
    ap.add_argument("--json", action="store_true", help="machine-readable JSON only")
    args = ap.parse_args()

    r = load_retriever()
    retr_mode = _MODE_MAP[args.mode]
    dense_ok = r.dense_available

    if args.mode in ("dense", "hybrid") and not dense_ok:
        msg = ("dense embeddings unavailable — build them with "
               "`python scripts/ai/build_dense_brain_embeddings.py` "
               "(needs sentence-transformers).")
        if args.require_dense:
            print(f"ERROR: {msg}", file=sys.stderr)
            return 2
        print(f"WARNING: {msg} Falling back to lexical for this run.", file=sys.stderr)
        retr_mode = "lexical_only"

    results = []
    for name, query, expect in CONCEPTS:
        hits = r.retrieve(query, k=8, mode=retr_mode)
        paths = [h.get("file_path", "").lower() for h in hits]
        exact_top = bool(paths) and expect in paths[0]
        any_hit = any(expect in p for p in paths)
        verdict = "PASS" if exact_top else ("PARTIAL" if any_hit else "FAIL")
        results.append((name, verdict, paths[0] if paths else "(none)"))

    counts = {v: sum(1 for _, vv, _ in results if vv == v) for v in ("PASS", "PARTIAL", "FAIL")}
    payload = {
        "requested_mode": args.mode, "effective_mode": retr_mode,
        "dense_available": dense_ok, "index_chunks": len(r.chunks),
        "counts": counts,
        "results": [{"concept": n, "verdict": v, "top": t} for n, v, t in results],
    }
    if args.json:
        print(json.dumps(payload))
        return 0
    print(f"index chunks: {len(r.chunks)} | mode={args.mode} (effective={retr_mode}) "
          f"| dense_available={dense_ok}\n")
    for n, v, t in results:
        print(f"  {n:22s} {v:8s} top={t[:60]}")
    print(f"\nPASS={counts['PASS']} PARTIAL={counts['PARTIAL']} FAIL={counts['FAIL']} / {len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
