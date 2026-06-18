"""Phase CONTROL-2C: verify concepts are discoverable from the CANONICAL index.

Uses lexical retrieval (no embeddings, no Ollama, no network) so it runs on a
fresh clone after `build_canonical_brain_index.py`. Prints PASS/PARTIAL/FAIL.

Run: python scripts/ai/check_brain_traceability.py
"""
from __future__ import annotations

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


def main() -> None:
    r = load_retriever()
    print(f"index chunks: {len(r.chunks)}\n")
    results = []
    for name, query, expect in CONCEPTS:
        hits = r.retrieve(query, k=8, mode="lexical_only")
        paths = [h.get("file_path", "").lower() for h in hits]
        exact_top = bool(paths) and expect in paths[0]
        any_hit = any(expect in p for p in paths)
        verdict = "PASS" if exact_top else ("PARTIAL" if any_hit else "FAIL")
        top = paths[0] if paths else "(none)"
        results.append((name, verdict, top))
        print(f"  {name:22s} {verdict:8s} top={top[:60]}")
    p = sum(1 for _, v, _ in results if v == "PASS")
    pa = sum(1 for _, v, _ in results if v == "PARTIAL")
    fa = sum(1 for _, v, _ in results if v == "FAIL")
    print(f"\nPASS={p} PARTIAL={pa} FAIL={fa} / {len(results)}")
    print(json.dumps([{"concept": n, "verdict": v} for n, v, _ in results]))


if __name__ == "__main__":
    main()
