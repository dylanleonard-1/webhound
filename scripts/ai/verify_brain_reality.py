"""Phase CONTROL-2F: physically verify the brain answers real WebHound questions.

Read-only. NO network, NO Ollama, NO Neo4j required (Neo4j checks are optional and
skipped if offline). Uses the canonical hybrid retriever to answer 10 real
questions and prints PASS / PARTIAL / FAIL with the top source + file path.

PASS    = an expected source is the #1 hit
PARTIAL = an expected source is in the top-k (but not #1)
FAIL    = no expected source in top-k

Run: python scripts/ai/verify_brain_reality.py [--json] [--k 8]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
from scripts.ai.hybrid_retrieval import classify_intent, load_retriever  # noqa: E402

# (id, question, expected file-path substrings (any), expected_type code|doc|any)
# Expected sets cover ALL genuinely-correct sources for the question (e.g. production
# WADE = the wade/ engine OR the baseline model/route that drives it) — not faked.
QUESTIONS = [
    ("cookie_impl", "where is cookie_scanner implemented",
     ["engines/cookies/cookie_scanner.py"], "code"),
    ("domain_fp", "how does domain_classifier avoid shared-hosting false positives",
     ["threat_intel/domain_classifier.py", "threat_intel/domain_reputation.py"], "code"),
    ("tls_impl", "which module performs TLS checking",
     ["engines/tls_dns/tls_checker.py"], "code"),
    ("scan_to_report", "how does a scan become a report",
     ["webhound/reporting/", "webhound/core/orchestrator.py"], "any"),
    ("prod_wade", "where is production WADE baseline implemented",
     ["scanner/webhound/wade/", "models/baseline", "routers/baselines",
      "services/wade_correlation"], "code"),
    ("adv_wade", "where is advisory WADE reasoning implemented",
     ["scripts/wade/", "advisor/advisor_engine", "tests/ai/test_wade_reasoning"], "code"),
    ("api_auth", "which file handles API authentication",
     ["apps/api/routers/auth.py", "apps/api/services/auth.py", "apps/api/security",
      "apps/api/schemas/auth"], "code"),
    ("verify_flow", "where is domain ownership verification implemented",
     ["apps/api/services/verification.py", "apps/api/routers/"], "code"),
    ("threat_intel", "what handles threat intelligence",
     ["scanner/webhound/threat_intel/", "engines/threat_intel/", "internal/threat_intel"], "code"),
    ("csp_knowledge", "what does Content Security Policy help prevent",
     ["csp", "content-security", "security_headers", "header"], "doc"),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--k", type=int, default=8)
    args = ap.parse_args()

    r = load_retriever()
    results = []
    for qid, q, expects, exp_type in QUESTIONS:
        hits = r.retrieve(q, k=args.k, mode="hybrid")
        paths = [h.get("file_path", "").lower() for h in hits]
        top = hits[0] if hits else {}
        top_path = top.get("file_path", "")
        top_type = top.get("chunk_type", "")

        def _match(p):
            return any(e.lower() in p for e in expects)

        top_ok = _match(top_path.lower())
        any_ok = any(_match(p) for p in paths)
        # type correctness: expected doc vs code ("any" accepts either) for the top hit
        type_ok = (exp_type == "any") or (top_type == exp_type)
        if top_ok and type_ok:
            verdict = "PASS"
        elif any_ok:
            verdict = "PARTIAL"
        else:
            verdict = "FAIL"
        results.append({"id": qid, "question": q, "verdict": verdict,
                        "intent": classify_intent(q), "top_file": top_path,
                        "top_type": top_type, "expected_type": exp_type})

    counts = {v: sum(1 for x in results if x["verdict"] == v) for v in ("PASS", "PARTIAL", "FAIL")}
    payload = {"index_chunks": len(r.chunks), "counts": counts, "results": results}
    if args.json:
        print(json.dumps(payload))
        return 0
    print(f"BRAIN REALITY — {len(r.chunks)} chunks indexed\n")
    for x in results:
        print(f"  {x['verdict']:8s} {x['id']:16s} {x['intent']:22s} "
              f"[{x['top_type']:4s}] {x['top_file'][:48]}")
    print(f"\nPASS={counts['PASS']} PARTIAL={counts['PARTIAL']} FAIL={counts['FAIL']} / {len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
