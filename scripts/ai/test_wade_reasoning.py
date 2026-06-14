"""Phase 8B: WADE retrieval sandbox demo.

Runs 4 representative WADE queries and prints ReasoningContext summaries.
No production changes — advisory read-only mode.

Run: .venv-api/Scripts/python scripts/ai/test_wade_reasoning.py
"""
from __future__ import annotations
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.wade.context_builder import build_reasoning_context


DEMO_QUERIES = [
    {
        "name": "missing_csp",
        "description": "Site missing Content-Security-Policy header",
        "finding_type": "missing_csp",
        "provider": None,
        "symptom": "",
    },
    {
        "name": "provider_blocked_scan",
        "description": "Cloudflare WAF blocked scanner",
        "finding_type": "provider_blocked_scan",
        "provider": "cloudflare",
        "symptom": "HTTP 1020 Access Denied",
    },
    {
        "name": "threat_intel_match",
        "description": "IP flagged by AbuseIPDB on Fastly CDN",
        "finding_type": "threat_intel_match",
        "provider": "fastly",
        "symptom": "AbuseIPDB confidence score 85",
    },
    {
        "name": "third_party_script_risk",
        "description": "Unknown CDN script loaded without SRI",
        "finding_type": "third_party_script_risk",
        "provider": None,
        "symptom": "",
    },
]


def run_demo() -> None:
    print("=" * 70)
    print("WADE Phase 8B — Retrieval Advisory Demo")
    print("Advisory mode only. No production impact.")
    print("=" * 70)

    for q in DEMO_QUERIES:
        print(f"\n[{q['name']}] {q['description']}")
        ctx = build_reasoning_context(
            finding_type=q["finding_type"],
            provider=q.get("provider"),
            symptom=q.get("symptom", ""),
            k=5,
        )

        print(f"  Brain Version : {ctx.brain_version}")
        print(f"  Finding Type  : {ctx.finding_type}")
        print(f"  Provider      : {ctx.provider_name or 'N/A'}")
        print(f"  CWE           : {ctx.taxonomy_context.get('cwe', 'N/A')}")
        print(f"  OWASP         : {ctx.taxonomy_context.get('owasp', 'N/A')}")
        print(f"  Severity      : {ctx.taxonomy_context.get('severity_guidance', 'N/A')[:80]}")
        print(f"  Confidence    : {ctx.retrieval_confidence:.3f}")
        print(f"  Sources       : {len(ctx.supporting_chunks)} chunks")
        print(f"  Auth Tiers    : {ctx.authority_tiers or 'N/A'}")

        print(f"  FP Patterns   :")
        for pat in ctx.false_positive_patterns[:2]:
            print(f"    - {pat[:80]}")

        print(f"  Risk Summary  :")
        risk = ctx.customer_safe_language.get("risk_summary", "")
        for line in risk[:200].split(". "):
            if line.strip():
                print(f"    {line.strip()[:78]}")

        print(f"  Reasoning     : {ctx.reasoning_summary[:100]}...")

        if ctx.retrieved_sources:
            top = ctx.retrieved_sources[0]
            print(f"  Top Source    : [{top.get('phase', '?')}] {top.get('title', '?')[:60]}")
            print(f"                  score={top.get('score', 0):.4f} "
                  f"tier={top.get('authority_tier', '?')}")

    print("\n" + "=" * 70)
    print("Demo complete. All retrieval is local — no cloud APIs used.")
    print("=" * 70)


if __name__ == "__main__":
    run_demo()
