"""Phase 8A: Graphiti memory seeding plan for WebHound AI Brain.

Defines 10 memory types and example seeds for Graphiti episodic memory.
This script generates seed data (JSON) only — no Graphiti API calls.
Graphiti installation is NOT required.

To actually seed Graphiti:
  pip install graphiti-core
  Then call graphiti.add_episode() with each seed dict.

Run: .venv-api/Scripts/python scripts/ai/graphiti_seed_memory.py [--dry-run]
"""
from __future__ import annotations
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
OUT_PATH = ROOT / "corpus" / "exports" / "graphiti_seeds.json"
DRY_RUN = "--dry-run" in sys.argv

# 10 memory types per Phase 8A spec
MEMORY_TYPES = [
    "engineering_decision",
    "scanner_behavior",
    "false_positive_pattern",
    "provider_behavior",
    "threat_intel_rule",
    "taxonomy_rule",
    "WADE_policy",
    "retrieval_decision",
    "phase_status",
    "benchmark_result",
]

NOW = datetime.utcnow().isoformat() + "Z"


def build_seeds() -> list[dict]:
    """Return example Graphiti episode seeds (safe internal memories only)."""
    return [
        {
            "type": "engineering_decision",
            "episode_id": "dec-local-embeddings",
            "name": "Local-only embedding decision",
            "content": (
                "WebHound uses all-MiniLM-L6-v2 (local) for dense embeddings. "
                "Cloud embedding APIs are explicitly prohibited to protect potentially "
                "sensitive page content and eliminate API costs."
            ),
            "valid_at": NOW,
            "source": "phase-7a",
            "tags": ["embeddings", "privacy", "local-only"],
        },
        {
            "type": "scanner_behavior",
            "episode_id": "scan-dalfox-confirm-xss",
            "name": "DalFox confirms XSS active",
            "content": (
                "DalFox is used as the active XSS confirmation engine. "
                "When DalFox fires, WADE increases confidence score by +0.4 "
                "(active confirmation weight). False positive rate is low for reflected XSS."
            ),
            "valid_at": NOW,
            "source": "phase-6b",
            "tags": ["dalfox", "xss", "active-confirmation"],
        },
        {
            "type": "false_positive_pattern",
            "episode_id": "fp-cloudflare-challenge",
            "name": "Cloudflare 1020 is not a finding",
            "content": (
                "HTTP 1020 from Cloudflare is an access denied / WAF block page, "
                "not a vulnerability. WADE suppresses findings on 1020 responses "
                "to prevent false XSS/injection alerts on WAF-managed error pages."
            ),
            "valid_at": NOW,
            "source": "phase-6c",
            "tags": ["cloudflare", "false-positive", "waf"],
        },
        {
            "type": "provider_behavior",
            "episode_id": "prov-vercel-deployment-protection",
            "name": "Vercel deployment protection gate",
            "content": (
                "Vercel preview deployments may have deployment protection enabled. "
                "Scanners receive 401 or redirect to auth gate instead of the actual app. "
                "WADE should not flag auth-gated responses as vulnerabilities."
            ),
            "valid_at": NOW,
            "source": "phase-6c",
            "tags": ["vercel", "deployment-protection", "preview"],
        },
        {
            "type": "threat_intel_rule",
            "episode_id": "ti-greynoise-shared-cdn",
            "name": "GreyNoise classifies CDN IPs as benign",
            "content": (
                "Shared CDN IP addresses (Cloudflare, Fastly, Akamai) appear in "
                "GreyNoise as scanners or benign mass-event IPs. "
                "WADE should not flag a CDN IP as malicious based solely on GreyNoise classification."
            ),
            "valid_at": NOW,
            "source": "phase-6e",
            "tags": ["greynoise", "cdn", "threat-intel"],
        },
        {
            "type": "taxonomy_rule",
            "episode_id": "tax-cwe79-xss",
            "name": "XSS maps to CWE-79",
            "content": (
                "All cross-site scripting findings (reflected, stored, DOM-based) "
                "are classified as CWE-79. Severity is assigned per CVSS v3.1 "
                "based on exploitability and impact subscores."
            ),
            "valid_at": NOW,
            "source": "phase-6a",
            "tags": ["cwe-79", "xss", "taxonomy"],
        },
        {
            "type": "WADE_policy",
            "episode_id": "wade-confidence-threshold",
            "name": "WADE confidence threshold for reporting",
            "content": (
                "WADE only reports findings with confidence >= 0.4. "
                "Findings below this threshold are suppressed as likely false positives. "
                "Active confirmation (DalFox) raises confidence above threshold in most cases."
            ),
            "valid_at": NOW,
            "source": "phase-6a",
            "tags": ["wade", "confidence", "policy"],
        },
        {
            "type": "retrieval_decision",
            "episode_id": "ret-hybrid-weights",
            "name": "Hybrid retrieval weight choice (0.35/0.65)",
            "content": (
                "Hybrid retrieval uses 0.35 lexical + 0.65 dense weight. "
                "Phase 7A evaluation: dense_only 71%/84%/92% vs hybrid 76%/88%/90% top-1/3/5. "
                "Dense weight higher because semantic similarity outperforms keyword on 120-Q benchmark."
            ),
            "valid_at": NOW,
            "source": "phase-7a",
            "tags": ["retrieval", "hybrid", "weights"],
        },
        {
            "type": "phase_status",
            "episode_id": "phase-8a-status",
            "name": "Phase 8A AI Brain Foundation",
            "content": (
                "Phase 8A (AI Brain Foundation) completed 2026-06-14. "
                "Deliverables: Obsidian vault, export_brain_vault.py, LightRAG corpus export, "
                "Graphiti seeds, Neo4j schema plan, WADE brain interface, 10 brain query tests."
            ),
            "valid_at": NOW,
            "source": "phase-8a",
            "tags": ["phase-8a", "status", "complete"],
        },
        {
            "type": "benchmark_result",
            "episode_id": "bench-phase7a-hybrid",
            "name": "Phase 7A hybrid retrieval benchmark",
            "content": (
                "120-question benchmark (Phase 7A): "
                "lexical_only 12%/38%/52%, dense_only 71%/84%/92%, hybrid 76%/88%/90% "
                "at top-1/top-3/top-5. Evaluated against path-fragment style queries "
                "on 1161 chunks from 487 docs."
            ),
            "valid_at": NOW,
            "source": "phase-7a",
            "tags": ["benchmark", "retrieval", "phase-7a"],
        },
    ]


def main() -> None:
    seeds = build_seeds()
    print(f"Generated {len(seeds)} Graphiti memory seeds across {len(MEMORY_TYPES)} types")

    if DRY_RUN:
        print("DRY RUN — not writing to disk")
        for s in seeds:
            print(f"  [{s['type']}] {s['name']}")
        return

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    output = {
        "generated_at": NOW,
        "cloud_api_used": False,
        "local_only": True,
        "memory_types": MEMORY_TYPES,
        "seeds": seeds,
        "ingestion_notes": [
            "Call graphiti.add_episode(**seed) to seed each memory.",
            "Install: pip install graphiti-core",
            "Requires Graphiti server running locally or graph backend configured.",
            "These seeds represent safe internal operational knowledge only.",
            "No customer data, scan results, or credentials included.",
        ],
    }
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    size_kb = OUT_PATH.stat().st_size // 1024
    print(f"  Wrote {OUT_PATH.relative_to(ROOT)} ({size_kb} KB)")
    print("Done.")


if __name__ == "__main__":
    main()
