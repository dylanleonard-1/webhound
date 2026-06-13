#!/usr/bin/env python3
"""Emit sample Claude-memory records from local knowledge (Phase 4).

Demonstrates the CLAUDE_MEMORY_POLICY format: SUMMARIES + POINTERS ONLY. Builds
records DETERMINISTICALLY from local files — NO LLM call, NO network, NO secrets,
NO customer data, NO full docs. Output is JSON to stdout (or --output).

Usage:
  python scripts/ai/export_memory_summary.py [--output FILE]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

# Fixed stamp (scripts must be reproducible; no live clock here).
STAMP = "2026-06-12"

# Curated, durable summaries + pointers ONLY. No secrets/customer data/full docs.
RECORDS = [
    {
        "memory_id": "ai-knowledge-layer-decisions",
        "summary": "AI Knowledge Layer locked decisions: corpus=evidence vs knowledge=curated; "
                   "pointer-first internal docs; link+summarize provider docs; in-repo vault; "
                   "ignore orphaned ruvector.db; reuse threat_intel/WADE/Security Graph/validation.",
        "related_manifest_doc_ids": [],
        "related_paths": ["knowledge/webhound/decisions/AI_KNOWLEDGE_LAYER_DECISIONS.md"],
        "authority_tier": "trusted_local",
        "review_status": "verified",
        "retention_class": "permanent",
    },
    {
        "memory_id": "webhound-architecture-summary",
        "summary": "WebHound = API (FastAPI) + web (Next.js) + worker (Celery) + scanner "
                   "(webhound engines). Railway API/worker, Vercel web, Postgres+Redis. "
                   "Static scanner egress IPs: 162.220.234.240, 152.55.180.240, 152.55.180.241.",
        "related_manifest_doc_ids": [],
        "related_paths": ["knowledge/webhound/architecture/WEBHOUND_ARCHITECTURE_SUMMARY.md"],
        "authority_tier": "trusted_local",
        "review_status": "verified",
        "retention_class": "long",
    },
    {
        "memory_id": "known-false-positive-classes",
        "summary": "10 seeded FP lessons: CORS-over-severity, social-link-as-API, minified entropy, "
                   "correlation w/o attack path, CSP unsafe-inline severity, cross-origin-isolation "
                   "noise, RSC educational copy, SPA form GET, auth-gated admin shell, CSP-hosts graph.",
        "related_manifest_doc_ids": [],
        "related_paths": ["knowledge/false-positive-catalog/"],
        "authority_tier": "trusted_local",
        "review_status": "verified",
        "retention_class": "long",
    },
    {
        "memory_id": "threat-intel-current-state",
        "summary": "Runtime threat_intel: URLHaus+VirusTotal live clients; OpenPhish+AbuseIPDB "
                   "partial (normalizers, no clients); ThreatFox+OTX missing. Reuse, don't rebuild; "
                   "TI is enrichment, not the sole decision-maker.",
        "related_manifest_doc_ids": [],
        "related_paths": ["knowledge/webhound/threat-intel/THREAT_INTEL_CURRENT_STATE.md"],
        "authority_tier": "trusted_local",
        "review_status": "verified",
        "retention_class": "long",
    },
    {
        "memory_id": "claude-memory-policy",
        "summary": "Memory stores summaries + pointers ONLY. Never: secrets, tokens, customer data, "
                   "raw scan payloads, payment data, raw malicious payloads, full vendor docs, "
                   "unreviewed scraped content.",
        "related_manifest_doc_ids": [],
        "related_paths": ["docs/ai/CLAUDE_MEMORY_POLICY.md"],
        "authority_tier": "trusted_local",
        "review_status": "verified",
        "retention_class": "permanent",
    },
]

# Fields that must NEVER carry secrets/customer data (policy guard).
_FORBIDDEN_SUBSTRINGS = ("sk-", "ghp_", "gho_", "Bearer ", "password", "api_key=")


def _validate(rec: dict) -> None:
    blob = json.dumps(rec).lower()
    for bad in _FORBIDDEN_SUBSTRINGS:
        if bad.lower() in blob:
            raise SystemExit(f"memory record {rec['memory_id']} contains forbidden token: {bad}")
    # pointers must reference existing local paths (provenance integrity)
    for p in rec.get("related_paths", []):
        if not os.path.exists(os.path.join(ROOT, p)):
            raise SystemExit(f"memory record {rec['memory_id']} points to missing path: {p}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default=None, help="write JSON here (default: stdout)")
    args = ap.parse_args(argv)

    out = []
    for r in RECORDS:
        rec = {**r, "created_at": STAMP, "updated_at": STAMP}
        _validate(rec)
        out.append(rec)

    text = json.dumps(out, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[ok] wrote {len(out)} memory records -> {args.output}")
    else:
        print(text)
    print(f"\n[info] {len(out)} records — summaries + pointers only (policy: docs/ai/CLAUDE_MEMORY_POLICY.md).",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
