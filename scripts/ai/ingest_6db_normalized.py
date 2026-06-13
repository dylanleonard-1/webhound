"""
Phase 6D-B: Ingest the 10 new official_provider_doc normalized files into manifest + chunks.
Appends new records to manifest.jsonl; rewrites provider_chunks.jsonl with all content.
"""
import hashlib
import json
import os
import re
import sys
from datetime import datetime

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MANIFEST_PATH = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
CHUNKS_PATH = os.path.join(ROOT, "corpus", "normalized", "provider-docs", "provider_chunks.jsonl")
NORM_BASE = os.path.join(ROOT, "corpus", "normalized", "provider-docs")

CHUNK_TARGET = 1400
TODAY = datetime.utcnow().strftime("%Y-%m-%d")

NEW_FILES = [
    {
        "doc_id": "pd-vercel--vercel-firewall",
        "norm_rel": "corpus/normalized/provider-docs/vercel/pd-vercel--vercel-firewall.md",
        "title": "Vercel Firewall — DDoS, WAF, Bot Protection",
        "source_url": "https://vercel.com/docs/vercel-firewall",
        "provider": "vercel",
        "topic_tags": ["vercel", "waf", "firewall", "ddos", "bot-protection", "rate-limiting", "provider-context"],
        "license_terms": "Developer docs are publicly available; ingesting factual summary only.",
    },
    {
        "doc_id": "pd-vercel--deployment-protection-overview",
        "norm_rel": "corpus/normalized/provider-docs/vercel/pd-vercel--deployment-protection-overview.md",
        "title": "Vercel Deployment Protection Overview",
        "source_url": "https://vercel.com/docs/deployment-protection",
        "provider": "vercel",
        "topic_tags": ["vercel", "deployment-protection", "authentication", "trusted-ips", "provider-context"],
        "license_terms": "Developer docs are publicly available; ingesting factual summary only.",
    },
    {
        "doc_id": "pd-vercel--protection-bypass-automation",
        "norm_rel": "corpus/normalized/provider-docs/vercel/pd-vercel--protection-bypass-automation.md",
        "title": "Protection Bypass for Automation — Vercel",
        "source_url": "https://vercel.com/docs/deployment-protection/methods-to-bypass-deployment-protection/protection-bypass-automation",
        "provider": "vercel",
        "topic_tags": ["vercel", "deployment-protection", "bypass", "automation", "scanner-bypass", "provider-context"],
        "license_terms": "Developer docs are publicly available; ingesting factual summary only.",
    },
    {
        "doc_id": "pd-vercel--firewall-concepts-ja3-ja4",
        "norm_rel": "corpus/normalized/provider-docs/vercel/pd-vercel--firewall-concepts-ja3-ja4.md",
        "title": "Vercel Firewall Concepts — JA3/JA4 TLS Fingerprinting",
        "source_url": "https://vercel.com/docs/vercel-firewall/firewall-concepts",
        "provider": "vercel",
        "topic_tags": ["vercel", "tls-fingerprinting", "ja3", "ja4", "firewall", "challenge-page", "provider-context"],
        "license_terms": "Developer docs are publicly available; ingesting factual summary only.",
    },
    {
        "doc_id": "pd-vercel--waf-custom-rules",
        "norm_rel": "corpus/normalized/provider-docs/vercel/pd-vercel--waf-custom-rules.md",
        "title": "Vercel WAF Custom Rules",
        "source_url": "https://vercel.com/docs/vercel-firewall/vercel-waf/custom-rules",
        "provider": "vercel",
        "topic_tags": ["vercel", "waf", "firewall", "custom-rules", "rate-limiting", "ip-allowlisting", "provider-context"],
        "license_terms": "Developer docs are publicly available; ingesting factual summary only.",
    },
    {
        "doc_id": "pd-vercel--waf-managed-rulesets",
        "norm_rel": "corpus/normalized/provider-docs/vercel/pd-vercel--waf-managed-rulesets.md",
        "title": "Vercel WAF Managed Rulesets — OWASP + Bot Protection",
        "source_url": "https://vercel.com/docs/vercel-firewall/vercel-waf/managed-rulesets",
        "provider": "vercel",
        "topic_tags": ["vercel", "waf", "owasp", "bot-protection", "managed-rulesets", "xss", "sql-injection", "provider-context"],
        "license_terms": "Developer docs are publicly available; ingesting factual summary only.",
    },
    {
        "doc_id": "pd-vercel--system-headers",
        "norm_rel": "corpus/normalized/provider-docs/vercel/pd-vercel--system-headers.md",
        "title": "Vercel System Headers — Request and Response",
        "source_url": "https://vercel.com/docs/headers/request-headers",
        "provider": "vercel",
        "topic_tags": ["vercel", "headers", "tls-fingerprinting", "ip-geolocation", "x-forwarded-for", "webhook-validation", "provider-context"],
        "license_terms": "Developer docs are publicly available; ingesting factual summary only.",
    },
    {
        "doc_id": "pd-stripe--webhooks-full",
        "norm_rel": "corpus/normalized/provider-docs/stripe/pd-stripe--webhooks-full.md",
        "title": "Stripe Webhooks — Complete Technical Reference",
        "source_url": "https://docs.stripe.com/webhooks",
        "provider": "stripe",
        "topic_tags": ["stripe", "webhook-validation", "hmac", "stripe-signature", "authentication", "replay-attack", "provider-context"],
        "license_terms": "Stripe docs are publicly available; ingesting factual summary only.",
    },
    {
        "doc_id": "pd-stripe--security",
        "norm_rel": "corpus/normalized/provider-docs/stripe/pd-stripe--security.md",
        "title": "Stripe Security — TLS, PCI DSS, API Key Management",
        "source_url": "https://docs.stripe.com/security",
        "provider": "stripe",
        "topic_tags": ["stripe", "tls", "pci-dss", "api-security", "ip-allowlisting", "provider-context"],
        "license_terms": "Stripe docs are publicly available; ingesting factual summary only.",
    },
    {
        "doc_id": "pd-fastly--next-gen-waf-overview",
        "norm_rel": "corpus/normalized/provider-docs/fastly/pd-fastly--next-gen-waf-overview.md",
        "title": "Fastly Next-Gen WAF (Signal Sciences) Overview",
        "source_url": "https://www.fastly.com/documentation/guides/next-gen-waf/getting-started/start-here/",
        "provider": "fastly",
        "topic_tags": ["fastly", "waf", "signal-sciences", "bot-detection", "ip-allowlisting", "x-sigsci-tags", "provider-context"],
        "license_terms": "Fastly docs are publicly available; ingesting factual summary only.",
    },
]


def sha256_of(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def chunk_text(text: str, doc_id: str, source_key: str) -> list[dict]:
    chunks = []
    paras = re.split(r"\n{2,}", text.strip())
    buf, ordinal = "", 0
    for p in paras:
        if len(buf) + len(p) + 2 > CHUNK_TARGET and buf:
            chunks.append({
                "chunk_id": f"{doc_id}::{ordinal:03d}",
                "doc_id": doc_id,
                "source_key": source_key,
                "ordinal": ordinal,
                "char_len": len(buf),
                "text": buf.strip(),
            })
            ordinal += 1
            buf = p
        else:
            buf = buf + "\n\n" + p if buf else p
    if buf.strip():
        chunks.append({
            "chunk_id": f"{doc_id}::{ordinal:03d}",
            "doc_id": doc_id,
            "source_key": source_key,
            "ordinal": ordinal,
            "char_len": len(buf),
            "text": buf.strip(),
        })
    return chunks


def load_existing_manifest():
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def load_existing_chunks():
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def main():
    existing_records = load_existing_manifest()
    existing_ids = {r["doc_id"] for r in existing_records}
    existing_chunks = load_existing_chunks()
    existing_chunk_doc_ids = {c["doc_id"] for c in existing_chunks}

    print(f"Existing manifest records: {len(existing_records)}")
    print(f"Existing chunk doc_ids: {len(existing_chunk_doc_ids)}")

    new_records = []
    new_chunks = []

    for spec in NEW_FILES:
        doc_id = spec["doc_id"]
        norm_abs = os.path.join(ROOT, spec["norm_rel"].replace("/", os.sep))

        if not os.path.exists(norm_abs):
            print(f"  MISSING: {norm_abs}", file=sys.stderr)
            continue

        content = open(norm_abs, encoding="utf-8").read()
        chash = sha256_of(content)

        if doc_id in existing_ids:
            print(f"  SKIP (already in manifest): {doc_id}")
            continue

        record = {
            "doc_id": doc_id,
            "title": spec["title"],
            "source_name": spec["provider"].capitalize(),
            "source_url": spec["source_url"],
            "source_type": "official_provider_doc",
            "doc_role": "engine_note",
            "authority_tier": "A",
            "language": "en",
            "product_or_provider": spec["provider"],
            "topic_tags": spec["topic_tags"],
            "version": TODAY,
            "last_updated": TODAY,
            "first_ingested": TODAY,
            "content_hash": chash,
            "confidence_score": 0.9,
            "verification_status": "verified",
            "license_terms": spec["license_terms"],
            "citability": "citable_external",
            "pii_risk_class": "none",
            "retention_class": "long",
            "entities": [spec["provider"].capitalize(), spec["provider"]],
            "related_docs": [],
            "trust_label": "trusted_external",
            "normalized_path": spec["norm_rel"],
        }
        new_records.append(record)

        # Chunk — skip if already chunked
        if doc_id not in existing_chunk_doc_ids:
            chunks = chunk_text(content, doc_id, spec["provider"])
            new_chunks.extend(chunks)
            print(f"  + {doc_id}: {len(chunks)} chunks")
        else:
            print(f"  CHUNK_SKIP (already chunked): {doc_id}")

    # Append new records to manifest
    if new_records:
        with open(MANIFEST_PATH, "a", encoding="utf-8") as f:
            for r in new_records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"\nAppended {len(new_records)} new manifest records -> total {len(existing_records) + len(new_records)}")
    else:
        print("\nNo new manifest records to add.")

    # Rewrite chunks with new ones appended
    if new_chunks:
        all_chunks = existing_chunks + new_chunks
        with open(CHUNKS_PATH, "w", encoding="utf-8") as f:
            for c in all_chunks:
                f.write(json.dumps(c, ensure_ascii=False) + "\n")
        print(f"Rewrote chunks: {len(existing_chunks)} existing + {len(new_chunks)} new = {len(all_chunks)} total")
    else:
        print("No new chunks to add.")

    print("\nDone.")


if __name__ == "__main__":
    main()
