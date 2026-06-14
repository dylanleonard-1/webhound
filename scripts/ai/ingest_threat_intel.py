"""Phase 6E: Ingest threat intelligence source docs into manifest + chunks.

Adds official_threat_intel_doc records for live-fetched sources (authority_tier=A)
and internal_doc records for authored synthesis notes (authority_tier=B).
Appends to manifest.jsonl; writes threat_intel_chunks.jsonl.
Prior 424 records are BYTE-STABLE (append-only).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import textwrap
from datetime import date

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MANIFEST_PATH = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
CHUNKS_PATH = os.path.join(ROOT, "corpus", "normalized", "threat-intel", "threat_intel_chunks.jsonl")
INGESTED_AT = str(date.today())
CHUNK_TARGET = 1400


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return "sha256:" + h.hexdigest()


def chunk_text(text: str, doc_id: str, source_key: str) -> list[dict]:
    paragraphs = re.split(r"\n{2,}", text.strip())
    chunks: list[dict] = []
    current = ""
    for para in paragraphs:
        if len(current) + len(para) + 2 > CHUNK_TARGET and current:
            chunks.append(current.strip())
            current = para
        else:
            current = (current + "\n\n" + para).strip() if current else para
    if current.strip():
        chunks.append(current.strip())
    return [
        {
            "chunk_id": f"{doc_id}::{i:03d}",
            "doc_id": doc_id,
            "source_key": source_key,
            "ordinal": i,
            "char_len": len(c),
            "text": c,
        }
        for i, c in enumerate(chunks)
    ]


# ---------------------------------------------------------------------------
# Official threat-intel docs (live-fetched; authority_tier=A)
# ---------------------------------------------------------------------------
OFFICIAL_DOCS = [
    {
        "doc_id": "pd-ti-urlhaus--api",
        "title": "URLHaus API — Technical Reference",
        "source_name": "URLHaus (abuse.ch)",
        "source_url": "https://urlhaus-api.abuse.ch/",
        "product_or_provider": "urlhaus",
        "topic_tags": ["urlhaus", "malware-url", "threat-intel", "abuse-ch", "api", "indicator-types", "rate-limits"],
        "license_terms": "abuse.ch Terms of Use; attribution required; commercial use may require subscription.",
        "normalized_path": "corpus/normalized/threat-intel/urlhaus/pd-ti-urlhaus--api.md",
    },
    {
        "doc_id": "pd-ti-threatfox--api",
        "title": "ThreatFox API — Technical Reference",
        "source_name": "ThreatFox (abuse.ch)",
        "source_url": "https://threatfox.abuse.ch/api/",
        "product_or_provider": "threatfox",
        "topic_tags": ["threatfox", "malware-ioc", "botnet-c2", "skimming", "threat-intel", "abuse-ch", "api"],
        "license_terms": "abuse.ch Terms of Use; attribution required; commercial use may require subscription.",
        "normalized_path": "corpus/normalized/threat-intel/threatfox/pd-ti-threatfox--api.md",
    },
    {
        "doc_id": "pd-ti-openphish--feed",
        "title": "OpenPhish Phishing Intelligence Feed — Technical Reference",
        "source_name": "OpenPhish",
        "source_url": "https://openphish.com/phishing_database.html",
        "product_or_provider": "openphish",
        "topic_tags": ["openphish", "phishing-url", "threat-intel", "feed", "indicator-types"],
        "license_terms": "OpenPhish Terms of Use; organizational domain verification required for paid tier.",
        "normalized_path": "corpus/normalized/threat-intel/openphish/pd-ti-openphish--feed.md",
    },
    {
        "doc_id": "pd-ti-phishtank--api",
        "title": "PhishTank API — Technical Reference",
        "source_name": "PhishTank (Cisco Talos)",
        "source_url": "https://www.phishtank.com/developer_info.php",
        "product_or_provider": "phishtank",
        "topic_tags": ["phishtank", "phishing-url", "threat-intel", "community-verified", "api", "cisco-talos"],
        "license_terms": "Cisco EULA; attribution to PhishTank (Cisco Talos) required.",
        "normalized_path": "corpus/normalized/threat-intel/phishtank/pd-ti-phishtank--api.md",
    },
    {
        "doc_id": "pd-ti-abuseipdb--api",
        "title": "AbuseIPDB API v2 — Technical Reference",
        "source_name": "AbuseIPDB",
        "source_url": "https://docs.abuseipdb.com/",
        "product_or_provider": "abuseipdb",
        "topic_tags": ["abuseipdb", "ip-abuse", "threat-intel", "api", "confidence-score", "false-positive"],
        "license_terms": "abuseipdb.com ToS; API key required; no bulk redistribution of raw data.",
        "normalized_path": "corpus/normalized/threat-intel/abuseipdb/pd-ti-abuseipdb--api.md",
    },
    {
        "doc_id": "pd-ti-virustotal--api",
        "title": "VirusTotal API v3 — Technical Reference",
        "source_name": "VirusTotal (Google)",
        "source_url": "https://docs.virustotal.com/reference/overview",
        "product_or_provider": "virustotal",
        "topic_tags": ["virustotal", "multi-engine", "threat-intel", "api", "malware", "url-reputation", "domain-reputation"],
        "license_terms": "VirusTotal ToS; no raw data redistribution; attribution required.",
        "normalized_path": "corpus/normalized/threat-intel/virustotal/pd-ti-virustotal--api.md",
    },
    {
        "doc_id": "pd-ti-gsb--lookup-api",
        "title": "Google Safe Browsing v4 Lookup API — Technical Reference",
        "source_name": "Google Safe Browsing",
        "source_url": "https://developers.google.com/safe-browsing/v4/lookup-api",
        "product_or_provider": "google-safe-browsing",
        "topic_tags": ["google-safe-browsing", "phishing", "malware", "threat-intel", "api", "url-safety"],
        "license_terms": "Google APIs ToS; attribution required in user-facing UI; no list redistribution.",
        "normalized_path": "corpus/normalized/threat-intel/google-safe-browsing/pd-ti-gsb--lookup-api.md",
    },
    {
        "doc_id": "pd-ti-greynoise--community-api",
        "title": "GreyNoise Community API — Technical Reference",
        "source_name": "GreyNoise Intelligence",
        "source_url": "https://docs.greynoise.io/docs/using-the-greynoise-community-api",
        "product_or_provider": "greynoise",
        "topic_tags": ["greynoise", "internet-noise", "ip-classification", "threat-intel", "api", "riot", "false-positive"],
        "license_terms": "greynoise.io/terms; community tier free; attribution required in reports.",
        "normalized_path": "corpus/normalized/threat-intel/greynoise/pd-ti-greynoise--community-api.md",
    },
    {
        "doc_id": "pd-ti-shodan--api",
        "title": "Shodan API — Technical Reference",
        "source_name": "Shodan",
        "source_url": "https://developer.shodan.io/api",
        "product_or_provider": "shodan",
        "topic_tags": ["shodan", "exposure", "port-scan", "threat-intel", "api", "banner", "vulnerability"],
        "license_terms": "account.shodan.io/terms; no bulk redistribution of raw data.",
        "normalized_path": "corpus/normalized/threat-intel/shodan/pd-ti-shodan--api.md",
    },
]

# ---------------------------------------------------------------------------
# Authored synthesis notes (internal_doc; authority_tier=B)
# ---------------------------------------------------------------------------
INTERNAL_DOCS = [
    {
        "doc_id": "pn-ti-otx--api",
        "title": "AlienVault OTX — Authored Reference",
        "source_name": "AlienVault OTX (LevelBlue)",
        "source_url": "https://otx.alienvault.com/",
        "product_or_provider": "otx",
        "topic_tags": ["otx", "threat-intel", "pulse", "indicator-types", "crowdsourced"],
        "license_terms": "OTX ToS; authored synthesis note; not a verbatim mirror.",
        "normalized_path": "corpus/normalized/threat-intel/otx/pd-ti-otx--api.md",
        "note": "live_fetch_blocked: JS-heavy SPA, 404 on /api/v1/docs",
    },
    {
        "doc_id": "pn-ti-censys--api",
        "title": "Censys Search API — Authored Reference",
        "source_name": "Censys",
        "source_url": "https://docs.censys.com/",
        "product_or_provider": "censys",
        "topic_tags": ["censys", "exposure", "certificate", "threat-intel", "api", "internet-scan"],
        "license_terms": "censys.io/legal/terms; authored synthesis note; not a verbatim mirror.",
        "normalized_path": "corpus/normalized/threat-intel/censys/pd-ti-censys--api.md",
        "note": "live_fetch_blocked: 403 on search.censys.io/api, session limit on docs.censys.com",
    },
    {
        "doc_id": "pn-ti-misp--overview",
        "title": "MISP Threat Intelligence Platform — Authored Reference",
        "source_name": "MISP Project",
        "source_url": "https://www.misp-project.org/documentation/",
        "product_or_provider": "misp",
        "topic_tags": ["misp", "threat-sharing", "indicator-types", "threat-intel", "federated"],
        "license_terms": "AGPL-3.0 (platform); data governed by community TLP/PAP policies.",
        "normalized_path": "corpus/normalized/threat-intel/misp/pd-ti-misp--overview.md",
        "note": "live_fetch_partial: MISP docs page returned limited content",
    },
    # Synthesis notes
    {
        "doc_id": "pn-ti-source-overview",
        "title": "Threat Intelligence Source Overview",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/threat-intel-source-overview.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "source-matrix", "coverage", "client-status"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/threat-intel-source-overview.md",
    },
    {
        "doc_id": "pn-ti-indicator-type-model",
        "title": "Indicator Type Model",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/indicator-type-model.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "indicator-types", "url", "domain", "ip", "hash"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/indicator-type-model.md",
    },
    {
        "doc_id": "pn-ti-confidence-model",
        "title": "Threat Intelligence Confidence Model",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/threat-intel-confidence-model.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "confidence", "scoring", "wade", "multi-source"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/threat-intel-confidence-model.md",
    },
    {
        "doc_id": "pn-ti-false-positive-model",
        "title": "Threat Intelligence False Positive Model",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/threat-intel-false-positive-model.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "false-positive", "shared-hosting", "cdn", "stale-ioc"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/threat-intel-false-positive-model.md",
    },
    {
        "doc_id": "pn-ti-shared-infrastructure-risk",
        "title": "Shared Infrastructure Risk",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/shared-infrastructure-risk.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "shared-hosting", "cdn", "cloud", "false-positive", "asn"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/shared-infrastructure-risk.md",
    },
    {
        "doc_id": "pn-ti-url-domain-ip-confidence",
        "title": "URL vs Domain vs IP Confidence",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/url-vs-domain-vs-ip-confidence.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "url", "domain", "ip", "confidence", "specificity"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/url-vs-domain-vs-ip-confidence.md",
    },
    {
        "doc_id": "pn-ti-for-wade",
        "title": "Threat Intelligence for WADE",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/threat-intel-for-wade.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "wade", "scoring", "must-not", "must-should", "false-positive"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/threat-intel-for-wade.md",
    },
    {
        "doc_id": "pn-ti-for-third-party-scripts",
        "title": "Threat Intelligence for Third-Party Scripts",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/threat-intel-for-third-party-scripts.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "third-party-scripts", "skimming", "magecart", "csp"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/threat-intel-for-third-party-scripts.md",
    },
    {
        "doc_id": "pn-ti-for-phishing-detection",
        "title": "Threat Intelligence for Phishing Detection",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/threat-intel-for-phishing-detection.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "phishing", "openphish", "phishtank", "gsb"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/threat-intel-for-phishing-detection.md",
    },
    {
        "doc_id": "pn-ti-for-malicious-redirects",
        "title": "Threat Intelligence for Malicious Redirects",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/threat-intel-for-malicious-redirects.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "redirect", "open-redirect", "malvertising"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/threat-intel-for-malicious-redirects.md",
    },
    {
        "doc_id": "pn-ti-for-customer-reporting",
        "title": "Threat Intelligence for Customer Reporting",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/threat-intel-for-customer-reporting.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "customer-reporting", "language", "severity", "false-positive"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/threat-intel-for-customer-reporting.md",
    },
    {
        "doc_id": "pn-ti-source-terms-and-limits",
        "title": "Threat Intelligence Source Terms and Rate Limits",
        "source_name": "WebHound AI Knowledge",
        "source_url": "knowledge/threat-intelligence/threat-intel-source-terms-and-limits.md",
        "product_or_provider": None,
        "topic_tags": ["threat-intel", "terms", "rate-limits", "api-keys", "compliance"],
        "license_terms": "Internal WebHound document.",
        "normalized_path": "knowledge/threat-intelligence/threat-intel-source-terms-and-limits.md",
    },
]


def make_record(meta: dict, source_type: str, authority_tier: str, confidence: float) -> dict:
    norm_path = meta["normalized_path"]
    abs_path = os.path.join(ROOT, norm_path.replace("/", os.sep))
    content_hash = sha256_of_file(abs_path) if os.path.exists(abs_path) else "sha256:unknown"
    r: dict = {
        "doc_id": meta["doc_id"],
        "title": meta["title"],
        "source_name": meta["source_name"],
        "source_url": meta["source_url"],
        "source_type": source_type,
        "doc_role": "canonical_note",
        "authority_tier": authority_tier,
        "language": "en",
        "product_or_provider": meta.get("product_or_provider"),
        "topic_tags": meta["topic_tags"],
        "version": INGESTED_AT,
        "last_updated": INGESTED_AT,
        "first_ingested": INGESTED_AT,
        "content_hash": content_hash,
        "confidence_score": confidence,
        "verification_status": "verified" if source_type == "official_threat_intel_doc" else "needs_review",
        "license_terms": meta["license_terms"],
        "citability": "citable_external" if source_type == "official_threat_intel_doc" else "internal_only",
        "pii_risk_class": "none",
        "retention_class": "long",
        "entities": [meta["source_name"]],
        "related_docs": [],
        "trust_label": "trusted_external" if source_type == "official_threat_intel_doc" else "trusted_internal",
        "normalized_path": norm_path,
    }
    return r


def main() -> None:
    # Load existing manifest to get current count
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        existing_lines = f.readlines()
    print(f"Existing manifest records: {len(existing_lines)}")

    existing_ids = {json.loads(l)["doc_id"] for l in existing_lines}

    new_records: list[dict] = []
    all_chunks: list[dict] = []

    # Official docs
    for meta in OFFICIAL_DOCS:
        if meta["doc_id"] in existing_ids:
            print(f"  SKIP (already in manifest): {meta['doc_id']}")
            continue
        r = make_record(meta, "official_threat_intel_doc", "A", 0.90)
        new_records.append(r)
        # Chunk
        abs_path = os.path.join(ROOT, meta["normalized_path"].replace("/", os.sep))
        if os.path.exists(abs_path):
            text = open(abs_path, encoding="utf-8").read()
            all_chunks.extend(chunk_text(text, meta["doc_id"], meta.get("product_or_provider", meta["doc_id"])))

    # Internal docs
    for meta in INTERNAL_DOCS:
        if meta["doc_id"] in existing_ids:
            print(f"  SKIP (already in manifest): {meta['doc_id']}")
            continue
        r = make_record(meta, "internal_doc", "B", 0.80)
        new_records.append(r)
        abs_path = os.path.join(ROOT, meta["normalized_path"].replace("/", os.sep))
        if os.path.exists(abs_path):
            text = open(abs_path, encoding="utf-8").read()
            all_chunks.extend(chunk_text(text, meta["doc_id"], meta.get("product_or_provider", "threat-intel")))

    print(f"New records to append: {len(new_records)}")
    print(f"New chunks: {len(all_chunks)}")

    # Append to manifest (BYTE-STABLE for prior records)
    with open(MANIFEST_PATH, "a", encoding="utf-8") as f:
        for r in new_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # Write chunks file
    with open(CHUNKS_PATH, "w", encoding="utf-8") as f:
        for c in all_chunks:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    total = len(existing_lines) + len(new_records)
    print(f"Manifest total: {total} records")
    print(f"Chunks written: {len(all_chunks)}")


if __name__ == "__main__":
    main()
