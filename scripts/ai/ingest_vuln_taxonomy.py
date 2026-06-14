"""Phase 6F: Ingest vulnerability taxonomy docs into manifest + chunks.

Adds official_taxonomy_doc records (authority_tier=A) for live-fetched sources
and internal_doc records (authority_tier=B) for authored synthesis notes.
Prior 448 records BYTE-STABLE (append-only).
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import date

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MANIFEST_PATH = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
CHUNKS_PATH = os.path.join(
    ROOT, "corpus", "normalized", "vulnerability-taxonomy", "vuln_taxonomy_chunks.jsonl"
)
INGESTED_AT = str(date.today())
CHUNK_TARGET = 1400


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return "sha256:" + h.hexdigest()


def chunk_text(text: str, doc_id: str, source_key: str) -> list[dict]:
    import re
    paragraphs = re.split(r"\n{2,}", text.strip())
    chunks: list[str] = []
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
# Official taxonomy docs (live-fetched; authority_tier=A)
# ---------------------------------------------------------------------------
OFFICIAL_DOCS = [
    # CWE official pages
    dict(doc_id="pd-vt-cwe--overview", title="CWE Program Overview",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/about/index.html",
         product_or_provider="cwe",
         topic_tags=["cwe","weakness","taxonomy","vulnerability","mitre"],
         license_terms="MITRE CWE terms of use; free for non-commercial research/tools.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--overview.md"),
    dict(doc_id="pd-vt-cwe--79-xss", title="CWE-79 Cross-Site Scripting",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/79.html",
         product_or_provider="cwe",
         topic_tags=["cwe","xss","injection","web-security","cwe-79"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--79-xss.md"),
    dict(doc_id="pd-vt-cwe--89-sqli", title="CWE-89 SQL Injection",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/89.html",
         product_or_provider="cwe",
         topic_tags=["cwe","sql-injection","injection","web-security","cwe-89"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--89-sqli.md"),
    dict(doc_id="pd-vt-cwe--352-csrf", title="CWE-352 Cross-Site Request Forgery",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/352.html",
         product_or_provider="cwe",
         topic_tags=["cwe","csrf","web-security","cwe-352","cookies"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--352-csrf.md"),
    dict(doc_id="pd-vt-cwe--22-path-traversal", title="CWE-22 Path Traversal",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/22.html",
         product_or_provider="cwe",
         topic_tags=["cwe","path-traversal","file-access","cwe-22"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--22-path-traversal.md"),
    dict(doc_id="pd-vt-cwe--78-cmdi", title="CWE-78 OS Command Injection",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/78.html",
         product_or_provider="cwe",
         topic_tags=["cwe","command-injection","injection","cwe-78"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--78-cmdi.md"),
    dict(doc_id="pd-vt-cwe--918-ssrf", title="CWE-918 Server-Side Request Forgery",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/918.html",
         product_or_provider="cwe",
         topic_tags=["cwe","ssrf","server-side","cwe-918","owasp-a10"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--918-ssrf.md"),
    dict(doc_id="pd-vt-cwe--200-info-exposure", title="CWE-200 Sensitive Information Exposure",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/200.html",
         product_or_provider="cwe",
         topic_tags=["cwe","information-exposure","confidentiality","cwe-200"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--200-info-exposure.md"),
    dict(doc_id="pd-vt-cwe--287-improper-auth", title="CWE-287 Improper Authentication",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/287.html",
         product_or_provider="cwe",
         topic_tags=["cwe","authentication","access-control","cwe-287"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--287-improper-auth.md"),
    dict(doc_id="pd-vt-cwe--522-protected-creds", title="CWE-522 Insufficiently Protected Credentials",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/522.html",
         product_or_provider="cwe",
         topic_tags=["cwe","credentials","cryptography","cwe-522"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--522-protected-creds.md"),
    dict(doc_id="pd-vt-cwe--798-hardcoded-creds", title="CWE-798 Use of Hard-coded Credentials",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/798.html",
         product_or_provider="cwe",
         topic_tags=["cwe","hardcoded-credentials","secrets","cwe-798"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--798-hardcoded-creds.md"),
    dict(doc_id="pd-vt-cwe--611-xxe", title="CWE-611 XML External Entity",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/611.html",
         product_or_provider="cwe",
         topic_tags=["cwe","xxe","xml","injection","cwe-611"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--611-xxe.md"),
    dict(doc_id="pd-vt-cwe--614-cookie-secure", title="CWE-614 Cookie Without Secure Flag",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/614.html",
         product_or_provider="cwe",
         topic_tags=["cwe","cookie","secure-flag","cwe-614","session"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--614-cookie-no-secure.md"),
    dict(doc_id="pd-vt-cwe--1004-cookie-httponly", title="CWE-1004 Cookie Without HttpOnly Flag",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/1004.html",
         product_or_provider="cwe",
         topic_tags=["cwe","cookie","httponly","cwe-1004","xss"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--1004-cookie-no-httponly.md"),
    dict(doc_id="pd-vt-cwe--1021-clickjacking", title="CWE-1021 Clickjacking / UI Redress",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/1021.html",
         product_or_provider="cwe",
         topic_tags=["cwe","clickjacking","iframe","x-frame-options","csp","cwe-1021"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--1021-clickjacking.md"),
    dict(doc_id="pd-vt-cwe--693-protection-failure", title="CWE-693 Protection Mechanism Failure",
         source_name="MITRE CWE", source_url="https://cwe.mitre.org/data/definitions/693.html",
         product_or_provider="cwe",
         topic_tags=["cwe","security-headers","protection-failure","cwe-693"],
         license_terms="MITRE CWE terms of use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cwe/pd-vt-cwe--693-protection-failure.md"),
    # NVD official pages
    dict(doc_id="pd-vt-nvd--cvss", title="NVD CVSS Scoring Reference",
         source_name="NIST NVD", source_url="https://nvd.nist.gov/vuln-metrics/cvss",
         product_or_provider="nvd",
         topic_tags=["nvd","cvss","scoring","severity","nist"],
         license_terms="NIST publications are in the public domain. Required attribution for NVD API use.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/nvd/pd-vt-nvd--cvss.md"),
    dict(doc_id="pd-vt-nvd--api", title="NVD API Developer Reference",
         source_name="NIST NVD", source_url="https://nvd.nist.gov/developers/start-here",
         product_or_provider="nvd",
         topic_tags=["nvd","api","cve","rate-limits","nist"],
         license_terms="NIST publications are in the public domain.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/nvd/pd-vt-nvd--api.md"),
    # CVSS official pages
    dict(doc_id="pd-vt-cvss--v31", title="CVSS v3.1 Specification Reference",
         source_name="FIRST CVSS", source_url="https://www.first.org/cvss/v3-1/",
         product_or_provider="cvss",
         topic_tags=["cvss","v3.1","scoring","vulnerability","first.org"],
         license_terms="FIRST.Org CVSS specification; free to use and reference.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cvss/pd-vt-cvss--v31.md"),
    dict(doc_id="pd-vt-cvss--v40", title="CVSS v4.0 Reference",
         source_name="FIRST CVSS", source_url="https://www.first.org/cvss/v4-0/",
         product_or_provider="cvss",
         topic_tags=["cvss","v4.0","scoring","vulnerability","first.org"],
         license_terms="FIRST.Org CVSS specification; free to use and reference.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cvss/pd-vt-cvss--v40.md"),
    # OWASP official pages
    dict(doc_id="pd-vt-owasp--risk-rating", title="OWASP Risk Rating Methodology",
         source_name="OWASP", source_url="https://owasp.org/www-community/OWASP_Risk_Rating_Methodology",
         product_or_provider="owasp",
         topic_tags=["owasp","risk-rating","likelihood","impact","severity"],
         license_terms="CC-BY-SA 3.0 (OWASP content); attribution required.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/owasp/pd-vt-owasp--risk-rating.md"),
    dict(doc_id="pd-vt-owasp--top10", title="OWASP Top 10 2021 Reference",
         source_name="OWASP", source_url="https://owasp.org/Top10/2021/",
         product_or_provider="owasp",
         topic_tags=["owasp","top-10","web-security","2021","injection","misconfiguration"],
         license_terms="CC-BY-SA 3.0 (OWASP content); A01 live-fetched; A02-A10 authored.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/owasp/pd-vt-owasp--top10.md"),
]

# ---------------------------------------------------------------------------
# Authored synthesis notes (internal_doc; authority_tier=B)
# ---------------------------------------------------------------------------
INTERNAL_DOCS = [
    dict(doc_id="pn-vt-cve--program", title="CVE Program — Authored Reference",
         source_name="MITRE CVE", source_url="https://cve.org/About/Overview",
         product_or_provider="cve",
         topic_tags=["cve","vulnerability","cna","nvd","taxonomy"],
         license_terms="Authored synthesis; not verbatim mirror.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cve/pd-vt-cve--program.md",
         note="live_fetch_blocked: JS SPA"),
    dict(doc_id="pn-vt-cisa-kev--catalog", title="CISA KEV Catalog — Authored Reference",
         source_name="CISA", source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
         product_or_provider="cisa-kev",
         topic_tags=["cisa","kev","exploited","vulnerability","prioritization"],
         license_terms="Authored synthesis; CISA materials public domain.",
         normalized_path="corpus/normalized/vulnerability-taxonomy/cisa-kev/pd-vt-cisa-kev--catalog.md",
         note="live_fetch_blocked: HTTP 403"),
    # Knowledge synthesis notes
    dict(doc_id="pn-vt-taxonomy-overview", title="Vulnerability Taxonomy Overview",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/vulnerability-taxonomy-overview.md",
         product_or_provider=None,
         topic_tags=["taxonomy","cve","cwe","nvd","cvss","overview"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/vulnerability-taxonomy-overview.md"),
    dict(doc_id="pn-vt-cve-vs-cwe-vs-nvd", title="CVE vs CWE vs NVD Distinctions",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/cve-vs-cwe-vs-nvd.md",
         product_or_provider=None,
         topic_tags=["cve","cwe","nvd","distinctions","taxonomy"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/cve-vs-cwe-vs-nvd.md"),
    dict(doc_id="pn-vt-cvss-severity-model", title="CVSS Severity Model",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/cvss-severity-model.md",
         product_or_provider=None,
         topic_tags=["cvss","severity","scoring","risk","vulnerability"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/cvss-severity-model.md"),
    dict(doc_id="pn-vt-cvss-v31-vs-v40", title="CVSS v3.1 vs v4.0 Comparison",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/cvss-v31-vs-v40.md",
         product_or_provider=None,
         topic_tags=["cvss","v3.1","v4.0","comparison","scoring"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/cvss-v31-vs-v40.md"),
    dict(doc_id="pn-vt-exploitability-vs-impact", title="Exploitability vs Impact",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/exploitability-vs-impact.md",
         product_or_provider=None,
         topic_tags=["exploitability","impact","cvss","severity","risk"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/exploitability-vs-impact.md"),
    dict(doc_id="pn-vt-severity-vs-confidence", title="Severity vs Confidence",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/severity-vs-confidence.md",
         product_or_provider=None,
         topic_tags=["severity","confidence","wade","false-positive","reporting"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/severity-vs-confidence.md"),
    dict(doc_id="pn-vt-cisa-kev-model", title="CISA KEV Known Exploited Model",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/cisa-kev-known-exploited-model.md",
         product_or_provider=None,
         topic_tags=["cisa","kev","exploited","prioritization","wade"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/cisa-kev-known-exploited-model.md"),
    dict(doc_id="pn-vt-owasp-risk-rating-model", title="OWASP Risk Rating Model",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/owasp-risk-rating-model.md",
         product_or_provider=None,
         topic_tags=["owasp","risk-rating","likelihood","impact","scanner-findings"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/owasp-risk-rating-model.md"),
    dict(doc_id="pn-vt-owasp-top10-mapping", title="OWASP Top 10 2021 WebHound Mapping",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/owasp-top-10-mapping.md",
         product_or_provider=None,
         topic_tags=["owasp","top-10","webhound","mapping","scanner"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/owasp-top-10-mapping.md"),
    dict(doc_id="pn-vt-finding-taxonomy", title="WebHound Finding Taxonomy",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/webhound-finding-taxonomy.md",
         product_or_provider=None,
         topic_tags=["webhound","findings","taxonomy","cwe","owasp","severity"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/webhound-finding-taxonomy.md"),
    dict(doc_id="pn-vt-cwe-mapping", title="WebHound CWE Mapping Reference",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/webhound-cwe-mapping.md",
         product_or_provider=None,
         topic_tags=["cwe","webhound","mapping","scanner-findings","weakness"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/webhound-cwe-mapping.md"),
    dict(doc_id="pn-vt-cvss-usage-policy", title="WebHound CVSS Usage Policy",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/webhound-cvss-usage-policy.md",
         product_or_provider=None,
         topic_tags=["cvss","policy","webhound","reporting","non-cve"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/webhound-cvss-usage-policy.md"),
    dict(doc_id="pn-vt-when-not-to-assign-cve", title="When NOT to Assign a CVE",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/when-not-to-assign-cve.md",
         product_or_provider=None,
         topic_tags=["cve","policy","webhound","misconfiguration","missing-headers"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/when-not-to-assign-cve.md"),
    dict(doc_id="pn-vt-customer-safe-language", title="Customer-Safe Vulnerability Language",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/customer-safe-vulnerability-language.md",
         product_or_provider=None,
         topic_tags=["customer-reporting","severity","language","confirmed","possible"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/customer-safe-vulnerability-language.md"),
    dict(doc_id="pn-vt-wade-taxonomy-relevance", title="Vulnerability Taxonomy — WADE Relevance",
         source_name="WebHound AI Knowledge", source_url="knowledge/vulnerability-taxonomy/wade-taxonomy-relevance.md",
         product_or_provider=None,
         topic_tags=["wade","taxonomy","cwe","cve","cvss","kev","policy"],
         license_terms="Internal WebHound document.",
         normalized_path="knowledge/vulnerability-taxonomy/wade-taxonomy-relevance.md"),
]


def make_record(meta: dict, source_type: str, authority_tier: str, confidence: float) -> dict:
    norm_path = meta["normalized_path"]
    abs_path = os.path.join(ROOT, norm_path.replace("/", os.sep))
    content_hash = sha256_of_file(abs_path) if os.path.exists(abs_path) else "sha256:unknown"
    return {
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
        "verification_status": "verified" if source_type == "official_taxonomy_doc" else "needs_review",
        "license_terms": meta["license_terms"],
        "citability": "citable_external" if source_type == "official_taxonomy_doc" else "internal_only",
        "pii_risk_class": "none",
        "retention_class": "long",
        "entities": [meta["source_name"]],
        "related_docs": [],
        "trust_label": "trusted_external" if source_type == "official_taxonomy_doc" else "trusted_internal",
        "normalized_path": norm_path,
    }


def main() -> None:
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        existing_lines = f.readlines()
    print(f"Existing manifest records: {len(existing_lines)}")
    existing_ids = {json.loads(l)["doc_id"] for l in existing_lines}

    new_records: list[dict] = []
    all_chunks: list[dict] = []

    for meta in OFFICIAL_DOCS:
        if meta["doc_id"] in existing_ids:
            print(f"  SKIP: {meta['doc_id']}")
            continue
        r = make_record(meta, "official_taxonomy_doc", "A", 0.90)
        new_records.append(r)
        abs_path = os.path.join(ROOT, meta["normalized_path"].replace("/", os.sep))
        if os.path.exists(abs_path):
            text = open(abs_path, encoding="utf-8").read()
            all_chunks.extend(chunk_text(text, meta["doc_id"], meta.get("product_or_provider", "vt")))

    for meta in INTERNAL_DOCS:
        if meta["doc_id"] in existing_ids:
            print(f"  SKIP: {meta['doc_id']}")
            continue
        r = make_record(meta, "internal_doc", "B", 0.80)
        new_records.append(r)
        abs_path = os.path.join(ROOT, meta["normalized_path"].replace("/", os.sep))
        if os.path.exists(abs_path):
            text = open(abs_path, encoding="utf-8").read()
            all_chunks.extend(chunk_text(text, meta["doc_id"],
                                         meta.get("product_or_provider") or "vuln-taxonomy"))

    print(f"New records to append: {len(new_records)}")
    print(f"New chunks: {len(all_chunks)}")

    with open(MANIFEST_PATH, "a", encoding="utf-8") as f:
        for r in new_records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    with open(CHUNKS_PATH, "w", encoding="utf-8") as f:
        for c in all_chunks:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    total = len(existing_lines) + len(new_records)
    print(f"Manifest total: {total} records")
    print(f"Chunks written: {len(all_chunks)}")


if __name__ == "__main__":
    main()
