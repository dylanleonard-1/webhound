#!/usr/bin/env python3
"""Phase 6A — official Tier-A security-doc ingestion (EXTERNAL, controlled).

Ingests a SMALL, fixed allow-list of official, authoritative security docs
(OWASP + MDN) into the WebHound knowledge corpus as Tier-A `official_doc`
records. This is the FIRST phase permitted to fetch external content.

Design guarantees (Phase 6A constraints):
  * APPEND-ONLY to corpus/manifests/manifest.jsonl. The 211 internal records
    written in Phase 5A are NEVER rewritten and stay byte-stable. We open the
    manifest in append mode and only add records whose doc_id is not present.
  * The internal ingestion builder (ingest_internal_knowledge.py) is NOT run
    and its content hashes are NOT recomputed.
  * Raw fetched HTML/markdown is EPHEMERAL (kept under the OS temp dir, never
    committed). Only NORMALIZED text + chunks + manifest metadata are committed.
  * External content is EVIDENCE, never instructions. We store it as plain text
    and never execute it. No secrets, no customer data, no private scans.
  * Sources are PINNED to the exact upstream commit SHA at fetch time, so the
    committed artifacts are reproducible and auditable.

Network is used ONLY by the `run` command. Importing this module performs no
network I/O, so tests/CI (which read the committed artifacts offline) never
touch the network.

Usage:
  python scripts/ai/ingest_official_docs.py run            # fetch + normalize + chunk + append
  python scripts/ai/ingest_official_docs.py run --dry-run  # compute + report, write nothing
  python scripts/ai/ingest_official_docs.py query "What is CSP?"
  python scripts/ai/ingest_official_docs.py selftest       # offline retrieval smoke test
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

# Fixed ingestion stamp -> deterministic, idempotent manifest records.
INGEST_STAMP = "2026-06-13"

MANIFEST_PATH = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
# Committed normalized artifacts live here (one .md per doc + one chunks file).
NORM_DIR = os.path.join(ROOT, "corpus", "normalized", "docs", "official")
CHUNKS_PATH = os.path.join(NORM_DIR, "official_chunks.jsonl")
# Raw fetched content is ephemeral and NEVER committed.
RAW_WORK_DIR = os.path.join(tempfile.gettempdir(), "webhound_official_raw")

USER_AGENT = "WebHound-KnowledgeIngest/6A (+https://webhoundsecurity.com)"
HTTP_TIMEOUT = 30

# ---------------------------------------------------------------------------
# Allow-list: the ONLY sources Phase 6A may ingest. Adding anything else here
# (a GitHub repo, a threat feed, a provider doc, a paper) is OUT OF SCOPE and
# belongs to a later, separately-approved phase.
# ---------------------------------------------------------------------------
SOURCES = [
    {
        "doc_id": "owasp-wstg-readme",
        "title": "OWASP Web Security Testing Guide (WSTG) — Overview",
        "source_name": "OWASP Web Security Testing Guide (WSTG)",
        "repo": "OWASP/wstg", "branch": "master", "path": "README.md",
        "license_terms": "CC-BY-SA-4.0",
        "topic_tags": ["owasp", "wstg", "web-security-testing", "methodology"],
        "entities": ["OWASP", "WSTG"],
    },
    {
        "doc_id": "owasp-csp-cheat-sheet",
        "title": "OWASP Cheat Sheet Series — Content Security Policy",
        "source_name": "OWASP Cheat Sheet Series",
        "repo": "OWASP/CheatSheetSeries", "branch": "master",
        "path": "cheatsheets/Content_Security_Policy_Cheat_Sheet.md",
        "license_terms": "CC-BY-SA-4.0",
        "topic_tags": ["owasp", "cheat-sheet", "csp", "content-security-policy", "headers"],
        "entities": ["OWASP", "CSP"],
    },
    {
        "doc_id": "owasp-asvs-readme",
        "title": "OWASP Application Security Verification Standard (ASVS) — Overview",
        "source_name": "OWASP Application Security Verification Standard (ASVS)",
        "repo": "OWASP/ASVS", "branch": "master", "path": "README.md",
        "license_terms": "CC-BY-SA-4.0",
        "topic_tags": ["owasp", "asvs", "verification", "standard", "requirements"],
        "entities": ["OWASP", "ASVS"],
    },
    {
        "doc_id": "mdn-csp-guide",
        "title": "MDN — Content Security Policy (CSP)",
        "source_name": "MDN Web Docs",
        "repo": "mdn/content", "branch": "main",
        "path": "files/en-us/web/http/guides/csp/index.md",
        "license_terms": "CC-BY-SA-2.5",
        "topic_tags": ["mdn", "csp", "content-security-policy", "headers", "browser-security"],
        "entities": ["MDN", "CSP"],
    },
    {
        "doc_id": "mdn-cors-guide",
        "title": "MDN — Cross-Origin Resource Sharing (CORS)",
        "source_name": "MDN Web Docs",
        "repo": "mdn/content", "branch": "main",
        "path": "files/en-us/web/http/guides/cors/index.md",
        "license_terms": "CC-BY-SA-2.5",
        "topic_tags": ["mdn", "cors", "cross-origin", "headers", "browser-security"],
        "entities": ["MDN", "CORS"],
    },
    {
        "doc_id": "mdn-subresource-integrity",
        "title": "MDN — Subresource Integrity (SRI)",
        "source_name": "MDN Web Docs",
        "repo": "mdn/content", "branch": "main",
        "path": "files/en-us/web/security/defenses/subresource_integrity/index.md",
        "license_terms": "CC-BY-SA-2.5",
        "topic_tags": ["mdn", "sri", "subresource-integrity", "integrity", "supply-chain"],
        "entities": ["MDN", "SRI"],
    },
]

# Shared, fixed metadata for every Phase-6A official record.
COMMON = {
    "source_type": "official_doc",
    "doc_role": "canonical_note",
    "authority_tier": "A",
    "language": "en",
    "product_or_provider": None,
    "confidence_score": 0.9,
    "verification_status": "verified",
    "citability": "citable_external",
    "pii_risk_class": "none",
    "retention_class": "long",
    "trust_label": "trusted_external",
}

STOP = set("a an the is are was were of to and or in on for with not no this that it "
           "as by be at from we you your our can will may should if then so".split())


# ---------------------------------------------------------------------------
# Fetch (network — `run` only)
# ---------------------------------------------------------------------------
def _http_get(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:  # noqa: S310 (allow-list URLs)
        return r.read().decode("utf-8", "replace")


def resolve_pin(src: dict) -> tuple[str | None, str | None]:
    """Return (commit_sha, commit_date_iso) for the file's latest upstream
    commit, or (None, None) if the GitHub API is unavailable (e.g. rate limit).
    Used purely for provenance + reproducible pinning."""
    api = (f"https://api.github.com/repos/{src['repo']}/commits"
           f"?path={src['path']}&per_page=1&sha={src['branch']}")
    try:
        data = json.loads(_http_get(api))
        if isinstance(data, list) and data:
            sha = data[0].get("sha")
            date = (data[0].get("commit", {}) or {}).get("committer", {}).get("date")
            return sha, date
    except Exception as e:  # noqa: BLE001
        print(f"  [warn] could not pin {src['doc_id']} ({e}); falling back to branch HEAD")
    return None, None


def raw_url(src: dict, sha: str | None) -> str:
    ref = sha or src["branch"]
    return f"https://raw.githubusercontent.com/{src['repo']}/{ref}/{src['path']}"


# ---------------------------------------------------------------------------
# Normalize — external markdown -> plain evidence text (no execution, ever)
# ---------------------------------------------------------------------------
def normalize(raw: str) -> str:
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    # 1) drop leading YAML front matter (MDN pages start with --- ... ---)
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            text = text[end + 5:]
    # 2) strip HTML comments
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    # 3) flatten MDN KumaScript macros: {{Glossary("CORS")}} -> CORS,
    #    {{HTTPHeader("Content-Security-Policy")}} -> Content-Security-Policy
    def _macro(m: re.Match) -> str:
        inner = m.group(1)
        q = re.search(r'"([^"]+)"', inner)
        if q:
            return q.group(1)
        q = re.search(r"\(([^)]*)\)", inner)
        return q.group(1).strip() if q else ""
    text = re.sub(r"\{\{(.*?)\}\}", _macro, text, flags=re.DOTALL)
    # 4) drop raw HTML tags but keep their text content
    text = re.sub(r"<[^>]+>", "", text)
    # 5) collapse trailing whitespace + excess blank lines
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text + "\n"


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Chunk — heading-aware, with min-length filter + dedup
# ---------------------------------------------------------------------------
CHUNK_TARGET = 1500
CHUNK_MIN = 200


def chunk_text(doc_id: str, text: str) -> list[dict]:
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks, buf = [], ""
    for p in paras:
        if buf and len(buf) + len(p) + 2 > CHUNK_TARGET:
            chunks.append(buf)
            buf = p
        else:
            buf = f"{buf}\n\n{p}" if buf else p
    if buf:
        chunks.append(buf)

    out, seen = [], set()
    for c in chunks:
        c = c.strip()
        key = re.sub(r"\s+", " ", c.lower())
        if len(c) < CHUNK_MIN or key in seen:
            continue
        seen.add(key)
        out.append({
            "chunk_id": f"{doc_id}::{len(out):03d}",
            "doc_id": doc_id,
            "ordinal": len(out),
            "char_len": len(c),
            "text": c,
        })
    return out


# ---------------------------------------------------------------------------
# Manifest record assembly
# ---------------------------------------------------------------------------
def build_record(src: dict, content_hash: str, url: str,
                 sha: str | None, date: str | None) -> dict:
    return {
        "doc_id": src["doc_id"],
        "title": src["title"],
        "source_name": src["source_name"],
        "source_url": url,
        "source_type": COMMON["source_type"],
        "doc_role": COMMON["doc_role"],
        "authority_tier": COMMON["authority_tier"],
        "language": COMMON["language"],
        "product_or_provider": COMMON["product_or_provider"],
        "topic_tags": src["topic_tags"],
        "version": (sha[:12] if sha else None),
        "last_updated": date,
        "first_ingested": INGEST_STAMP,
        "content_hash": content_hash,
        "confidence_score": COMMON["confidence_score"],
        "verification_status": COMMON["verification_status"],
        "license_terms": src["license_terms"],
        "citability": COMMON["citability"],
        "pii_risk_class": COMMON["pii_risk_class"],
        "retention_class": COMMON["retention_class"],
        "entities": src["entities"],
        "related_docs": [],
        "trust_label": COMMON["trust_label"],
    }


def norm_path(doc_id: str) -> str:
    """Committed, local normalized artifact for a doc_id (the locality anchor
    for external records — see tests/ai)."""
    return os.path.join(NORM_DIR, f"{doc_id}.md")


# ---------------------------------------------------------------------------
# Existing-manifest helpers (read-only; append-only writes)
# ---------------------------------------------------------------------------
def existing_doc_ids() -> set[str]:
    ids: set[str] = set()
    if not os.path.exists(MANIFEST_PATH):
        return ids
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                ids.add(json.loads(line)["doc_id"])
    return ids


def _ensure_trailing_newline(path: str) -> None:
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path, "rb") as f:
            f.seek(-1, os.SEEK_END)
            last = f.read(1)
        if last != b"\n":
            with open(path, "a", encoding="utf-8") as f:
                f.write("\n")


def append_manifest(records: list[dict]) -> None:
    if not records:
        return
    _ensure_trailing_newline(MANIFEST_PATH)
    with open(MANIFEST_PATH, "a", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Retrieval (offline; over committed chunks) — small BM25-ish term overlap
# ---------------------------------------------------------------------------
def _terms(s: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9]+", s.lower()) if w not in STOP and len(w) > 1]


def load_chunks() -> list[dict]:
    if not os.path.exists(CHUNKS_PATH):
        return []
    rows = []
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def retrieve(chunks: list[dict], query: str, k: int = 5) -> list[dict]:
    q = set(_terms(query))
    scored = []
    for c in chunks:
        ct = _terms(c["text"]) + _terms(c["doc_id"].replace("-", " "))
        if not ct:
            continue
        tf: dict[str, int] = {}
        for w in ct:
            tf[w] = tf.get(w, 0) + 1
        score = sum(tf.get(w, 0) for w in q) / (1 + (len(ct) / 500.0))
        if score > 0:
            scored.append((score, c))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in scored[:k]]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_run(args) -> int:
    have = existing_doc_ids()
    os.makedirs(RAW_WORK_DIR, exist_ok=True)
    new_records, all_chunks, summary = [], [], []

    for src in SOURCES:
        sha, date = resolve_pin(src)  # pin to upstream commit for reproducibility
        url = raw_url(src, sha)
        raw = _http_get(url)
        # raw -> ephemeral temp (NEVER committed)
        with open(os.path.join(RAW_WORK_DIR, f"{src['doc_id']}.raw.md"), "w",
                  encoding="utf-8") as f:
            f.write(raw)
        norm = normalize(raw)
        chash = _sha256(norm.encode("utf-8"))
        chunks = chunk_text(src["doc_id"], norm)
        all_chunks.extend(chunks)
        rec = build_record(src, chash, url, sha, date)
        already = src["doc_id"] in have
        if not already:
            new_records.append((rec, norm))
        summary.append({
            "doc_id": src["doc_id"], "pinned": bool(sha), "chunks": len(chunks),
            "chars": len(norm), "already_in_manifest": already,
        })
        print(f"  [{'skip' if already else 'new '}] {src['doc_id']:28s} "
              f"chars={len(norm):6d} chunks={len(chunks):3d} pin={(sha or 'HEAD')[:12]}")

    print(f"\n[summary] sources={len(SOURCES)} new_records={len(new_records)} "
          f"total_chunks={len(all_chunks)}")

    if args.dry_run:
        print("[dry-run] nothing written.")
        return 0

    # write committed artifacts: per-doc normalized .md + chunks jsonl,
    # rebuilt deterministically from the ephemeral raw fetch.
    os.makedirs(NORM_DIR, exist_ok=True)
    for src in SOURCES:
        with open(norm_path(src["doc_id"]), "w", encoding="utf-8", newline="\n") as f:
            f.write(normalize(_read_raw(src["doc_id"])))
    with open(CHUNKS_PATH, "w", encoding="utf-8", newline="\n") as f:
        for c in all_chunks:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    append_manifest([r for r, _ in new_records])
    print(f"[ok] wrote {len(SOURCES)} normalized docs -> {os.path.relpath(NORM_DIR, ROOT)}/")
    print(f"[ok] wrote {len(all_chunks)} chunks -> {os.path.relpath(CHUNKS_PATH, ROOT)}")
    print(f"[ok] appended {len(new_records)} records -> "
          f"{os.path.relpath(MANIFEST_PATH, ROOT)} (existing records untouched)")
    return 0


def _read_raw(doc_id: str) -> str:
    with open(os.path.join(RAW_WORK_DIR, f"{doc_id}.raw.md"), encoding="utf-8") as f:
        return f.read()


def cmd_query(args) -> int:
    chunks = load_chunks()
    if not chunks:
        print("[error] no committed chunks; run `ingest_official_docs.py run` first.")
        return 1
    hits = retrieve(chunks, args.query, k=args.k)
    print(f"query: {args.query!r}")
    for i, c in enumerate(hits, 1):
        snippet = re.sub(r"\s+", " ", c["text"])[:140]
        print(f"  {i}. [{c['doc_id']}] {snippet}...")
    return 0


SELFTEST = [
    ("What is Content Security Policy?", "mdn-csp-guide"),
    ("How does Cross-Origin Resource Sharing work?", "mdn-cors-guide"),
    ("What is Subresource Integrity and the integrity attribute?", "mdn-subresource-integrity"),
    ("OWASP web security testing guide methodology", "owasp-wstg-readme"),
    ("Application Security Verification Standard requirements levels", "owasp-asvs-readme"),
    ("CSP cheat sheet nonce and hash directives", "owasp-csp-cheat-sheet"),
]


def cmd_selftest(args) -> int:
    chunks = load_chunks()
    if not chunks:
        print("[error] no committed chunks; run `run` first.")
        return 1
    top1 = top3 = 0
    for q, want in SELFTEST:
        hits = retrieve(chunks, q, k=3)
        ids = [h["doc_id"] for h in hits]
        if ids[:1] == [want]:
            top1 += 1
        if want in ids:
            top3 += 1
        mark = "OK " if want in ids else "MISS"
        print(f"  [{mark}] want={want:28s} got={ids}")
    n = len(SELFTEST)
    print(f"\n[selftest] top1={top1}/{n} top3={top3}/{n}")
    return 0 if top3 == n else 1


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="Phase 6A official Tier-A doc ingestion")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="fetch + normalize + chunk + append (network)")
    r.add_argument("--dry-run", action="store_true", help="compute + report, write nothing")
    r.set_defaults(func=cmd_run)
    q = sub.add_parser("query", help="offline retrieval over committed chunks")
    q.add_argument("query")
    q.add_argument("-k", type=int, default=5)
    q.set_defaults(func=cmd_query)
    s = sub.add_parser("selftest", help="offline retrieval smoke test")
    s.set_defaults(func=cmd_selftest)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
