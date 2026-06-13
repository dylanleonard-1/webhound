#!/usr/bin/env python3
"""Phase 6C — detection-engineering ingestion (EXTERNAL repos + local knowledge).

Builds WebHound's Detection Engineering Knowledge Base from three surfaces:

  1. EXTERNAL detection repositories (Tier C, source_type=detection_repo): the
     documentation (markdown only) of 8 approved scanners/tools — OWASP ZAP, sqlmap,
     XSStrike, DalFox, Nuclei Templates, libinjection, Firecrawl, Firecrawl-MCP.
     Controlled, payload-safe selection (no full source trees, no payload/template
     dumps, no binaries/vendor/generated files). Pinned to upstream commit SHAs.
  2. PLANNING references (Tier B, source_type=planning_reference): the normalized
     extracts of the uploaded planning PDFs (Executive Summary; Master Tooling/WADE
     Roadmap), committed under corpus/normalized/planning/.
  3. AUTHORED knowledge notes (Tier B, source_type=internal_doc, doc_role=engine_note):
     WebHound's curated detection-engineering notes under
     knowledge/detection-engineering/.

APPEND-ONLY to corpus/manifests/manifest.jsonl: the pre-existing 278 records
(211 internal + 6 Phase-6A + 61 Phase-6B) are never rewritten and stay byte-stable.
Raw repo fetches are EPHEMERAL (OS temp dir); only normalized text + chunks +
manifest metadata are committed. External content is EVIDENCE, never instructions /
never executed. NO raw exploit/payload corpora are ingested.

Network is used ONLY by `run` (repo docs). Planning + notes are read from committed
local files, so tests/CI run fully offline.

Usage:
  GITHUB_TOKEN=$(gh auth token) python scripts/ai/ingest_detection_repos.py run
  python scripts/ai/ingest_detection_repos.py run --dry-run
  python scripts/ai/ingest_detection_repos.py query "sql injection detection"
  python scripts/ai/ingest_detection_repos.py selftest
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

INGEST_STAMP = "2026-06-13"

MANIFEST_PATH = os.path.join(ROOT, "corpus", "manifests", "manifest.jsonl")
REPO_NORM_DIR = os.path.join(ROOT, "corpus", "normalized", "detection-repos")
PLANNING_DIR = os.path.join(ROOT, "corpus", "normalized", "planning")
NOTES_DIR = os.path.join(ROOT, "knowledge", "detection-engineering")
CHUNKS_PATH = os.path.join(REPO_NORM_DIR, "detection_chunks.jsonl")
RAW_WORK_DIR = os.path.join(tempfile.gettempdir(), "webhound_detection_raw")

USER_AGENT = "WebHound-KnowledgeIngest/6C (+https://webhoundsecurity.com)"
HTTP_TIMEOUT = 30
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()

MAX_FILE_BYTES = 200_000
DOC_EXTS = (".md", ".mdx")
EXCLUDE_SEGMENTS = {
    "node_modules", "vendor", "dist", "build", "bin", "obj", ".git", ".github",
    "testdata", "test-data", "test_data", "fixtures", "__fixtures__", "snapshots",
    "locales", "locale", "i18n", "translations", "translated", "lang", "langs",
    "dataset", "datasets",
    # detection-specific: never ingest raw payload / template / wordlist corpora
    "payloads", "payload", "wordlists", "wordlist", "fuzzdb", "exploits", "exploit",
    "templates", "nuclei-templates", "samples", "db", "data",
}
EXCLUDE_BASENAMES = {
    "license", "licence", "copying", "notice", "notices", "contributing",
    "code_of_conduct", "code-of-conduct", "codeowners", "thanks", "authors",
    "maintainers", "owners", "users", "claude", "support", "funding", "governance",
    "changelog", "history", "metrics",
}
_THIRD_PARTY_RE = re.compile(r"third[-_]party[-_](licen|notice)", re.IGNORECASE)
_LOCALIZED_RE = re.compile(
    r"[._-](zh|cn|tw|ja|jp|ko|kr|fr|de|es|pt|ru|it|tr|pl|id|hi|ar|vi|th|nl|"
    r"uk|fa|bn)(-[a-z]{2})?\.mdx?$", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Approved detection repositories (Phase 6C). Markdown DOCS only.
# ---------------------------------------------------------------------------
REPOS = [
    {"slug": "zap", "repo": "zaproxy/zaproxy", "max_files": 10,
     "product": "owasp-zap",
     "tags": ["detection-engineering", "scanner-design", "active-scanning",
              "passive-scanning", "evidence-models", "confidence-models", "zap"],
     "entities": ["OWASP", "ZAP"]},
    {"slug": "sqlmap", "repo": "sqlmapproject/sqlmap", "max_files": 10,
     "product": "sqlmap",
     "tags": ["detection-engineering", "sql-injection", "fuzzing",
              "confidence-models", "false-positive-reduction", "sqlmap"],
     "entities": ["sqlmap"]},
    {"slug": "xsstrike", "repo": "s0md3v/XSStrike", "max_files": 8,
     "product": "xsstrike",
     "tags": ["detection-engineering", "xss", "dom-xss", "payload-generation",
              "browser-analysis", "xsstrike"],
     "entities": ["XSStrike"]},
    {"slug": "dalfox", "repo": "hahwul/dalfox", "max_files": 10,
     "product": "dalfox",
     "tags": ["detection-engineering", "xss", "dom-xss", "payload-validation",
              "false-positive-reduction", "dalfox"],
     "entities": ["DalFox"]},
    {"slug": "nuclei-templates", "repo": "projectdiscovery/nuclei-templates",
     "max_files": 8, "product": "nuclei-templates",
     "tags": ["detection-engineering", "template-matching", "nuclei-templates",
              "signature-analysis", "severity-modeling"],
     "entities": ["ProjectDiscovery", "Nuclei"]},
    {"slug": "libinjection", "repo": "libinjection/libinjection", "max_files": 8,
     "product": "libinjection",
     "tags": ["detection-engineering", "signature-analysis", "sql-injection",
              "xss", "libinjection"],
     "entities": ["libinjection"]},
    {"slug": "firecrawl", "repo": "firecrawl/firecrawl", "max_files": 10,
     "product": "firecrawl",
     "tags": ["detection-engineering", "content-extraction", "browser-validation",
              "crawling", "firecrawl"],
     "entities": ["Firecrawl"]},
    {"slug": "firecrawl-mcp", "repo": "firecrawl/firecrawl-mcp-server", "max_files": 8,
     "product": "firecrawl-mcp",
     "tags": ["detection-engineering", "mcp", "content-extraction", "firecrawl"],
     "entities": ["Firecrawl", "MCP"]},
]

# Planning references (committed local normalized artifacts -> records).
PLANNING = [
    {"doc_id": "plan-executive-summary", "file": "executive-summary.md",
     "source_name": "Executive Summary.pdf", "source_key": "executive-summary",
     "title": "Executive Summary — Detection Engineering Survey (planning reference)",
     "tags": ["detection-engineering", "scanner-design", "modern-scanner-design",
              "static-vs-dynamic", "hybrid-architecture"],
     "entities": ["WebHound", "Executive Summary"]},
    {"doc_id": "plan-master-tooling-roadmap", "file": "master-tooling-wade-roadmap.md",
     "source_name": "WebHound Master Tooling + Knowledge + WADE Roadmap.pdf",
     "source_key": "master-tooling",
     "title": "WebHound Master Tooling + Knowledge + WADE Roadmap (planning reference)",
     "tags": ["detection-engineering", "roadmap", "wade", "scanner-audit"],
     "entities": ["WebHound", "WADE", "Roadmap"]},
]

# slug -> retrieval source_key + tags (for repo records / retrieval tag-boost)
SOURCE_TAGS = {r["slug"]: set(r["tags"]) for r in REPOS}
SOURCE_TAGS.update({p["source_key"]: set(p["tags"]) for p in PLANNING})

NOTE_TOOL_PREFIXES = [
    ("firecrawl-mcp-", "firecrawl-mcp"), ("firecrawl-", "firecrawl"),
    ("zap-", "zap"), ("sqlmap-", "sqlmap"), ("xsstrike-", "xsstrike"),
    ("dalfox-", "dalfox"), ("nuclei-", "nuclei-templates"),
    ("libinjection-", "libinjection"),
]

REPO_COMMON = {
    "source_type": "detection_repo", "authority_tier": "C", "language": "en",
    "doc_role": "engine_note", "confidence_score": 0.75,
    "verification_status": "verified", "citability": "citable_external",
    "pii_risk_class": "none", "retention_class": "long",
    "trust_label": "trusted_external",
}
PLAN_COMMON = {
    "source_type": "planning_reference", "authority_tier": "B", "language": "en",
    "doc_role": "phase_result_report", "confidence_score": 0.7,
    "verification_status": "verified", "citability": "citable_external",
    "pii_risk_class": "none", "retention_class": "long",
    "trust_label": "trusted_local",
}
NOTE_COMMON = {
    "source_type": "internal_doc", "authority_tier": "B", "language": "en",
    "doc_role": "engine_note", "confidence_score": 0.8,
    "verification_status": "verified", "citability": "citable_internal",
    "pii_risk_class": "none", "retention_class": "long",
    "trust_label": "trusted_local",
}

STOP = set((
    "a an the is are was were of to and or in on for with not no this that it "
    "as by be at from we you your our can will may should if then so "
    "what which who whom where when how why repository repositories repo repos "
    "help helps helping document documents documentation explain explains "
    "teach teaches relevant most more used use using work works does do did "
    "about into onto via per best useful"
).split())
TAG_BONUS = 8.0


# ---------------------------------------------------------------------------
# GitHub API (network — `run` only)
# ---------------------------------------------------------------------------
def _http(url: str, accept: str = "application/vnd.github+json") -> bytes:
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:  # noqa: S310
        return r.read()


def _api_json(url: str) -> object:
    return json.loads(_http(url).decode("utf-8", "replace"))


def repo_head(repo: str) -> tuple[str, str, str]:
    meta = _api_json(f"https://api.github.com/repos/{repo}")
    branch = meta.get("default_branch", "main")
    commit = _api_json(f"https://api.github.com/repos/{repo}/commits/{branch}")
    sha = commit["sha"]
    date = (commit.get("commit", {}) or {}).get("committer", {}).get("date")
    return branch, sha, date


def repo_license(repo: str) -> str:
    try:
        lic = _api_json(f"https://api.github.com/repos/{repo}/license")
        spdx = (lic.get("license") or {}).get("spdx_id")
        if spdx and spdx not in ("NOASSERTION", "NONE"):
            return spdx
    except Exception:  # noqa: BLE001
        pass
    return "manual_required"


def repo_tree(repo: str, sha: str) -> tuple[list[dict], bool]:
    data = _api_json(f"https://api.github.com/repos/{repo}/git/trees/{sha}?recursive=1")
    return data.get("tree", []), bool(data.get("truncated"))


def raw_url(repo: str, sha: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"


# ---------------------------------------------------------------------------
# Controlled, payload-safe file selection (markdown docs only)
# ---------------------------------------------------------------------------
def _excluded(path: str) -> bool:
    segs = [s.lower() for s in path.split("/")]
    if any(s in EXCLUDE_SEGMENTS for s in segs):
        return True
    base = os.path.basename(path)
    if _LOCALIZED_RE.search(base):
        return True
    stem = re.sub(r"\.(md|mdx)$", "", base, flags=re.IGNORECASE).lower()
    if stem in EXCLUDE_BASENAMES or _THIRD_PARTY_RE.search(stem):
        return True
    return False


def _priority(path: str) -> int:
    base = os.path.basename(path).lower()
    depth = path.count("/")
    if depth == 0 and base == "readme.md":
        return 0
    if depth == 0 and base == "security.md":
        return 1
    if depth == 0:
        return 2
    if path.lower().startswith(("docs/", "doc/", "documentation/")):
        return 3
    return 4


def select_files(tree: list[dict], max_files: int) -> tuple[list[str], dict]:
    cands, too_big, excluded = [], 0, 0
    for node in tree:
        if node.get("type") != "blob":
            continue
        path = node["path"]
        if not path.lower().endswith(DOC_EXTS):
            continue
        if _excluded(path):
            excluded += 1
            continue
        if int(node.get("size", 0)) > MAX_FILE_BYTES:
            too_big += 1
            continue
        cands.append(path)
    cands.sort(key=lambda p: (_priority(p), p.count("/"), p.lower()))
    kept = cands[:max_files]
    return kept, {"candidates": len(cands), "kept": len(kept),
                  "skipped_over_cap": max(0, len(cands) - len(kept)),
                  "skipped_too_big": too_big, "skipped_excluded": excluded}


def doc_id_for(slug: str, path: str, seen: set[str]) -> str:
    stem = re.sub(r"\.(md|mdx)$", "", path, flags=re.IGNORECASE)
    sp = re.sub(r"[^a-z0-9]+", "-", stem.lower()).strip("-")
    did = base = f"det-{slug}--{sp}"
    n = 1
    while did in seen:
        n += 1
        did = f"{base}-{n}"
    seen.add(did)
    return did


# ---------------------------------------------------------------------------
# Normalize / chunk / hash
# ---------------------------------------------------------------------------
def normalize(raw: str) -> str:
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            text = text[end + 5:]
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]+>", "", text)
    text = "\n".join(line.rstrip() for line in text.split("\n"))
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text + "\n"


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


CHUNK_TARGET = 1500
CHUNK_MIN = 200


def chunk_text(doc_id: str, source_key: str, text: str) -> list[dict]:
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
        out.append({"chunk_id": f"{doc_id}::{len(out):03d}", "doc_id": doc_id,
                    "source_key": source_key, "ordinal": len(out),
                    "char_len": len(c), "text": c})
    return out


# ---------------------------------------------------------------------------
# Manifest records
# ---------------------------------------------------------------------------
def _rel(path: str) -> str:
    return os.path.relpath(path, ROOT).replace("\\", "/")


def repo_record(cfg, doc_id, path, url, chash, sha, date, lic) -> dict:
    return {
        "doc_id": doc_id, "title": f"{cfg['repo']} — {path}",
        "source_name": cfg["repo"], "source_url": url,
        "source_type": REPO_COMMON["source_type"], "doc_role": REPO_COMMON["doc_role"],
        "authority_tier": REPO_COMMON["authority_tier"], "language": "en",
        "product_or_provider": cfg["product"], "topic_tags": cfg["tags"],
        "version": sha[:12], "last_updated": date, "first_ingested": INGEST_STAMP,
        "content_hash": chash, "confidence_score": REPO_COMMON["confidence_score"],
        "verification_status": REPO_COMMON["verification_status"], "license_terms": lic,
        "citability": REPO_COMMON["citability"], "pii_risk_class": "none",
        "retention_class": "long", "entities": cfg["entities"] + [path],
        "related_docs": [], "trust_label": REPO_COMMON["trust_label"],
    }


def planning_record(p, chash) -> dict:
    rel = _rel(os.path.join(PLANNING_DIR, p["file"]))
    return {
        "doc_id": p["doc_id"], "title": p["title"], "source_name": p["source_name"],
        "source_url": rel, "source_type": PLAN_COMMON["source_type"],
        "doc_role": PLAN_COMMON["doc_role"], "authority_tier": PLAN_COMMON["authority_tier"],
        "language": "en", "product_or_provider": "webhound-planning",
        "topic_tags": p["tags"], "version": INGEST_STAMP, "last_updated": INGEST_STAMP,
        "first_ingested": INGEST_STAMP, "content_hash": chash,
        "confidence_score": PLAN_COMMON["confidence_score"],
        "verification_status": PLAN_COMMON["verification_status"],
        "license_terms": "internal-planning", "citability": PLAN_COMMON["citability"],
        "pii_risk_class": "none", "retention_class": "long", "entities": p["entities"],
        "related_docs": [], "trust_label": PLAN_COMMON["trust_label"],
    }


def note_record(doc_id, rel, title, source_key, chash) -> dict:
    return {
        "doc_id": doc_id, "title": title, "source_name": "WebHound Detection Engineering",
        "source_url": rel, "source_type": NOTE_COMMON["source_type"],
        "doc_role": NOTE_COMMON["doc_role"], "authority_tier": NOTE_COMMON["authority_tier"],
        "language": "en", "product_or_provider": source_key,
        "topic_tags": sorted(SOURCE_TAGS.get(source_key, {"detection-engineering"})),
        "version": INGEST_STAMP, "last_updated": INGEST_STAMP,
        "first_ingested": INGEST_STAMP, "content_hash": chash,
        "confidence_score": NOTE_COMMON["confidence_score"],
        "verification_status": NOTE_COMMON["verification_status"],
        "license_terms": "internal", "citability": NOTE_COMMON["citability"],
        "pii_risk_class": "none", "retention_class": "long",
        "entities": [source_key, "detection-engineering"], "related_docs": [],
        "trust_label": NOTE_COMMON["trust_label"],
    }


def repo_norm_path(doc_id: str) -> str:
    return os.path.join(REPO_NORM_DIR, f"{doc_id}.md")


def note_source_key(filename: str) -> str:
    base = filename.lower()
    for prefix, key in NOTE_TOOL_PREFIXES:
        if base.startswith(prefix):
            return key
    return "executive-summary"  # planning-derived notes


# ---------------------------------------------------------------------------
# Manifest helpers (append-only)
# ---------------------------------------------------------------------------
def existing_doc_ids() -> set[str]:
    ids: set[str] = set()
    if os.path.exists(MANIFEST_PATH):
        with open(MANIFEST_PATH, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    ids.add(json.loads(line)["doc_id"])
    return ids


def _ensure_trailing_newline(path: str) -> None:
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path, "rb") as f:
            f.seek(-1, os.SEEK_END)
            if f.read(1) != b"\n":
                with open(path, "a", encoding="utf-8") as g:
                    g.write("\n")


def append_manifest(records: list[dict]) -> None:
    if not records:
        return
    _ensure_trailing_newline(MANIFEST_PATH)
    with open(MANIFEST_PATH, "a", encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def iter_notes() -> list[tuple[str, str]]:
    """(abs_path, rel_path) for every authored detection note (not READMEs)."""
    out = []
    for dp, _d, files in os.walk(NOTES_DIR):
        for fn in files:
            if fn.endswith(".md") and fn.lower() not in ("readme.md", "index.md"):
                ap = os.path.join(dp, fn)
                out.append((ap, _rel(ap)))
    return sorted(out, key=lambda x: x[1])


# ---------------------------------------------------------------------------
# Retrieval (offline; over committed chunks; IDF + stem + tag boost)
# ---------------------------------------------------------------------------
def _stem(w: str) -> str:
    if len(w) > 4 and w.endswith("s") and not w.endswith("ss"):
        return w[:-1]
    return w


def _terms(s: str) -> list[str]:
    return [_stem(w) for w in re.findall(r"[a-z0-9]+", s.lower())
            if w not in STOP and len(w) > 1]


def load_chunks() -> list[dict]:
    if not os.path.exists(CHUNKS_PATH):
        return []
    rows = []
    with open(CHUNKS_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _build_idf(chunks: list[dict]) -> dict[str, float]:
    df: dict[str, int] = {}
    for c in chunks:
        for w in set(_terms(c["text"])):
            df[w] = df.get(w, 0) + 1
    n = max(1, len(chunks))
    return {w: math.log(1 + n / d) for w, d in df.items()}


def _chunk_score(c: dict, qterms: set[str], idf: dict[str, float]) -> float:
    ct = _terms(c["text"]) + 3 * _terms(c["source_key"].replace("-", " "))
    if not ct:
        return 0.0
    tf: dict[str, int] = {}
    for w in ct:
        tf[w] = tf.get(w, 0) + 1
    denom = 1 + (len(ct) / 500.0)
    return sum(tf.get(w, 0) * idf.get(w, math.log(2)) for w in qterms) / denom


def retrieve(chunks: list[dict], query: str, k: int = 5) -> list[dict]:
    idf = _build_idf(chunks)
    qt = set(_terms(query))
    scored = [(_chunk_score(c, qt, idf), c) for c in chunks]
    scored = [(s, c) for s, c in scored if s > 0]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [c for _, c in scored[:k]]


def retrieve_sources(chunks: list[dict], query: str, k: int = 3) -> list[str]:
    idf = _build_idf(chunks)
    qt = set(_terms(query))
    best: dict[str, float] = {}
    for c in chunks:
        s = _chunk_score(c, qt, idf)
        if s <= 0:
            continue
        r = c["source_key"]
        if s > best.get(r, 0.0):
            best[r] = s
    for key, tags in SOURCE_TAGS.items():
        overlap = len(qt & set(_terms(" ".join(tags))))
        if overlap:
            best[key] = best.get(key, 0.0) + overlap * TAG_BONUS
    return sorted(best, key=lambda r: best[r], reverse=True)[:k]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_run(args) -> int:
    have = existing_doc_ids()
    os.makedirs(RAW_WORK_DIR, exist_ok=True)
    new_records, all_chunks, summaries = [], [], []
    repo_norm: dict[str, str] = {}
    seen: set[str] = set()

    # 1) external detection repos (network) -----------------------------------
    for cfg in REPOS:
        repo = cfg["repo"]
        branch, sha, date = repo_head(repo)
        lic = repo_license(repo)
        tree, truncated = repo_tree(repo, sha)
        kept, rep = select_files(tree, cfg["max_files"])
        rnew = 0
        for path in kept:
            try:
                raw = _http(raw_url(repo, sha, path), accept="text/plain").decode(
                    "utf-8", "replace")
            except Exception as e:  # noqa: BLE001
                print(f"    [warn] fetch failed {repo}/{path}: {e}")
                continue
            doc_id = doc_id_for(cfg["slug"], path, seen)
            norm = normalize(raw)
            ch = chunk_text(doc_id, cfg["slug"], norm)
            if not ch:
                continue
            all_chunks.extend(ch)
            repo_norm[doc_id] = norm
            rec = repo_record(cfg, doc_id, path, raw_url(repo, sha, path),
                              _sha256(norm.encode()), sha, date, lic)
            if doc_id not in have:
                new_records.append(rec)
                rnew += 1
        summaries.append({"repo": repo, "slug": cfg["slug"], "pin": sha[:12],
                          "license": lic, "new_records": rnew, **rep})
        print(f"  [{cfg['slug']:15s}] pin={sha[:12]} lic={lic:14s} kept={rep['kept']:2d}"
              f" new={rnew:2d} skip(cap/big/excl)={rep['skipped_over_cap']}/"
              f"{rep['skipped_too_big']}/{rep['skipped_excluded']}")

    # 2) planning references (local) -----------------------------------------
    for p in PLANNING:
        fp = os.path.join(PLANNING_DIR, p["file"])
        norm = normalize(open(fp, encoding="utf-8").read())
        all_chunks.extend(chunk_text(p["doc_id"], p["source_key"], norm))
        if p["doc_id"] not in have:
            new_records.append(planning_record(p, _sha256(norm.encode())))

    # 3) authored knowledge notes (local) ------------------------------------
    note_count = 0
    for ap, rel in iter_notes():
        text = open(ap, encoding="utf-8").read()
        norm = normalize(text)
        sk = note_source_key(os.path.basename(ap))
        doc_id = "de-" + re.sub(r"[^a-z0-9]+", "-",
                                rel[len("knowledge/"):].lower()).strip("-")
        title = next((ln[2:].strip() for ln in text.splitlines()
                      if ln.startswith("# ")), os.path.basename(ap))
        all_chunks.extend(chunk_text(doc_id, sk, norm))
        if doc_id not in have:
            new_records.append(note_record(doc_id, rel, title, sk,
                                            _sha256(norm.encode())))
        note_count += 1

    print(f"\n[summary] repos={len(REPOS)} planning={len(PLANNING)} notes={note_count}"
          f" new_records={len(new_records)} chunks={len(all_chunks)}")
    if args.dry_run:
        print("[dry-run] nothing written.")
        return 0

    os.makedirs(REPO_NORM_DIR, exist_ok=True)
    for doc_id, norm in repo_norm.items():
        with open(repo_norm_path(doc_id), "w", encoding="utf-8", newline="\n") as f:
            f.write(norm)
    with open(CHUNKS_PATH, "w", encoding="utf-8", newline="\n") as f:
        for c in all_chunks:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")
    with open(os.path.join(REPO_NORM_DIR, "ingest_summary.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump({"stamp": INGEST_STAMP, "repos": summaries,
                   "planning": len(PLANNING), "notes": note_count,
                   "new_records": len(new_records), "chunks": len(all_chunks)},
                  f, ensure_ascii=False, indent=2)
        f.write("\n")
    append_manifest(new_records)
    print(f"[ok] wrote {len(repo_norm)} repo docs, {len(all_chunks)} chunks; "
          f"appended {len(new_records)} records (existing untouched)")
    return 0


def cmd_query(args) -> int:
    chunks = load_chunks()
    if not chunks:
        print("[error] no committed chunks; run `... run` first.")
        return 1
    print(f"query: {args.query!r}  -> sources: {retrieve_sources(chunks, args.query)}")
    for i, c in enumerate(retrieve(chunks, args.query, k=args.k), 1):
        print(f"  {i}. [{c['source_key']}/{c['doc_id']}] "
              f"{re.sub(chr(92)+'s+', ' ', c['text'])[:130]}...")
    return 0


SELFTEST = [
    ("Which repository best explains SQL injection detection?", {"sqlmap", "libinjection", "zap"}),
    ("Which repository teaches reflected XSS validation?", {"xsstrike", "dalfox"}),
    ("Which repository teaches nuclei-style templates?", {"nuclei-templates"}),
    ("Which repository teaches passive scanning?", {"zap"}),
    ("Which repository teaches active scanning?", {"zap", "sqlmap"}),
    ("Which repository teaches SQLi fingerprinting?", {"sqlmap"}),
    ("Which repository teaches DOM XSS detection?", {"xsstrike", "dalfox"}),
    ("Which repository teaches content extraction?", {"firecrawl"}),
    ("Which repository teaches MCP-based retrieval?", {"firecrawl-mcp"}),
    ("Which repositories are most useful for future scanner engine audits?",
     {"zap", "sqlmap", "xsstrike", "dalfox", "nuclei-templates", "libinjection"}),
    ("What is the difference between static and dynamic scanning?",
     {"executive-summary", "zap"}),
    ("What is the recommended hybrid detection architecture?",
     {"executive-summary", "firecrawl", "zap", "nuclei-templates"}),
]


def cmd_selftest(args) -> int:
    chunks = load_chunks()
    if not chunks:
        print("[error] no committed chunks; run first.")
        return 1
    top1 = top3 = 0
    for q, want in SELFTEST:
        got = retrieve_sources(chunks, q, k=3)
        if got[:1] and got[0] in want:
            top1 += 1
        ok = any(g in want for g in got)
        if ok:
            top3 += 1
        print(f"  [{'OK ' if ok else 'MISS'}] {'/'.join(sorted(want))[:32]:32s} got={got}")
    n = len(SELFTEST)
    print(f"\n[selftest] top1={top1}/{n} top3={top3}/{n}")
    return 0 if top3 == n else 1


def main(argv) -> int:
    ap = argparse.ArgumentParser(description="Phase 6C detection-engineering ingestion")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run"); r.add_argument("--dry-run", action="store_true")
    r.set_defaults(func=cmd_run)
    q = sub.add_parser("query"); q.add_argument("query"); q.add_argument("-k", type=int, default=5)
    q.set_defaults(func=cmd_query)
    s = sub.add_parser("selftest"); s.set_defaults(func=cmd_selftest)
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
