"""Phase 6H: Build unified chunk index across all AI knowledge phases (6A–6F).

Output: corpus/normalized/unified_chunks.jsonl
Run:    .venv-api/Scripts/python scripts/ai/build_unified_chunk_index.py
Read-only except for the output JSONL. No manifest/knowledge changes.
"""
from __future__ import annotations
import json, re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST = ROOT / "corpus" / "manifests" / "manifest.jsonl"
OUT = ROOT / "corpus" / "normalized" / "unified_chunks.jsonl"
MIN_CHARS = 300    # skip stubs below this
TARGET = 1200     # target chunk size (chars)

PHASE_MAP = {
    "pd-sec": "6A", "pn-sec": "6A", "owasp-": "6A", "mdn-": "6A",
    "det-": "6B", "nuclei--": "6B", "det-zap": "6B", "det-dalfox": "6B",
    "det-xsstrike": "6B", "det-libinjection": "6B", "det-sqlmap": "6B",
    "det-firecrawl": "6B", "semgrep": "6B", "playwright": "6B",
    "katana": "6B", "httpx": "6B", "amass": "6B", "gitleaks": "6B",
    "lightrag": "6B", "mcp-servers": "6B", "github-mcp": "6B",
    "pd-cloudflare": "6C", "pn-cloudflare": "6C",
    "pd-vercel": "6C", "pn-vercel": "6C",
    "pd-railway": "6C", "pn-railway": "6C",
    "pd-fastly": "6C", "pn-fastly": "6C",
    "pd-netlify": "6C", "pn-netlify": "6C",
    "pd-aws-cloudfront": "6C", "pn-aws-cloudfront": "6C",
    "pn-akamai": "6D", "pn-aws-waf": "6D", "pn-azure": "6D",
    "pn-google": "6D", "pn-imperva": "6D", "pn-sucuri": "6D",
    "pn-flyio": "6D", "pn-render": "6D", "pn-stripe": "6D",
    "pn-resend": "6D", "pn-github": "6D",
    "pd-aws-waf": "6D", "pd-azure": "6D", "pd-google": "6D",
    "pd-imperva": "6D", "pd-flyio": "6D", "pd-stripe": "6D",
    "pd-ti-": "6E", "pn-ti-": "6E",
    "pd-vt-": "6F", "pn-vt-": "6F",
}


def guess_phase(doc_id: str) -> str:
    for prefix, phase in PHASE_MAP.items():
        if doc_id.startswith(prefix):
            return phase
    return "Other"


def load_manifest() -> dict[str, dict]:
    rows: dict[str, dict] = {}
    with open(MANIFEST, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                r = json.loads(line)
                rows[r["doc_id"]] = r
    return rows


def build_file_map(records: dict[str, dict]) -> dict[str, dict]:
    """Map absolute file path -> manifest record (best-effort three-way lookup)."""
    url_map = {r.get("source_url", ""): r for r in records.values() if r.get("source_url")}
    all_md = (list((ROOT / "corpus" / "normalized").rglob("*.md")) +
              list((ROOT / "knowledge").rglob("*.md")))
    file_map: dict[str, dict] = {}
    for f in all_md:
        key = str(f)
        rel = str(f.relative_to(ROOT)).replace("\\", "/")
        stem = f.stem
        parent_rel = str(f.parent.relative_to(ROOT)).replace("\\", "/") + "/"
        if stem in records:
            file_map[key] = records[stem]
        elif rel in url_map:
            file_map[key] = url_map[rel]
        elif parent_rel in url_map:
            file_map[key] = url_map[parent_rel]
        else:
            # Fuzzy: longest doc_id that is a substring of stem (or vice versa)
            best = max(
                ((did, rec) for did, rec in records.items() if did in stem or stem in did),
                key=lambda x: len(x[0]), default=(None, None)
            )
            if best[0]:
                file_map[key] = best[1]
            else:
                file_map[key] = {
                    "doc_id": stem, "title": stem, "source_type": "internal_doc",
                    "authority_tier": "C", "source_url": rel,
                    "verification_status": "unregistered", "topic_tags": [],
                }
    return file_map


def _section_split(text: str) -> list[str]:
    """Split at section headers while keeping tables and code blocks intact."""
    # Protect fenced code blocks and markdown tables from splitting
    lines = text.split("\n")
    segments: list[str] = []
    buf: list[str] = []
    in_fence = False
    for line in lines:
        if line.startswith("```"):
            in_fence = not in_fence
        if not in_fence and re.match(r"^#{1,3} ", line) and buf:
            segments.append("\n".join(buf))
            buf = [line]
        else:
            buf.append(line)
    if buf:
        segments.append("\n".join(buf))
    return segments


def chunk_document(text: str, doc_id: str, rec: dict, file_path: str = "") -> list[dict]:
    """Semantically chunk a document, preserving section coherence."""
    sections = _section_split(text.strip())
    chunks: list[str] = []
    buf = ""
    for sec in sections:
        if len(buf) + len(sec) + 1 <= TARGET or not buf:
            buf = (buf + "\n" + sec).lstrip()
        else:
            if len(buf.strip()) >= MIN_CHARS:
                chunks.append(buf.strip())
            buf = sec
    if buf.strip() and len(buf.strip()) >= MIN_CHARS:
        chunks.append(buf.strip())
    result: list[dict] = []
    for i, txt in enumerate(chunks):
        result.append({
            "chunk_id": f"{doc_id}--c{i:03d}",
            "doc_id": doc_id,
            "chunk_index": i,
            "total_chunks": len(chunks),
            "text": txt,
            "file_path": file_path,
            "source_type": rec.get("source_type", "internal_doc"),
            "authority_tier": rec.get("authority_tier", "C"),
            "source_url": rec.get("source_url", ""),
            "title": rec.get("title", doc_id),
            "verification_status": rec.get("verification_status", ""),
            "topic_tags": rec.get("topic_tags", []),
            "phase": guess_phase(doc_id),
        })
    return result


def main() -> None:
    print("Loading manifest...")
    records = load_manifest()
    print(f"  {len(records)} records")

    print("Building file->record map...")
    file_map = build_file_map(records)
    print(f"  {len(file_map)} files mapped")

    print("Generating chunks...")
    all_chunks: list[dict] = []
    seen: set[str] = set()
    phase_stats: dict[str, dict] = defaultdict(lambda: {"files": 0, "chunks": 0, "skipped": 0})

    for fpath_str in sorted(file_map):
        rec = file_map[fpath_str]
        doc_id = rec["doc_id"]
        phase = guess_phase(doc_id)
        # Dedup by doc_id — knowledge/ and corpus/ may share a record
        if doc_id in seen:
            continue
        try:
            content = Path(fpath_str).read_text(encoding="utf-8")
        except Exception:
            phase_stats[phase]["skipped"] += 1
            continue
        if len(content.strip()) < MIN_CHARS:
            phase_stats[phase]["skipped"] += 1
            continue
        rel = str(Path(fpath_str).relative_to(ROOT)).replace("\\", "/")
        chunks = chunk_document(content, doc_id, rec, file_path=rel)
        if not chunks:
            phase_stats[phase]["skipped"] += 1
            continue
        seen.add(doc_id)
        phase_stats[phase]["files"] += 1
        phase_stats[phase]["chunks"] += len(chunks)
        all_chunks.extend(chunks)

    # Verify no duplicate chunk_ids
    cid_counts = Counter(c["chunk_id"] for c in all_chunks)
    dups = [k for k, v in cid_counts.items() if v > 1]

    print(f"  {len(all_chunks)} chunks from {len(seen)} unique docs")
    if dups:
        print(f"  WARNING: {len(dups)} duplicate chunk_ids — investigate!")

    print(f"Writing {OUT} ...")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        for c in all_chunks:
            f.write(json.dumps(c, ensure_ascii=False) + "\n")

    sizes = [len(c["text"]) for c in all_chunks] or [0]
    print(f"Chunk stats: avg={sum(sizes)//len(sizes)}  min={min(sizes)}  max={max(sizes)}")
    print("\nPhase coverage:")
    phase_topics = {"6A": "Security Standards", "6B": "Detection Engineering",
                    "6C": "Provider Intelligence", "6D": "Provider Docs",
                    "6E": "Threat Intelligence", "6F": "Vulnerability Taxonomy",
                    "Other": "Internal/Planning"}
    for ph in ["6A", "6B", "6C", "6D", "6E", "6F", "Other"]:
        ps = phase_stats.get(ph, {"files": 0, "chunks": 0, "skipped": 0})
        n_rec = sum(1 for r in records.values() if guess_phase(r.get("doc_id", "")) == ph)
        print(f"  {ph} {phase_topics[ph]}: {n_rec} records | {ps['files']} docs | {ps['chunks']} chunks | {ps['skipped']} skipped")
    print(f"\nDuplicate chunk_ids: {len(dups)}")
    print("Done.")


if __name__ == "__main__":
    main()
