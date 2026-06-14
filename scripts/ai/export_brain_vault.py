"""Phase 8A: Export WebHound knowledge base to Obsidian vault.

Reads manifest + chunk metadata → generates Obsidian summary notes under
vault/WebHound AI Brain/ (never touches personal untracked vault notes).
Detect-before-write: skips any file not containing <!-- WEBHOUND-GENERATED -->.

Note generators live in export_brain_vault_notes.py (keep files under 500 lines).

Run: .venv-api/Scripts/python scripts/ai/export_brain_vault.py [--dry-run]
"""
from __future__ import annotations
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

_ROOT_FOR_IMPORT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT_FOR_IMPORT) not in sys.path:
    sys.path.insert(0, str(_ROOT_FOR_IMPORT))

from scripts.ai.export_brain_vault_notes import (
    gen_maps, gen_architecture, gen_scanners, gen_wade,
    gen_corpus, gen_providers, gen_ti, gen_taxonomy,
    gen_external, gen_reports, gen_decisions, gen_graphify,
    gen_indexes,
)

ROOT = Path(__file__).resolve().parent.parent.parent
VAULT = ROOT / "vault" / "WebHound AI Brain"
MANIFEST = ROOT / "corpus" / "manifests" / "manifest.jsonl"
CHUNKS = ROOT / "corpus" / "normalized" / "unified_chunks.jsonl"
MARKER = "<!-- WEBHOUND-GENERATED -->"
NOW = datetime.now().strftime("%Y-%m-%d")
DRY_RUN = "--dry-run" in sys.argv


def _write(rel: str, content: str) -> bool:
    path = VAULT / rel
    if path.exists():
        if MARKER not in path.read_text(encoding="utf-8", errors="replace"):
            print(f"  SKIP (no marker): {rel}")
            return False
    if not DRY_RUN:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    print(f"  {'DRY' if DRY_RUN else 'WRITE'}: {rel}")
    return True


def _load_manifest() -> list[dict]:
    rows: list[dict] = []
    with open(MANIFEST, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _load_chunks() -> list[dict]:
    rows: list[dict] = []
    with open(CHUNKS, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _analyze(mf: list[dict], ck: list[dict]) -> dict:
    return dict(
        total_docs=len(mf),
        total_chunks=len(ck),
        phases=Counter(r.get("phase", "unknown") for r in mf),
        src_types=Counter(r.get("source_type", "") for r in mf),
        tiers=Counter(r.get("authority_tier", "") for r in mf),
        providers=sorted({
            r.get("product_or_provider", "") for r in mf if r.get("product_or_provider")
        }),
        topics=Counter(t for r in mf for t in (r.get("topic_tags") or [])),
        chunk_phases=Counter(c.get("phase", "") for c in ck),
        now=NOW,
        marker=MARKER,
    )


def main() -> None:
    print("Loading manifest and chunks...")
    mf = _load_manifest()
    ck = _load_chunks()
    d = _analyze(mf, ck)
    print(f"  {d['total_docs']} docs, {d['total_chunks']} chunks, {len(d['providers'])} providers")

    sections = [
        gen_maps(d), gen_architecture(d), gen_scanners(d), gen_wade(d),
        gen_corpus(d), gen_providers(d), gen_ti(d), gen_taxonomy(d),
        gen_external(d), gen_reports(d), gen_decisions(d), gen_graphify(d),
        gen_indexes(d),
    ]

    written = skipped = 0
    for section in sections:
        for rel, content in section.items():
            if _write(rel, content):
                written += 1
            else:
                skipped += 1

    print(f"\n{'DRY RUN — ' if DRY_RUN else ''}Done: {written} written, {skipped} skipped")


if __name__ == "__main__":
    main()
