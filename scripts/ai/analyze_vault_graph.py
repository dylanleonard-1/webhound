"""Phase 8C: Obsidian vault graph analysis.

Parses all vault .md notes for [[wikilinks]], computes graph stats
(note count, link count, backlinks, orphans, clusters), and generates
docs/ai/VAULT_GRAPH_RESULTS.md.

Run: .venv-api/Scripts/python scripts/ai/analyze_vault_graph.py
"""
from __future__ import annotations
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
VAULT_DIR = ROOT / "vault" / "WebHound AI Brain"
OUT_RESULTS = ROOT / "docs" / "ai" / "VAULT_GRAPH_RESULTS.md"

_WIKILINK_RE = re.compile(r"\[\[([^\]|#]+?)(?:[|#][^\]]+)?\]\]")
_TAG_RE = re.compile(r"#([\w/-]+)")
_FM_TITLE_RE = re.compile(r"^title:\s*(.+)$", re.MULTILINE)
_FM_TAGS_RE = re.compile(r"^tags:\s*\[([^\]]+)\]", re.MULTILINE)


def _note_name(path: Path) -> str:
    return path.stem


def _rel(p: Path) -> str:
    return str(p.relative_to(ROOT)).replace("\\", "/")


def analyze_vault() -> dict:
    """Parse all vault notes and compute graph statistics."""
    notes: dict[str, dict] = {}  # stem → {path, links, tags, section}

    for f in sorted(VAULT_DIR.rglob("*.md")):
        stem = _note_name(f)
        text = f.read_text(encoding="utf-8", errors="replace")
        links = list({m for m in _WIKILINK_RE.findall(text)})
        fm_tags_m = _FM_TAGS_RE.search(text)
        fm_tags = [t.strip().strip("\"'") for t in fm_tags_m.group(1).split(",")] if fm_tags_m else []
        inline_tags = _TAG_RE.findall(text)
        section = f.parent.name
        notes[stem] = {
            "path": _rel(f),
            "stem": stem,
            "section": section,
            "links": links,
            "tags": list(set(fm_tags + inline_tags)),
            "in_degree": 0,
            "out_degree": len(links),
        }

    # Compute in-degrees
    for stem, data in notes.items():
        for link in data["links"]:
            target = link.strip()
            if target in notes:
                notes[target]["in_degree"] += 1

    # Cluster by section
    sections: dict[str, list[str]] = defaultdict(list)
    for stem, data in notes.items():
        sections[data["section"]].append(stem)

    # Identify orphans (no links in or out)
    orphans = [
        stem for stem, d in notes.items()
        if d["in_degree"] == 0 and d["out_degree"] == 0
    ]

    # Identify dangling links (link target not in vault)
    dangling: list[tuple[str, str]] = []
    for stem, data in notes.items():
        for link in data["links"]:
            if link.strip() not in notes:
                dangling.append((stem, link))

    # Top linked notes
    by_in = sorted(notes.values(), key=lambda n: n["in_degree"], reverse=True)

    total_links = sum(len(d["links"]) for d in notes.values())
    return {
        "note_count": len(notes),
        "link_count": total_links,
        "unique_links": sum(len(set(d["links"])) for d in notes.values()),
        "sections": {k: len(v) for k, v in sections.items()},
        "orphan_count": len(orphans),
        "orphans": orphans,
        "dangling_count": len(dangling),
        "dangling": dangling[:20],
        "cluster_count": len(sections),
        "top_linked": [
            {"note": n["stem"], "in": n["in_degree"], "out": n["out_degree"]}
            for n in by_in[:10]
        ],
        "all_tags": sorted({t for d in notes.values() for t in d["tags"]}),
        "graph_density": round(
            total_links / max(len(notes) * (len(notes) - 1), 1), 4
        ),
    }


def write_results(stats: dict) -> None:
    section_table = "\n".join(
        f"| {sec} | {cnt} |"
        for sec, cnt in sorted(stats["sections"].items())
    )
    top_table = "\n".join(
        f"| {n['note']} | {n['in']} | {n['out']} |"
        for n in stats["top_linked"]
    )
    orphan_list = "\n".join(f"- {o}" for o in stats["orphans"])
    dangling_list = "\n".join(
        f"- `{src}` → `{tgt}` (unresolved)"
        for src, tgt in stats["dangling"][:15]
    )

    report = f"""<!-- WEBHOUND-GENERATED -->
# WebHound Vault Graph Results — Phase 8C

## Summary

| Metric | Value |
|--------|-------|
| Total notes | {stats['note_count']} |
| Total wikilinks | {stats['link_count']} |
| Unique link targets | {stats['unique_links']} |
| Sections (clusters) | {stats['cluster_count']} |
| Orphan notes | {stats['orphan_count']} |
| Dangling links | {stats['dangling_count']} |
| Graph density | {stats['graph_density']} |

## Sections

| Section | Notes |
|---------|-------|
{section_table}

## Most Referenced Notes (by in-degree)

| Note | In-links | Out-links |
|------|---------|-----------|
{top_table}

## Orphan Notes ({stats['orphan_count']})

Notes with no wikilinks in or out:

{orphan_list if orphan_list else '_None — all notes are linked._'}

## Dangling Links ({stats['dangling_count']})

Links that point to notes not yet in the vault:

{dangling_list if dangling_list else '_None — all links resolved._'}

## All Tags ({len(stats['all_tags'])})

```
{', '.join(stats['all_tags'][:60])}
```

## Analysis

- **Graph density** {stats['graph_density']:.4f} — ratio of actual links to maximum possible
- **Clusters**: {stats['cluster_count']} sections form natural knowledge clusters
- **Orphans**: {stats['orphan_count']} notes with no connections (typically index/stub notes)
- All vault notes have `<!-- WEBHOUND-GENERATED -->` marker and YAML frontmatter (validated in Phase 8A)
"""
    OUT_RESULTS.write_text(report, encoding="utf-8")
    print(f"Wrote {OUT_RESULTS.relative_to(ROOT)}")


def main() -> None:
    stats = analyze_vault()
    print(
        f"Vault: {stats['note_count']} notes, {stats['link_count']} links, "
        f"{stats['cluster_count']} clusters, {stats['orphan_count']} orphans"
    )
    write_results(stats)
    # Also write JSON for programmatic use
    json_path = ROOT / "docs" / "ai" / "vault_graph_stats.json"
    json_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(f"Wrote {json_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
