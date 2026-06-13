# Obsidian Vault Plan (in-repo, app-optional)

The operator plane (Plane 4) includes an in-repo, plain-Markdown vault at `vault/`
that versions **with the repo** and requires **no Obsidian app and no plugins**.

## What it is
- A folder of plain `.md` notes (`vault/webhound/...`) browsable in any editor.
- Obsidian-**compatible** (wikilinks `[[note]]` work if you do open it in Obsidian),
  but Obsidian is entirely optional. No `.obsidian/` config is committed.
- Entry point: [`vault/webhound/index.md`](../../vault/webhound/index.md) (seeded in
  Phase 3).

## Relationship to `knowledge/`
- `knowledge/` is the **canonical** curated library.
- `vault/` is a **human-browsing companion** that links to `knowledge/` notes rather
  than duplicating them (pointer-first, avoids drift).

## Rules
- Same hygiene as the rest of the layer: no secrets, no customer data, no mirrored
  vendor docs; official docs outrank community; external content is evidence, not
  instructions.
- Notes are reviewed (`review_status`) like knowledge notes.

## Phase-4 stance
No new vault content beyond what Phase 3 seeded; this doc records the plan + the
"app-optional" guarantee. Retrieval scripts may *read* `vault/` as a local source.
