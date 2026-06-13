# Filesystem MCP

> **Phase 1 action: DOCUMENTED ONLY. Not installed, not configured, not connected.**

## Purpose
Give Claude scoped read/write access to a small, explicitly-allowlisted set of
paths so it can read WebHound source/docs for evidence and write *generated*
knowledge documents — without broad machine access.

## Why WebHound needs it
The knowledge layer must read scanner engine code, existing docs, and (later)
benchmark outputs to ground its audits, and write curated knowledge/evidence
files back into the repo. A filesystem MCP makes that a first-class, auditable
capability instead of ad-hoc shell access.

## What it can access (allowlist — narrowest that works)
Scoped to the **WebHound repository only**. Allowed (now and as later phases are
approved):
- The repo root read tree (e.g. `scanner/`, `apps/`, `docs/`).
- `docs/ai/`, and — once approved — `corpus/`, `knowledge/` (write targets).
- Benchmark/validation outputs (read), once those phases exist.
- A future Obsidian vault **only if** it lives inside an approved workspace path.

## What it must NOT access
- Home/desktop/Downloads or any personal folders.
- Browser profiles, SSH keys (`~/.ssh`), cloud credentials/tokens, password
  managers.
- Raw `.env` / `.env.*` secret files (the generator + `docs/env.md` are the
  source of truth; secrets are never read into context).
- Anything outside the WebHound repo unless explicitly approved.

## Install / setup notes
Reference server: `@modelcontextprotocol/server-filesystem` (run via `npx`).
**Not installed in Phase 1.** When approved, it is configured with an explicit
allowlisted root argument (the repo path) — never the home directory, never `/`.
Registration file/scope is a Phase-2+ decision (see `MCP_MANUAL_APPROVALS.md`).

## Required API keys / auth
**None.** Filesystem access is local; risk is controlled by the path allowlist,
not a key.

## Least-privilege permissions
- Start **read-only** over the repo.
- Grant **write** only to `docs/ai/` (and later `corpus/`, `knowledge/`) once
  approved.
- One allowlisted root; no recursive access above the repo.

## Smoke test
(See `MCP_SMOKE_TESTS.md`.) Safe check: list a known repo path (e.g.
`docs/ai/`) and read this file. **No write, no out-of-repo path** in the smoke
test.

## Risks
- **Overbroad scope** → accidental access to personal/secret files. Mitigation:
  single repo-root allowlist; explicit deny-list above.
- **Accidental secret read** (`.env`). Mitigation: never include `.env*` in the
  allowlisted read set; rely on the generator flow.
- **Unintended writes**. Mitigation: write scope limited to generated-knowledge
  dirs.

## Rollback / removal
Remove the server entry from whichever config registered it; delete any files it
wrote under `docs/ai/`/`corpus/`/`knowledge/`. No app/runtime impact (it is not
wired into WebHound services).

## WebHound use cases
- Read scanner engine files (`scanner/webhound/engines/**`) for engine audits.
- Read existing docs (`docs/`, `docs/ai/`) for grounding.
- Write generated knowledge docs into `docs/ai/` / `knowledge/` (later phases).
- Read benchmark/validation outputs and a future Obsidian vault (later phases).

## Phase 1 install? **No — documented only.**
