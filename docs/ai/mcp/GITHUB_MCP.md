# GitHub MCP

> **Phase 1 action: DOCUMENTED ONLY. Not installed, not configured, not connected.**

## Purpose
Let Claude inspect GitHub repository state (commits, PRs, issues, diffs, releases)
as evidence, and — only with explicit approval in a later phase — open PRs/issues.

## Why WebHound needs it
Engine audits and the evidence layer benefit from linking findings to the exact
commits/PRs that introduced behavior, reading release notes from official tool
repos (later, for ingestion), and (eventually) filing engine-audit issues. A
GitHub MCP makes this precise and auditable.

## ⚠️ `GITHUB_TOKEN` is NEW and DISTINCT from existing OAuth creds
WebHound already has `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` in `.env` — those
are the **OAuth app credentials for end-user "Sign in with GitHub" login** and are
**NOT** for MCP. The GitHub MCP uses a **separate, personal, read-only
`GITHUB_TOKEN` (a fine-grained PAT)**. Do **not** reuse the OAuth client secret.

## What it can access
- Read commits, branches, PRs, issues, diffs, releases for repos the token can see
  (start with this repo / public tool repos).

## What it must NOT access
- No org administration, no settings, no Actions secrets / repo secrets.
- No destructive branch operations (delete/force-push) without explicit approval.
- No auto-merge, no auto-push, no branch-protection edits.
- No write scope at all in the initial least-privilege grant.

## Install / setup notes
Reference server: `github/github-mcp-server` (or `@modelcontextprotocol`-family
GitHub server), run via `npx`/container. **Not installed in Phase 1.** The token
is supplied via env (`GITHUB_TOKEN`), never committed.

## Required API keys / auth
`GITHUB_TOKEN` — a **fine-grained PAT, read-only** to start
(Contents: Read, Metadata: Read; optionally Pull requests / Issues: Read).
Stored in the local environment / MCP config env block — **never** in the repo,
never in `.env.example` with a value. Placeholder key name added to the env
generator this phase (blank).

## Least-privilege permissions
1. **Phase intro:** repo-read only (commits/PRs/issues/releases).
2. **Later, with approval:** Pull requests: Write (to open PRs), Issues: Write
   (to file audit issues) — still no admin, no force-push, no auto-merge.

## Smoke test
(See `MCP_SMOKE_TESTS.md`.) If `GITHUB_TOKEN` is set, a read-only call such as
"get repo metadata" or "list recent commits". **Skipped entirely when the token
is absent** — the smoke script never prints token values.

## Risks
- **Token leakage** → never log it; never echo; store only in the MCP env block.
- **Over-scoped token** → use a fine-grained read-only PAT, not a classic
  all-scopes token.
- **Destructive ops via write scope** → no write scope until approved; no
  force-push/auto-merge ever without explicit per-action approval.

## Rollback / removal
Remove the server entry from its config; revoke the PAT in GitHub settings; remove
the `GITHUB_TOKEN` from the local env. No WebHound runtime impact.

## WebHound use cases
- Inspect commits/PRs/issues to ground findings in code history.
- Link a scanner finding/false-positive to the commit that caused it.
- Read official tool repos' release notes (Phase 5 ingestion).
- (Approved, later) open engine-audit issues / remediation PRs.

## Phase 1 install? **No — documented only.**
