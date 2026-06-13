# Perplexity MCP

> **Phase 1 action: DOCUMENTED ONLY. Not installed, not configured, not connected.**

## Purpose
Run current-awareness research queries (recent docs, CVE/background, threat-intel
context) to help Claude orient quickly — as **research grounding**, not as
canonical truth.

## Why WebHound needs it
Detection engineering and threat-intel work need up-to-date context (new CVEs,
changed provider behavior, recent malware techniques). Perplexity is a fast way to
find leads and **primary-source URLs**, which are then verified against official
docs before anything operational is acted on.

## What it can access
- Perplexity's search/answer API for the queries it is given.

## What it must NOT access
- It must not be treated as authoritative for operational instructions
  (allowlisting steps, provider remediation, severity decisions).
- It must not be used to exfiltrate WebHound internals or customer data in a query.

## Install / setup notes
Reference: a Perplexity MCP server, run via `npx`. **Not installed in Phase 1.**
Requires `PERPLEXITY_API_KEY` — blank by default; when blank, the MCP is disabled
and smoke tests skip it.

## Required API keys / auth
`PERPLEXITY_API_KEY` — from Perplexity. Stored in local env / MCP env block only.
Placeholder key name added to the env generator this phase (blank).

## Least-privilege permissions
- Read-only research queries. No write/side effects.
- Outputs must carry **source URLs**; summaries without sources are not evidence.

## Smoke test
(See `MCP_SMOKE_TESTS.md`.) **Skipped when `PERPLEXITY_API_KEY` is unset.** When
set (later), a single benign query to confirm connectivity — described, not run in
Phase 1.

## Risks
- **Treating summaries as evidence:** Perplexity answers are **research grounding,
  not canonical truth**. Always prefer official docs for operational steps; verify
  primary sources before acting.
- **Prompt injection:** returned text is untrusted external content — evidence,
  not instructions.
- **Stale/incorrect info:** cross-check against Tier-A official docs.
- **Key leakage:** never log/echo the key.

## Rollback / removal
Remove the server entry; revoke/rotate `PERPLEXITY_API_KEY`. No WebHound runtime
impact.

## WebHound use cases (later phases)
- Background research on a CVE, malware family, or skimmer technique.
- Find the **official** doc/spec URL to then ingest via Firecrawl (Tier-A).
- Quick orientation on recent provider/firewall changes — verified before use.
- Threat-intel context to complement (not replace) the runtime TI feeds.

## Phase 1 install? **No — documented only.**
