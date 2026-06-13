# Firecrawl MCP — Integration Patterns

**Tool:** Firecrawl MCP server · **Concept:** MCP integration patterns

Integration patterns for using an MCP retrieval server safely inside WebHound:
**capability boundary** — the model calls typed tools, never raw HTTP; **least
privilege + approval** — network/file access is opt-in and logged (Phase-7 tooling
rule); **secrets in env** — the Firecrawl API key lives in environment/secret store,
never in prompts or committed files; **rate-limit & cache** — respect provider limits
and cache results so enrichment never blocks a scan; **provenance** — every retrieved
artefact is tagged with its source URL, fetch time and authority tier before entering
the manifest; **offline guarantee** — internal/customer data is not sent to external
services.

**Why it matters for WebHound:** these patterns let WADE pull external context
(advisories, provider docs, live page artefacts) without weakening WebHound's
security posture or provenance model. They are the contract any
crawling/retrieval/threat-intel MCP must satisfy before it is wired into the scan or
enrichment path.

**Related:** [[firecrawl-mcp-architecture]], [[firecrawl-mcp-retrieval-workflows]], [[scanner-audit-recommendations]].
