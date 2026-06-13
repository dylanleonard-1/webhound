# Firecrawl MCP — Retrieval Workflows

**Tool:** Firecrawl MCP server · **Concept:** retrieval workflows / external knowledge acquisition

Through the Firecrawl MCP an agent runs **retrieval workflows** entirely as tool
calls: `search` the web for a topic, `map` a site to enumerate URLs, `scrape`/`crawl`
specific pages, and `extract` structured fields — each returning clean,
agent-consumable Markdown/JSON with automatic retries and rate-limiting. Typical
detection-support workflows: fetch a site's rendered page + all script URLs for
offline analysis; pull an official doc/advisory to enrich a finding; gather a vendor
page to map a CVE to remediation.

**Why it matters for WebHound:** this defines how WebHound can **acquire external
reference content for WADE enrichment** without bespoke scrapers — retrieval as
mediated, rate-limited, approvable tool calls. It complements the local LightRAG-style
internal retrieval: MCP retrieval reaches *out* for fresh external docs/pages; the
local index serves *internal* knowledge. Both must respect the offline-by-default
rule for internal/customer data.

**Related:** [[firecrawl-mcp-architecture]], [[firecrawl-mcp-integration-patterns]], [[repo-priority-summary]].
