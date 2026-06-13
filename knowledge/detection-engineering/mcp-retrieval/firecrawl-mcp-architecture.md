# Firecrawl MCP — Architecture

**Tool:** Firecrawl MCP server · **Concept:** MCP architecture

The Firecrawl MCP server wraps Firecrawl's crawling/scraping API behind the **Model
Context Protocol**, exposing tools (e.g. `scrape`, `crawl`, `map`, `search`,
`extract`) that an LLM/agent can call over the standard MCP transport (stdio/HTTP).
It handles auth (API key), batching, retries, rate-limits and returns clean
Markdown/JSON. Architecturally it is an **adapter**: it turns an external capability
into typed, discoverable MCP tools with controlled inputs/outputs, so the model never
touches raw network plumbing and every call is mediated and approvable.

**Why it matters for WebHound:** this is the canonical pattern for how WebHound/Claude
acquire **external knowledge and live page content safely** — capability behind an
MCP tool boundary, with explicit approval for network/file access (per the tooling
roadmap's Phase-7 controls). It is the reference design for any future
crawling/retrieval MCP WebHound adopts.

**Related:** [[firecrawl-mcp-retrieval-workflows]], [[firecrawl-mcp-integration-patterns]], [[firecrawl-crawl-architecture]].
