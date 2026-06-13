# Firecrawl — Extraction Workflows

**Tool:** Firecrawl · **Concept:** content extraction workflows

Firecrawl turns messy live pages into **structured, analysable artefacts**. Per page
it can return: cleaned Markdown, raw + rendered HTML, the list of links, the
**script/asset URLs**, screenshots, and structured JSON via schema-guided
extraction. Workflows: `scrape` for a single page, `crawl` to walk a site with
include/exclude path rules and depth caps, `map` to enumerate URLs fast. These
outputs are exactly what downstream detectors need — clean text for keyword/regex/
obfuscation checks, and the inventory of third-party `<script src>`/`<iframe>` URLs
for supply-chain analysis.

**Why it matters for WebHound:** the per-page artefact set (text + links + external
script inventory + rendered DOM) maps onto WebHound's JavaScript-analysis,
third-party-domain, and content engines. Firecrawl's extraction model shows how to
hand a uniform "page bundle" to many analysers, decoupling *acquisition* from
*detection* — a clean seam for the Phase-9 engine architecture.

**Related:** [[firecrawl-crawl-architecture]], [[firecrawl-rendering-model]], [[firecrawl-mcp-retrieval-workflows]].
