# Firecrawl — Crawl Architecture

**Tool:** Firecrawl · **Type:** crawling/scraping API · **Concept:** crawl architecture

Firecrawl is an agent-oriented crawling and scraping engine. Its pipeline:
**discover** URLs (sitemap, link-following with depth/scope limits), **fetch** each
page rendering JavaScript in a real/headless browser (so SPA and JS-generated content
is captured), handle proxies/rate-limits/retries, then **transform** the rendered DOM
into clean **Markdown/JSON** (stripping nav/boilerplate). It exposes `scrape` (one
URL), `crawl` (a site), `map` (URL discovery), and `search`, returning normalised,
LLM-ready content plus metadata and links.

**Why it matters for WebHound:** detection coverage starts with *seeing the real
page*. Firecrawl's render-then-normalise architecture is the model for WebHound's
crawler/fetcher stage in the layered engine: capture JS-executed content and every
script/asset URL, then feed clean artefacts to static and dynamic analysers. It is
the "Crawler" node in the recommended hybrid architecture.

**Related:** [[firecrawl-extraction-workflows]], [[firecrawl-rendering-model]], [[hybrid-engine-architecture]].
