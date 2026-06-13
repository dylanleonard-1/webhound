# Firecrawl — Rendering Model

**Tool:** Firecrawl · **Concept:** browser rendering / dynamic capture

Firecrawl fetches pages through a **real browser engine**, so it executes JavaScript,
waits for dynamic content, and returns the **post-render DOM** rather than the raw
server HTML. This matters for security: modern sites build the DOM client-side, inject
third-party scripts at runtime, and may only reveal malicious behaviour (skimmers,
redirects, hidden iframes, network calls to suspicious domains) **after** JS runs.
Rendering also lets a pipeline observe network requests and the final asset list as a
user's browser would see them.

**Why it matters for WebHound:** rendering is what enables **browser-assisted
validation** — the same capability XSStrike/DalFox need for DOM XSS and that the
planning roadmap calls "headless browser instrumentation." WebHound's JavaScript and
compromise-detection engines require post-render DOM + network observation to catch
runtime-only threats; static HTML alone misses them. Firecrawl (or Playwright-class
headless) is the reference for this stage.

**Related:** [[firecrawl-crawl-architecture]], [[xsstrike-dom-xss]], [[hybrid-engine-architecture]].
