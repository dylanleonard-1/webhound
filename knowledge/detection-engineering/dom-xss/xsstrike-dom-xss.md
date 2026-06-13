# XSStrike — DOM XSS Detection

**Tool:** XSStrike · **Concept:** DOM-based XSS

DOM XSS occurs entirely in the browser: a client-side **source** (e.g.
`location.hash`, `location.search`, `document.referrer`, `window.name`) flows into a
dangerous **sink** (`innerHTML`, `document.write`, `eval`, `setTimeout`, jQuery
`.html()`) without sanitisation — the server response may look clean. XSStrike
analyses JavaScript to trace these **source→sink** flows and tests by injecting into
the client-controlled inputs and observing whether script executes in-page. Because
the vulnerability never appears in the raw HTTP body, **only runtime/DOM inspection
(a real browser) reliably confirms it**.

**Why it matters for WebHound:** this motivates browser-assisted validation. Static
HTML scanning cannot see DOM XSS; WebHound needs headless-browser execution
(Playwright/Firecrawl-class) to confirm source→sink exploitation. The detection
knowledge — the catalogue of sources and sinks and the requirement for runtime proof
— directly informs WebHound's JavaScript-analysis engine and its DOM-XSS confidence.

**Related:** [[xsstrike-context-analysis]], [[dalfox-xss-validation]], [[firecrawl-rendering-model]].
