# Recommended Hybrid Detection Engine Architecture

**Source:** Executive Summary.pdf (planning reference) · **Concept:** hybrid scanner architecture

The planning reference recommends a **layered, hybrid engine** that combines static
narrowing with dynamic confirmation:

```
Crawler (Firecrawl / Playwright headless)
   → page bundle (rendered HTML, JS, assets, script URLs)
   → Static analysers (Semgrep, regex/Yara, libinjection)   ─┐
   → Dynamic scanners (ZAP, sqlmap, XSStrike, DalFox, Nuclei) ─┤
   → Findings DB / Manifest (evidence + authority tier)        │
   → Knowledge Graph / Retrieval (LightRAG-style, local)       │
   → Reports / Alerts (WADE explanations)                      ┘
```

**Flow:** a headless crawler captures the *real* (post-JS) page and every asset;
static analysers cheaply flag candidates (libinjection on inputs, regex/Yara on
scripts); dynamic scanners then **confirm** candidates with real probes (e.g. static
flags a possible SQLi → launch sqlmap on that endpoint). All findings land in the
manifest with evidence and an authority tier, feed the knowledge graph for Q&A, and
are explained to the user. Everything runs **locally/offline** for privacy.

**Why it matters for WebHound:** this is the target shape for the Phase-9 engine
audit and Phase-8 WADE integration — multi-pass, static-narrows/dynamic-confirms,
evidence-first, lower combined FP/FN.

**Related:** [[static-vs-dynamic-comparison]], [[firecrawl-crawl-architecture]], [[zap-active-scanning]], [[nuclei-template-structure]].
