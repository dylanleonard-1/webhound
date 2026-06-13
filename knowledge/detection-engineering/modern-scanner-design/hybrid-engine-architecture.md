# Recommended Hybrid Detection Engine Architecture

**Source:** Executive Summary.pdf (planning reference, binary not committed) · **Concept:** hybrid scanner architecture

Derived from full-text extract of the planning PDF (section 4). Binary intentionally
not committed.

## The layered pipeline

```
Crawler (Firecrawl / Playwright headless)
   ↓
page bundle: rendered HTML, JS, assets, script src URLs
   ↓
┌─────────────────────────────────────────────────────────┐
│ STATIC LAYER (fast, broad, runs first)                  │
│   Semgrep — code-aware pattern rules (SQLi/XSS/CSRF)   │
│   Gitleaks — secret/credential regex + entropy          │
│   libinjection — SQLi/XSS token pre-filter on inputs   │
│   Regex/Yara — known-malware script patterns            │
└─────────────────────────────────────────────────────────┘
   ↓ flagged candidates
┌─────────────────────────────────────────────────────────┐
│ DYNAMIC LAYER (targeted, confirmation-grade)            │
│   ZAP — active+passive scan, broad vuln class           │
│   sqlmap — SQLi differential proof (per flagged param)  │
│   XSStrike — context-tailored XSS payloads              │
│   DalFox — verified XSS (reflect ≠ execute)            │
│   Nuclei — template-driven HTTP fuzzing (YAML)          │
│   Playwright-MCP — DOM XSS + malicious script monitors  │
│   (all in isolated sandbox)                             │
└─────────────────────────────────────────────────────────┘
   ↓
Findings DB / Manifest
   (each finding: Vuln{type, location, evidence, authority_tier}
    linked to source URL/snippet + confidence score)
   ↓
Knowledge Graph / RAG (LightRAG-style, local — no cloud calls)
   ↓
Reports / Alerts (JSON/SARIF or WebHound WADE explanations)
```

## Multi-pass flow detail

1. **Crawl:** headless browser (Firecrawl or Playwright) fetches the real (post-JS)
   rendered page; captures all assets, script src URLs, form parameters, hidden inputs.

2. **Static pass (broad):** static analyzers flag *candidates* cheaply — libinjection
   on every form input for SQLi signals, Semgrep for unescaped output sinks (XSS),
   Yara on script content for known malware patterns.

3. **Dynamic pass (targeted):** static signals drive targeted dynamic probes — a
   suspected SQLi form field triggers a sqlmap session on that specific endpoint; an
   XSS sink triggers XSStrike/DalFox context analysis + payload generation.

4. **DOM/runtime pass:** Playwright monitors `document.cookie` access, external network
   calls, DOM mutations during page load — catches skimmer scripts that only activate
   post-load.

5. **Findings manifest:** every confirmed finding committed as a manifest node with
   evidence pointer (request/response snippet), detection method, authority tier, and
   confidence score. No finding without evidence.

6. **Knowledge layer:** findings feed the knowledge graph for NL Q&A ("Was SQLi
   detected on site X?", "List pages with suspicious JS obfuscation").

## Implementation guidance (candidate libraries)

| Need | Library/Tool |
|---|---|
| SQLi pre-filter on inputs | libinjection (C, fast) |
| JS AST analysis (eval/obfuscation) | Esprima / Acorn |
| HTTP fuzzing (known vulns) | Nuclei templates |
| Script content pattern matching | Yara |
| Obfuscated JS normalization | js-beautify / uglify |

## Per-class detection pipelines

- **SQLi/command injection:** static regex (sql/exec/backticks) → dynamic sqlmap per flagged param
- **XSS/HTML injection:** Semgrep `.innerHTML`/unescaped output → XSStrike/DalFox fuzz → DOM scan (document.write/eval at runtime)
- **CSRF:** Semgrep missing-token + dynamic form submit via Playwright (no token)
- **LFI/RFI:** static `include($_GET)` regex → Nuclei `../` fuzzing
- **Obfuscation:** detect eval/Function()/high-entropy → deobfuscate with js-beautify → rescan
- **Third-party malicious assets:** enumerate script src/iframe src → blocklist+Yara static check → monitor network traffic (bad domains, crypto miners) → flag packed JS/long base64

## Offline-only constraint

ALL scanning and ML ops run locally. Never send internal site data to external ML APIs
(privacy requirement, exact from PDF). Cloud-only JS-intent classifiers (Cloudflare
Page Shield style) are excluded; implement equivalents locally.

## Test queries & metrics (from PDF section 8)

Run against known-vulnerable apps (OWASP Juice Shop, DVWA):
- "List all SQL injection points"
- "Find obfuscated JavaScript"
- "Was SQLi detected on site X?"
- "List pages with suspicious JS obfuscation"
- "Identify injected malicious scripts"

Metrics: precision/recall per vuln class (SQLi/XSS); top-1/top-3 retrieval accuracy;
confirm findings map to Tier A/B sources.

## Why this matters for WebHound

This is the **target architecture for Phase 9 engine audit and Phase 8 WADE
integration**: multi-pass, static-narrows/dynamic-confirms, evidence-first, lower
combined FP/FN. Each existing WebHound engine should be evaluated against how well
it fits into this pipeline.

**Related:** [[static-vs-dynamic-comparison]], [[firecrawl-crawl-architecture]], [[zap-active-scanning]], [[nuclei-template-structure]], [[sqlmap-confidence-model]].
