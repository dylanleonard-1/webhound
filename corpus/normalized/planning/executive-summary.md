# Executive Summary — Detection Engineering Survey (planning reference)

Normalized extract of the uploaded `Executive Summary.pdf` (planning/reference
document, not an official standard). Source: internal WebHound planning PDF.

## Overview
A survey of leading open-source web-security scanning and malicious-content
detection tools, ranging from static analyzers (Semgrep, Gitleaks) to dynamic
scanners (ZAP, sqlmap, XSStrike/DalFox, Nuclei). Static tools use pattern/AST
analysis on code or page content; dynamic tools actively probe running web apps and
generate/fuzz payloads. Hybrid scanners like Nuclei combine template-driven requests
with optional headless JS. Browser automation servers (Playwright-MCP, Firecrawl-MCP)
enable controlled crawling and DOM inspection. No single approach suffices: static
analysis is fast but prone to false positives, while pure dynamic scanning yields
fewer false alarms but may miss untriggered paths. Recommendation: a **layered engine
combining both**, all running locally/offline, feeding WebHound's knowledge graph/
manifest tagged by source and confidence.

## 1. High-priority repositories
OWASP ZAP, sqlmap, XSStrike, DalFox, Semgrep, Gitleaks, Nuclei + nuclei-templates,
Playwright-MCP, Firecrawl, Firecrawl-MCP, LightRAG, libinjection. Ingest each repo's
README, user docs (install/usage), and example/template sets for rule/payload
*methodology* extraction.

## 2. Detection techniques by project
- **OWASP ZAP** — full DAST; crawls, injects payloads (XSS/SQLi/CSRF/RCE), active +
  passive scanners; attack signatures; custom scripts; rule/fuzz based (no ML).
- **sqlmap** — automated SQLi; error/boolean/time/UNION/stacked; DB fingerprinting;
  tamper scripts; mostly dynamic probing.
- **XSStrike** — context-aware XSS; analyses response context then crafts
  guaranteed-working payloads; hidden parameter discovery; DOM XSS; WAF evasion.
- **DalFox** — modern XSS; static parameter analysis + active testing; reflected/
  stored/DOM (AST verification); WAF fingerprint; JSON/SARIF; REST + MCP.
- **Semgrep** — SAST via code-aware patterns; community rules for SQLi/XSS/CSRF;
  offline; fast but FP-prone on complex context.
- **Gitleaks** — secret scanning via regex + entropy; configurable rules; CI action.
- **Nuclei** — template-driven YAML scanner; requests + response-match logic;
  simulates real steps to reduce FPs; headless mode for JS-heavy pages.
- **libinjection** — C library; SQL/SQLi token parsing to classify inputs; building
  block / pre-filter.
- **Playwright-MCP / Firecrawl / Firecrawl-MCP** — headless browsing, DOM inspection,
  clean Markdown/JSON extraction for realistic dynamic analysis.

Other threat classes: CSRF (static missing-token checks + dynamic form submits), LFI/
RFI (regex + Nuclei templates), obfuscation (deobfuscate then detect eval/Function/
high-entropy), third-party malicious assets (blocklist script src, signature scan,
runtime network monitoring; ML JS-intent classification is proprietary/emerging).

## 3. Static vs dynamic vs hybrid
Static: fast, broad, deterministic, offline; **high FP**, misses runtime/context.
Dynamic: real exploitable findings, **far fewer FP**, language-independent; slower,
coverage-bound, can miss untested paths. Hybrid: static narrows candidates, dynamic
confirms; lower combined FP/FN. Signature: precise on known, misses novel. Heuristic:
balances. ML: emerging, needs labelled data, local-only for privacy. Sandbox/runtime
monitoring catches executing malicious payloads (skimmer network calls, DOM changes).

## 4. Recommended engine architecture
Crawler (Firecrawl/Playwright headless) → page content (HTML/JS/assets) → Static
analyzers (Semgrep, Gitleaks, libinjection) + Dynamic scanners (ZAP, sqlmap, XSStrike,
DalFox, Nuclei) → Findings DB/Manifest (evidence + authority tier) → Knowledge Graph/
RAG (LightRAG, local) → Reports/Alerts. Multi-pass: static flags injection points that
trigger targeted dynamic tests; headless browsers test real executions (DOM XSS,
malicious `<script>`).

## 5. Implementation guidance
Ingest findings into the manifest with metadata (URL, vuln type, snippet hash) and
authority tiers. Use libinjection for SQLi pre-filtering, JS parsers (Esprima/Acorn)
for eval/obfuscation, Nuclei templates / Yara for HTTP fuzzing and known-malware, JS
beautifiers for obfuscated code. Per-class pipelines for SQLi, XSS/HTML injection,
CSRF, LFI/RFI, obfuscation, third-party assets. **Offline-only**: never send internal
site data to external ML APIs.

## 6–8. Practical actions, repos/files, test queries & metrics
Short term: static rule scans, asset enumeration. Medium term: browser-based testing,
hybrid fuzzing, extend templates. Long term: ML/embeddings (local), automated learning
from the manifest. Evaluate on known-vuln apps (Juice Shop, DVWA) measuring
precision/recall and top-1/top-3 retrieval accuracy, preferring Tier A/B sources.

## 9. Recommended next steps
Merge the AI-Knowledge layer; onboard the above repos (README+docs); implement static
scan rules; build a dynamic harness (Playwright/ZAP/Nuclei); integrate results into
the manifest; iterate detectors guided by false negatives.
