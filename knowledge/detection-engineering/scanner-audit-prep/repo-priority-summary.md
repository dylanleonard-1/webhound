# Detection-Engineering Repo Priority Summary

**Source:** Executive Summary.pdf + WebHound Master Tooling/WADE Roadmap (planning references) · **Concept:** repo prioritization

The Phase-6C planning survey prioritised open-source tools spanning the detection
spectrum, to teach WebHound *how real scanners detect*:

- **DAST scanners:** OWASP ZAP (broad active+passive), sqlmap (SQLi).
- **XSS fuzzers/validators:** XSStrike (context-aware payloads), DalFox (verified XSS, SARIF/MCP).
- **Template/signature:** Nuclei + nuclei-templates (declarative YAML detections), libinjection (structural SQLi/XSS classification).
- **Static analyzers (from 6B):** Semgrep, Gitleaks.
- **Crawl/browser/retrieval:** Firecrawl + Firecrawl-MCP, Playwright-MCP (from 6B).

**Key files to ingest per repo:** README, `docs/`, `examples/`, schemas, security
docs, release notes, and *representative* templates/configs — never full source
trees, binaries, vendor folders, generated files, or raw exploit/payload dumps.

**Prioritisation logic:** coverage of the core threat classes WebHound scans for
(SQLi, XSS, DOM XSS, exposures, supply-chain JS), maintenance/activity, and clear
authoritative docs. This list seeds Phase 8 (WADE), Phase 9 (engine audit) and
Phase 10 (benchmarks).

**Related:** [[scanner-audit-recommendations]], [[static-vs-dynamic-comparison]], [[hybrid-engine-architecture]].
