# Detection-Engineering Repo Priority Summary

**Source:** Executive Summary.pdf (planning reference, binary not committed) · **Concept:** repo prioritization

The Phase-6C planning survey prioritised open-source tools spanning the detection
spectrum, to teach WebHound *how real scanners detect*. Source PDF ingested in Phase 6C;
binary intentionally not committed — this note is derived from the full text extract.

## Phase 6C repos (ingested)

| Repo | Lang | GitHub URL | Key files | Detection class |
|---|---|---|---|---|
| OWASP ZAP | Java | https://github.com/zaproxy/zaproxy | README, docs/quickstart, sample scripts | DAST — active+passive |
| sqlmap | Python | https://github.com/sqlmapproject/sqlmap | README, doc/user Installation+Usage | SQLi — dynamic |
| XSStrike | Python | https://github.com/s0md3v/XSStrike | README, Wiki modes/usage | XSS — context-aware |
| DalFox | Rust | https://github.com/hahwul/dalfox | README, docs/, examples/ | XSS — validated |
| nuclei-templates | YAML | https://github.com/projectdiscovery/nuclei-templates | YAML templates (SQLi, XSS, etc.) | Template-driven |
| Firecrawl | TS/Python | https://github.com/firecrawl/firecrawl | README, scrape examples | Crawl/extraction |
| Firecrawl-MCP | JS/TS | https://github.com/firecrawl/firecrawl-mcp-server | README, usage | MCP retrieval |
| libinjection | C | https://github.com/libinjection/libinjection | README, tests | SQLi/XSS pre-filter |

## Phase 6B repos (referenced, not re-ingested in 6C)

| Repo | Detection class |
|---|---|
| Semgrep (returntocorp/semgrep) | SAST — pattern/AST |
| Gitleaks (gitleaks/gitleaks) | Static secret scanning |
| Nuclei (projectdiscovery/nuclei) | Template scanner engine |
| Playwright-MCP (microsoft/playwright-mcp) | Browser automation / DOM inspection |
| LightRAG (HKUDS/LightRAG) | Knowledge graph / RAG (not a scanner) |

## Detection spectrum

```
Static analyzers   ←→  Semgrep, Gitleaks, libinjection
DAST scanners      ←→  ZAP, sqlmap
XSS fuzzers        ←→  XSStrike, DalFox
Template scanners  ←→  Nuclei + nuclei-templates
Browser/MCP        ←→  Playwright-MCP, Firecrawl
Knowledge layer    ←→  LightRAG (Phase 6B)
```

## Key file-selection criteria applied in Phase 6C

Only READMEs, docs/, examples/, schemas, security docs, release notes, and
representative architecture notes were ingested. Excluded: full source trees, binaries,
vendor folders, generated files, raw exploit/payload dumps, and any files matching
`payloads/`, `wordlists/`, `templates/` (raw corpora), `data/`, `db/`, `samples/`.
Files were shallow-scanned via the GitHub Trees API with max_files caps per repo.

## Prioritisation logic

Coverage of core threat classes WebHound scans for: SQLi, XSS, DOM XSS, exposures,
supply-chain JS. Selected for maintenance/activity and clear authoritative docs.
This list seeds Phase 8 (WADE), Phase 9 (engine audit), and Phase 10 (benchmarks).

**Related:** [[scanner-audit-recommendations]], [[static-vs-dynamic-comparison]], [[hybrid-engine-architecture]].
