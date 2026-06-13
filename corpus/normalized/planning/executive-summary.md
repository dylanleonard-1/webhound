# Executive Summary — Detection Engineering Survey (planning reference)

Full normalized extract of the uploaded `Executive Summary.pdf` (planning/reference
document, not an official standard). Source: internal WebHound planning PDF.
Binary PDF intentionally not committed (binaries disallowed); this is the canonical
text extract. Repos marked [6B] were ingested in Phase 6B; repos marked [6C] in
Phase 6C; Semgrep/Gitleaks/Playwright-MCP/LightRAG are referenced here for
architectural context but belong to Phase 6B or later phases — do not re-ingest in 6C.

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

## 1. High-priority repositories (with key files to ingest)

| Repo | Lang | GitHub URL | Key files | Phase |
|---|---|---|---|---|
| OWASP ZAP | Java | https://github.com/zaproxy/zaproxy | README, docs/quickstart, sample scripts | 6C |
| sqlmap | Python | https://github.com/sqlmapproject/sqlmap | README, doc/user Installation+Usage | 6C |
| XSStrike | Python | https://github.com/s0md3v/XSStrike | README, Wiki modes/usage | 6C |
| DalFox | Rust | https://github.com/hahwul/dalfox | README, docs/, examples/ | 6C |
| Semgrep | OCaml/Python | https://github.com/returntocorp/semgrep | README, docs(rules) | 6B |
| Gitleaks | Go | https://github.com/gitleaks/gitleaks | README, config/templates | 6B |
| Nuclei | Go | https://github.com/projectdiscovery/nuclei | README, documentation, templates repo | 6B |
| nuclei-templates | YAML | https://github.com/projectdiscovery/nuclei-templates | YAML templates (SQLi, XSS, etc.) | 6C |
| Playwright-MCP | TypeScript | https://github.com/microsoft/playwright-mcp | README, example skills/scripts | 6B |
| Firecrawl | TS/Python | https://github.com/firecrawl/firecrawl | README, scrape examples | 6C |
| Firecrawl-MCP | JS/TS | https://github.com/firecrawl/firecrawl-mcp-server | README, usage | 6C |
| LightRAG | Python | https://github.com/HKUDS/LightRAG | README, design docs | 6B |
| libinjection | C | https://github.com/libinjection/libinjection | README, tests | 6C |

Detection spectrum: Static analyzers (Semgrep, Gitleaks, libinjection); DAST scanners
(ZAP, sqlmap); fuzzing/XSS (XSStrike, DalFox); template scanners (Nuclei+templates);
browser automation (Playwright-MCP, Firecrawl).

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

**STATIC (SAST):** analyze code/page content without execution (AST/regex; Semgrep,
Gitleaks, libinjection). Pros: very fast, broad code-path coverage, deterministic,
offline. Cons: high FPs, misses runtime/context issues, language-specific.

**DYNAMIC (DAST):** active probing of running app — send payloads via HTTP/browser,
observe responses (ZAP, sqlmap, XSStrike). Pros: real exploitable issues, far fewer
FPs, language-independent, tests runtime misconfig. Cons: slower, only tests
paths/payloads it reaches (FN risk), payloads risk stability, black-box.
Key finding: "Dynamic scanners generate far fewer false positives than static tools."

**HYBRID:** combine static rule checks + dynamic probes (template scanners, headless
browsers). Pros: best of both — static narrows candidates, dynamic confirms, lower
FP/FN. Cons: more complex, needs tool coordination and tuning.

**SIGNATURE-BASED:** match known bad patterns/blacklists (Gitleaks, Yara). Precise
for known threats, low CPU; misses novel/obfuscated, needs updates.

**HEURISTIC/RULE-BASED:** generalized rules (unsanitized output, eval use) or
statistical features (JS entropy). Catches new variants if rule covers; tuning needed.

**ML:** train on benign vs malicious; detect unseen patterns. Needs labeled data,
heavy compute, limited open-source for web. All ML ops must run locally (no cloud).

**SANDBOX/RUNTIME:** execute JS instrumented / hook functions; catches skimmers making
network calls/DOM changes; complex, perf overhead.

FP/FN summary: static over-reports; dynamic fewer FPs but FNs if payloads don't
trigger; signatures low-FP on known but fail novel; heuristics balance.

## 4. Recommended engine architecture
Crawler (Firecrawl/Playwright headless) → page content (HTML/JS/assets) → Static
analyzers (Semgrep, Gitleaks, libinjection) + Dynamic scanners (ZAP, sqlmap, XSStrike,
DalFox, Nuclei) → Findings DB/Manifest (evidence + authority tier) → Knowledge Graph/
RAG (LightRAG, local) → Reports/Alerts. Multi-pass: static flags injection points that
trigger targeted dynamic tests; headless browsers test real executions (DOM XSS,
malicious `<script>`).

## 5. Implementation guidance

**Indexing/Manifest:** store metadata (URL, vuln type, snippet hash); authority tiers
(official verified scanners high, manual A, summary pages B, ephemeral memory C).

**Candidate libs:**
- libinjection — SQLi on inputs (C library, fast pre-filter)
- Esprima/Acorn — parse JS for eval/obfuscation (AST-level)
- Nuclei templates — HTTP fuzzing for known vuln patterns
- Yara — script/content pattern matching
- js-beautify/uglify — format obfuscated JS before rescan

**Detection pipelines per threat class:**
- SQL/Command injection: static regex (sql/exec/backticks) + dynamic sqlmap per form param
- XSS/HTML injection: Semgrep unescaped output/.innerHTML + XSStrike/DalFox fuzz + DOM scanning document.write/eval at runtime
- CSRF: Semgrep missing token + dynamic form submit without token via Playwright
- LFI/RFI: static include($_GET) + Nuclei ../ fuzz
- Obfuscation: detect eval/Function()/high-entropy via regex/AST, deobfuscate with js-beautify, rescan
- Third-party assets: crawl all script src/iframe src, static checks (blocklist/Yara), monitor network traffic for bad domains/crypto miners, flag packed JS/long base64

**Offline-only:** ALL scanning + model ops run locally; do NOT send internal site data
to external ML APIs (privacy).

## 6. Practical recommendations (short/medium/long term)

**Short term (wk 1–2):**
- Clone + ingest key repos (READMEs/docs)
- Write Semgrep/YARA rules for obvious patterns (' OR 1=1, XSS sinks, CSRF token presence, eval usage)
- libinjection pre-filter on all user inputs
- Asset enumeration via Firecrawl

**Medium term (wk 3–6):**
- Browser-based testing (Playwright/Puppeteer: log document.cookie leaks, external calls, exfil)
- Hybrid fuzzing: static SQLi finding auto-launches sqlmap
- Extend Nuclei templates

**Long term (mo 3+):**
- ML/embeddings: unsupervised anomaly detection on JS, local fine-tuned transformer on labeled malicious/benign
- Automated learning feedback loop: true positives seed new static rules

## 8. Test queries & metrics

Run engine vs deliberately vulnerable site (OWASP Juice Shop / DVWA). Example queries:
- "List all SQL injection points"
- "Find obfuscated JavaScript"
- "Was SQLi detected on site X?"
- "List pages with suspicious JS obfuscation"
- "Identify injected malicious scripts"

Metrics: precision (reported issues real) + recall (known issues found); top-1/top-3
retrieval accuracy; ensure findings map to Tier A/B sources. Measure per vuln class
(SQLi/XSS), top-1 accuracy, tier authority check.

## 9. Recommended next steps

1. Merge the AI-Knowledge Layer branch (stable) to preserve retrieval + manifest features.
2. Onboard the above repos into ingest pipeline (README + docs).
3. Implement static scan rules as quick win (Semgrep community rules + custom Yara/regex).
4. Build dynamic scanning harness (Playwright/ZAP/Nuclei).
5. Integrate results into WebHound (manifest entries, pointer memory).
6. Iterate by writing more detectors guided by false negatives.

Approach: start static rules, gradually add dynamic + ML layers for best coverage of
injections / obfuscation / malicious third-party assets.
