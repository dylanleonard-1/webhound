# Scanner Audit Recommendations (Phase-9 Prep)

**Source:** Executive Summary.pdf (planning reference, binary not committed) · **Concept:** future scanner audit guidance

Derived from full-text extract of the planning PDF (sections 5, 6, 8, 9). Binary
intentionally not committed. Also references the WebHound Master Tooling/WADE Roadmap
planning reference.

## Phase-9 engine audit checklist

Detection knowledge from Phase 6C feeds the **Phase-9 full engine audit**. For every
WebHound engine (Recon, DNS, TLS, Headers, CSP, CORS, Cookies, Crawler, Forms,
Sensitive Paths, JavaScript, Third-Party Domains, CMS, API Discovery, Threat Intel,
Compromise, Correlation, Reporting, WADE), audit against:

- **Evidence:** does the detector emit an evidence locator (à la ZAP alert / Nuclei
  extractor)? No evidence ⇒ low confidence by policy.
- **Proof bar:** for active-class findings, is there a *reproducible differential*
  (sqlmap model) or *verified execution/context* (DalFox/XSStrike model)? Reflection
  or a single suspicious response is not proof.
- **Confidence vs severity:** kept on separate axes (ZAP model); severity from CWE/CVSS
  mapping (Nuclei model), confidence from evidence strength.
- **False-positive guards:** baseline comparison, negative controls, dedup, WAF-awareness,
  delay-scaling for time-based probes.
- **Coverage/recall:** input discovery (parameter mining à la DalFox) so detectors are
  not blind to untested inputs.
- **Mapping & tests:** each finding mapped to CWE/OWASP and covered by a regression
  test; gaps documented.

## Short-term actions (wk 1–2)

1. Clone and ingest key repos (READMEs/docs) — Phase 6C complete for the 8 approved repos.
2. Write Semgrep/YARA rules for obvious patterns:
   - `' OR 1=1` — SQLi in form inputs
   - XSS sinks — `.innerHTML`, `document.write`, `eval()`
   - CSRF token presence — forms lacking hidden token fields
   - Eval usage — `eval()`, `Function()`, `setTimeout(string)`
3. libinjection pre-filter on all user-controlled inputs (fast, offline C library).
4. Asset enumeration via Firecrawl — collect all `<script src>` / `<iframe src>` URLs.

## Medium-term actions (wk 3–6)

1. Browser-based testing via Playwright:
   - Monitor `document.cookie` access by third-party scripts
   - Log external network calls from page JS
   - Detect exfiltration patterns (sensitive data in POST bodies to external domains)
2. Hybrid fuzzing pipeline: static SQLi candidate → auto-launch sqlmap on that specific param.
3. Extend Nuclei templates for WebHound-specific detection patterns.
4. Build pipeline orchestration to coordinate static → dynamic hand-off.

## Long-term actions (mo 3+)

1. ML/embedding-based JS classifier (local, no cloud):
   - Unsupervised anomaly detection on JS
   - Local fine-tuned transformer on labeled malicious/benign JS samples
2. Automated learning feedback loop: confirmed true positives seed new static rules.
3. Broader labeled datasets; automated regression on new malware samples.

## Implementation guidance (from PDF section 5)

**Candidate libraries:**
- `libinjection` — SQLi token classification on input strings (C, fast, offline)
- `Esprima` / `Acorn` — JS AST parsing for eval/obfuscation detection
- `Nuclei templates` — HTTP request + response matching YAML
- `Yara` — binary/script pattern matching on page content
- `js-beautify` / `uglify` — normalize obfuscated JS before static rescan

**Per-class detection pipelines:**
- SQLi/command injection: static regex (sql/exec/backticks) → dynamic sqlmap per flagged form param
- XSS/HTML injection: Semgrep unescaped output + `.innerHTML` → XSStrike/DalFox fuzz + DOM scan at runtime
- CSRF: Semgrep missing-token + dynamic form submit without token via Playwright
- LFI/RFI: static `include($_GET)` → Nuclei `../` fuzz
- Obfuscation: detect eval/Function()/high-entropy → deobfuscate → rescan
- Third-party assets: enumerate all script/iframe src → blocklist+Yara → monitor network traffic

## Test queries & metrics (PDF section 8)

Run against known-vulnerable apps (OWASP Juice Shop, DVWA):
- "List all SQL injection points"
- "Find obfuscated JavaScript"
- "Was SQLi detected on site X?"
- "List pages with suspicious JS obfuscation"
- "Identify injected malicious scripts"

**Metrics:** precision (reported issues are real) + recall (known issues are found);
top-1 / top-3 retrieval accuracy; confirm findings map to Tier A/B sources.
Measure per vuln class (SQLi, XSS). Track tier authority of returned results.

## Recommended next steps (PDF section 9)

1. Merge the AI-Knowledge Layer branch (stable) — preserves retrieval + manifest.
2. Onboard the approved repos into the ingest pipeline (README + docs).
3. Implement static scan rules as quick win (Semgrep community rules + Yara/regex).
4. Build dynamic scanning harness (Playwright + ZAP + Nuclei).
5. Integrate results into WebHound manifest (manifest entries, pointer memory).
6. Iterate by writing more detectors guided by false negatives from test runs.

Recommended approach: start static rules (fast, broad), gradually add dynamic layers
(confirms real hits), then ML/embedding (catches novel obfuscation). Each layer builds
on the previous for best coverage of injections, obfuscation, and malicious third-party assets.

## Audit sequence

`Review each engine → Fix gaps → Test on known-vuln app → Regression-protect → Benchmark (Phase 10)`

**Related:** [[repo-priority-summary]], [[zap-evidence-model]], [[sqlmap-false-positive-reduction]], [[nuclei-severity-mapping]], [[hybrid-engine-architecture]].
