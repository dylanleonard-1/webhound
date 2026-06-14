---
title: "Engine: JavaScript"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: JavaScript

## Purpose
Analyzes JavaScript bundles for exposed secrets, third-party library versions, inline credentials, and source map exposure.

## Inputs
- JS files discovered by crawler
- `<script>` tags, dynamic imports

## Outputs
- Exposed API keys / credentials in JS
- Outdated vulnerable library versions
- Source map exposure (`.map` files)
- postMessage handling issues

## Related Findings
- Hardcoded secrets → CWE-312, CWE-798
- Source map exposure → CWE-540
- Outdated deps with CVEs → CWE-1104

## Related Taxonomy
- CWE-312, CWE-540, CWE-798, CWE-1104
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- Semgrep integration for static JS analysis
- [[02-Scanner Engines/Scanner Engines Overview|Semgrep integration (Phase 8A)]]
- [[08-WADE/index|WADE]]

## Knowledge Corpus
- Semgrep: 9 engine notes (static analysis patterns)

## Repo Path
`apps/api/services/engines.py`

#webhound #scanner #javascript
