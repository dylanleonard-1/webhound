---
title: "Engine: Compromise Detection"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: Compromise Detection

## Purpose
Detects active compromise indicators: injected scripts, defacement patterns, cryptominer scripts, malicious redirects, web shells, phishing page signatures.

## Inputs
- Page DOM content from crawler
- Script content
- Redirect chains

## Outputs
- Active compromise findings (high severity)
- Injected content evidence
- Suspicious redirect chains

## Related Findings
- Cryptominer injected → CWE-1038
- Malicious redirect → CWE-601
- Web shell detected → CWE-78
- Defacement → content integrity breach

## Related Taxonomy
- CWE-601, CWE-78, CWE-1038
- [[12-Taxonomy/index|Taxonomy]]

## Related Threat Intel
- Indicators cross-checked against threat intel sources
- [[09-Threat Intelligence/index|Threat Intel]]

## Related WADE Logic
- High-confidence rule: compromise findings never FP-suppressed without explicit approval
- [[08-WADE/index|WADE]]

## Repo Path
`apps/api/services/engines.py`

#webhound #scanner #compromise
