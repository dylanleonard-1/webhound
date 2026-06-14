---
title: "Engine: Headers"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: Headers

## Purpose
Checks HTTP response headers for security misconfigurations: missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.

## Inputs
- HTTP responses from crawler
- Header allowlist / expected values

## Outputs
- Findings per missing/misconfigured header
- WADE confidence score per finding

## Related Findings
- Missing Content-Security-Policy → CWE-693
- Missing HSTS → CWE-295
- Missing X-Frame-Options → CWE-1021

## Related Taxonomy
- CWE-693, CWE-295, CWE-1021
- OWASP A05:2021 Security Misconfiguration
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- WADE cross-scan: "persistent header regressions" rule in `wade_correlation.py`
  — fires when same header has been absent/wrong across last N scans
- [[08-WADE/index|WADE]]

## Related Threat Intel
- CDN-served sites may strip security headers → [[09-Threat Intelligence/index|TI]]

## Knowledge Corpus
- 107 internal engine notes include header analysis patterns

## Repo Path
`apps/api/services/engines.py`

#webhound #scanner #headers
