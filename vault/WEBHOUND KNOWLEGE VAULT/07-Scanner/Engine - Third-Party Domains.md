---
title: "Engine: Third-Party Domains"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: Third-Party Domains

## Purpose
Enumerates third-party domains loaded by the target (scripts, images, iframes, fonts, analytics). Identifies risky or unexpected external dependencies.

## Inputs
- Crawler network requests
- `<script src>`, `<link>`, `<iframe>` tags
- CSP header domain list

## Outputs
- Third-party domain inventory
- WADE anomaly: "third-party explosion" (domain count ≥3x median)
- Reputation scores via threat intel

## Related Findings
- Suspicious third-party domain → supply chain risk
- Domain loaded but not in CSP → policy gap

## Related Taxonomy
- CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- WADE cross-scan: "unexplained third-party explosion" rule in `wade_correlation.py`
  — fires when current scan domain count ≥3x median of prior N-1 scans
- [[08-WADE/index|WADE]]

## Related Threat Intel
- Third-party domains checked against reputation sources
- [[09-Threat Intelligence/index|Threat Intel]]

## Repo Path
`apps/api/services/engines.py` · `services/wade_correlation.py`

#webhound #scanner #third-party
