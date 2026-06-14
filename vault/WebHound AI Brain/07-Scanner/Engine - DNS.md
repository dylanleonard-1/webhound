---
title: "Engine: DNS"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: DNS

## Purpose
Resolves DNS records for the target domain. Identifies dangling CNAMEs, subdomain takeover risk, SPF/DMARC misconfigs.

## Inputs
- Target domain
- DNS resolver output (A, CNAME, MX, TXT records)

## Outputs
- Findings for dangling CNAME targets
- SPF/DMARC absence findings
- Subdomain enumeration for scan surface expansion

## Related Findings
- Dangling CNAME → subdomain takeover (CWE-284)
- Missing DMARC → email spoofing risk
- Wildcard DNS → unintended exposure

## Related Taxonomy
- CWE-284 (Improper Access Control)
- [[12-Taxonomy/index|Taxonomy]]

## Related Threat Intel
- CDN/WAF DNS patterns (Cloudflare CNAME detection)
- [[09-Threat Intelligence/index|TI]] · [[10-Providers/index|Providers]]

## Repo Path
`apps/api/services/engines.py`

#webhound #scanner #dns
