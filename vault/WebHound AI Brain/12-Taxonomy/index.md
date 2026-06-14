---
title: Taxonomy
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 12 — Taxonomy

→ Existing Phase 8A coverage: [[07-Vulnerability Taxonomy/Taxonomy Overview|Taxonomy Overview]] · [[07-Vulnerability Taxonomy/CWE Mapping|CWE Mapping]] · [[07-Vulnerability Taxonomy/OWASP Categories|OWASP Categories]] · [[07-Vulnerability Taxonomy/Severity Framework|Severity Framework]]

## Corpus Coverage

| Source | Records | Type |
|--------|---------|------|
| MITRE CWE | 16 | official_taxonomy_doc |
| OWASP | 6 | official_doc |
| Internal taxonomy rules | 24 | policy_doc |

## Key CWEs Referenced Across Scanner Engines

| CWE | Name | Engines |
|-----|------|---------|
| CWE-79 | XSS | Forms, JavaScript → [[02-Scanner Engines/DalFox Engine|DalFox]] |
| CWE-200 | Information Exposure | Crawler, API Discovery |
| CWE-284 | Improper Access Control | Sensitive Paths, DNS |
| CWE-295 | Improper Certificate Validation | TLS |
| CWE-312 | Cleartext Storage | JavaScript, Cookies |
| CWE-352 | CSRF | Forms |
| CWE-601 | Open Redirect | Compromise Detection |
| CWE-614 | Insecure Cookie | Cookies |
| CWE-693 | Protection Mechanism Failure | Headers |
| CWE-829 | Untrusted Control Sphere | Third-Party Domains |
| CWE-1104 | Vulnerable Component | CMS, JavaScript |

## See Also

- [[07-Scanner/index|Scanner]] · [[08-WADE/index|WADE]] · [[13-Knowledge Corpus/index|Corpus]]
- [[07-Vulnerability Taxonomy/index|Phase 8A Taxonomy]]

#webhound #taxonomy #index
