---
title: Scanner
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 07 — Scanner

WebHound's scanner runs 14 analysis modules against each target domain. Results feed into WADE scoring and findings storage.

## Pipeline

```
Trigger (schedule/manual) → scan_jobs.py → engine dispatch
  → 14 modules run in parallel/sequence
  → findings collected → result_persistence.py
  → WADE correlation → wade_correlation.py
  → notifications
```

## 14 Analysis Modules

| Module | Note |
|--------|------|
| Crawler | [[07-Scanner/Engine - Crawler]] |
| Headers | [[07-Scanner/Engine - Headers]] |
| Cookies | [[07-Scanner/Engine - Cookies]] |
| TLS | [[07-Scanner/Engine - TLS]] |
| DNS | [[07-Scanner/Engine - DNS]] |
| Sensitive Paths | [[07-Scanner/Engine - Sensitive Paths]] |
| Forms | [[07-Scanner/Engine - Forms]] |
| JavaScript | [[07-Scanner/Engine - JavaScript]] |
| Third-Party Domains | [[07-Scanner/Engine - Third-Party Domains]] |
| CMS Detection | [[07-Scanner/Engine - CMS Detection]] |
| API Discovery | [[07-Scanner/Engine - API Discovery]] |
| Compromise Detection | [[07-Scanner/Engine - Compromise Detection]] |
| Threat Intel | [[07-Scanner/Engine - Threat Intel]] |
| Reporting | [[07-Scanner/Engine - Reporting]] |

## External Scanner Tools (Phase 8A)

- [[02-Scanner Engines/DalFox Engine|DalFox]] — XSS detection
- [[02-Scanner Engines/Nuclei Engine|Nuclei]] — template-based scanning
- [[02-Scanner Engines/ZAP Engine|ZAP]] — DAST proxy scanning
- [[02-Scanner Engines/Scanner Engines Overview|Overview]]

## WADE Integration

Every finding has a `confidence` field. WADE post-processing applies:
- FP rules (per provider, per pattern)
- Behavioural anomaly correlation (cross-scan)
- Severity adjustment

→ [[08-WADE/index|WADE Index]]

## Provider Access

Scanner needs firewall bypass for protected sites:
- [[06-Infrastructure/Cloudflare|Cloudflare]] — IP allowlisting
- [[06-Infrastructure/Vercel|Vercel]] — Deployment Protection bypass

## Knowledge Corpus

222 engine notes across scanner sources (87% internal + detection repos).

## See Also

- [[07-Scanner/Scanner Pipeline Overview|Pipeline Overview]] · [[08-WADE/index|WADE]]
- [[09-Threat Intelligence/index|Threat Intel]] · [[05-Database/Database Entity Map|Entity Map]]
- [[WEBHOUND_BRAIN_DASHBOARD|Dashboard]]

#webhound #scanner #index
