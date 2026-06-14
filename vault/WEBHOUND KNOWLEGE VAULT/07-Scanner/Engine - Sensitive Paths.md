---
title: "Engine: Sensitive Paths"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: Sensitive Paths

## Purpose
Probes well-known sensitive paths: admin panels, `.git`, backup files, config files, API docs endpoints, debug endpoints.

## Inputs
- Crawler page inventory
- Wordlist of sensitive path patterns

## Outputs
- Findings per accessible sensitive path
- HTTP status + content type evidence

## Common Targets
- `/.git/`, `/.env`, `/backup.zip`, `/wp-admin`, `/admin`, `/.DS_Store`
- `/api/docs` (unprotected Swagger), `/debug`, `/phpinfo.php`
- `robots.txt` (surface enumeration)

## Related Findings
- Exposed source code → CWE-540
- Exposed credentials → CWE-312
- Admin panel accessible → CWE-284

## Related Taxonomy
- CWE-540, CWE-312, CWE-284
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- FP rules for known-public paths (e.g. `/sitemap.xml` is not a finding)
- Nuclei templates provide confidence baseline
- [[08-WADE/index|WADE]]

## Knowledge Corpus
- Nuclei: 10 engine notes (template-based path scanning)
- Nuclei-templates: 8 engine notes

## Repo Path
`apps/api/services/engines.py`

#webhound #scanner #sensitive-paths
