---
title: "Engine: Crawler"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: Crawler

## Purpose
Discovers pages, links, and resources on the target domain. Forms the input surface for all other analysis modules.

## Inputs
- Target URL (from `Website.url`)
- Depth limit, follow-external config
- Auth credentials (if provided)

## Outputs
- Page inventory (URLs discovered)
- DOM structure per page
- Link graph

## Dependencies
- `services/scan_jobs.py` — triggers crawl
- External: Firecrawl (9 engine notes in corpus)

## Related Findings
- Exposed admin pages → [[07-Scanner/Engine - Sensitive Paths]]
- JS-heavy SPAs → [[07-Scanner/Engine - JavaScript]]

## Related Taxonomy
- CWE-200 (Information Exposure) for excessive crawlable content
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- Crawl depth affects false-positive rate on sensitive-path findings
- [[08-WADE/index|WADE]]

## Knowledge Corpus
- Firecrawl: 9 engine notes (official_repo, tier B)

## Repo Path
`apps/api/services/engines.py` (dispatch) · `services/scan_jobs.py` (orchestration)

#webhound #scanner #crawler
