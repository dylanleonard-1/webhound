---
title: "Engine: CMS Detection"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: CMS Detection

## Purpose
Identifies CMS platform (WordPress, Drupal, Joomla, Shopify, etc.) and version. Enables CMS-specific vulnerability checks.

## Inputs
- HTTP responses, DOM, meta tags
- Path patterns, generator meta, admin URLs

## Outputs
- CMS type + version (if detectable)
- CMS-specific findings (e.g. WordPress xmlrpc.php exposed)
- Plugin/theme vulnerability indicators

## Common Detections
- WordPress: `wp-login.php`, `wp-content/`, `generator` meta
- Drupal: `sites/default/`, `node/` paths
- Shopify: `cdn.shopify.com` scripts
- Joomla: `/administrator/` path

## Related Findings
- Outdated CMS version → specific CVEs
- xmlrpc.php exposed → bruteforce/DDoS amplification risk

## Related Taxonomy
- CWE-1104 (Vulnerable Third-Party Component)
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- CMS type informs FP rules (e.g. WordPress login is expected)
- [[08-WADE/index|WADE]]

## Repo Path
`apps/api/services/engines.py`

#webhound #scanner #cms
