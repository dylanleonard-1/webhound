---
title: "Engine: Forms"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: Forms

## Purpose
Discovers and analyzes HTML forms: login forms, search inputs, file uploads, contact forms. Feeds XSS and injection testing.

## Inputs
- Crawler DOM output (forms, inputs, actions)
- CSRF token patterns

## Outputs
- Form inventory (action, method, fields)
- Missing CSRF protection findings
- Autocomplete on sensitive fields
- File upload exposure

## Related Findings
- Missing CSRF token → CWE-352
- Autocomplete on password fields → CWE-522
- Unrestricted file upload → CWE-434

## Related Taxonomy
- CWE-352, CWE-522, CWE-434
- OWASP A01, A03
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- WADE cross-scan: "admin/login surface flapping" rule — login form appears/disappears across scans
- DalFox fed form inputs for XSS testing
- [[08-WADE/index|WADE]] · [[02-Scanner Engines/DalFox Engine|DalFox]]

## Repo Path
`apps/api/services/engines.py`

#webhound #scanner #forms
