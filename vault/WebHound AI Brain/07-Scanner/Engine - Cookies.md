---
title: "Engine: Cookies"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: Cookies

## Purpose
Analyzes Set-Cookie headers and cookie attributes: Secure, HttpOnly, SameSite, domain scope, expiry.

## Inputs
- HTTP responses (Set-Cookie headers)
- Session cookie patterns

## Outputs
- Findings per insecure cookie attribute
- Auth-cookie exposure findings

## Related Findings
- Missing Secure flag → session token transmitted over HTTP
- Missing HttpOnly → XSS-accessible cookies
- Overly broad domain → session fixation risk

## Related Taxonomy
- CWE-614 (Sensitive Cookie Without Secure Attribute)
- CWE-1004 (Sensitive Cookie Without HttpOnly)
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- High-confidence finding when cookie is named `session`, `auth`, `token`
- [[08-WADE/index|WADE]]

## Repo Path
`apps/api/services/engines.py`

#webhound #scanner #cookies
