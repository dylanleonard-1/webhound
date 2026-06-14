---
title: "Engine: API Discovery"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: API Discovery

## Purpose
Discovers API endpoints (REST, GraphQL) exposed by the target. Identifies unprotected API documentation, unauthenticated endpoints, and rate-limit-free APIs.

## Inputs
- Crawler URL inventory
- Common API path patterns (`/api/`, `/graphql`, `/v1/`, `/swagger`)
- OpenAPI / Swagger spec files if accessible

## Outputs
- API endpoint inventory
- Unprotected doc endpoints (`/docs`, `/swagger-ui`)
- Unauthenticated data-exposure findings

## Related Findings
- Unprotected Swagger UI → information disclosure
- GraphQL introspection enabled → schema exposure
- Unauthenticated API → CWE-306

## Related Taxonomy
- CWE-306 (Missing Authentication for Critical Function)
- CWE-200 (Information Exposure)
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- API endpoints that return 200 but no data → low confidence finding
- [[08-WADE/index|WADE]]

## Repo Path
`apps/api/services/engines.py`

#webhound #scanner #api-discovery
