# Deployment Protection on Vercel

Source: https://vercel.com/docs/deployment-protection
Provider: Vercel | Authority: Tier A
Ingested: 2026-06-13 | Terms: Developer docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

Deployment Protection controls who can access preview and production URLs. Configured at the project level with a **protection method** (how) and **protection scope** (what).

## Protection methods

- **Vercel Authentication** — restricts to Vercel users with suitable access rights. Available on all plans.
- **Passport** — restricts to visitors authenticating via identity provider. Beta; Enterprise only.
- **Password Protection** — restricts to users with correct password. Enterprise plan or Pro add-on ($150/mo).
- **Trusted IPs** — restricts to specific IP addresses. Enterprise only.

## Protection scope

- **Standard Protection** — protects all deployments EXCEPT production domains. Available on all plans.
  - Preview URLs (`*.vercel.app`) and deployment URLs: protected
  - Production domain (`example.com`): publicly accessible
- **All Deployments** — protects ALL URLs including production. Pro/Enterprise.
- **Only Production Deployments** — Trusted IPs only; Enterprise plan.
- **(Legacy) Standard Protection** — protects preview + deployment URLs; production remains unprotected.

## What scanner sees when hitting protected URLs

- Vercel Authentication: redirect to `vercel.com/login` (302) or auth challenge
- Password Protection: password form page (HTML, 200 with auth wall)
- Trusted IPs: 403 if source IP not in allowlist
- Standard Protection on Hobby: preview URLs gated, production public

## Scanner implications

Scanners running against `*.vercel.app` preview URLs frequently encounter Standard Protection. Production domains on `example.com` are typically unprotected (Standard Protection default).

Generated deployment URLs (`my-project-1234.vercel.app`) will be protected under All Deployments scope.

## Source maps protection

Protected Source Maps gates `.map` file requests behind Vercel Authentication, preventing source code exposure.
