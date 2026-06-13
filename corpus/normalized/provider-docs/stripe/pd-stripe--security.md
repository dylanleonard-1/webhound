# Stripe Security

Source: https://docs.stripe.com/security
Provider: Stripe | Authority: Tier A
Ingested: 2026-06-13 | Terms: Stripe docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## TLS and Encryption

- Minimum TLS 1.2 required; requests using older TLS automatically blocked
- All internal server-to-server communication uses mutual TLS (mTLS)
- HSTS enforced across all services; Stripe domains on HSTS preload lists for major browsers
- TLS implementation regularly audited; certificate authorities and ciphers regularly reviewed

## PCI DSS compliance

- PCI Service Provider Level 1 (most stringent available)
- Annual audits by PCI-certified auditors; covers Card Data Vault (CDV) and secure software development

## Card data security

- PANs tokenized internally; raw card numbers isolated from rest of infrastructure
- AES-256 encryption at rest; decryption keys on separate machines
- Card Data Vault (CDV) runs in separate AWS environment; no credential sharing with primary Stripe services
- Infrastructure can only request card transmission to allowlisted service providers

## API key security

- **Restricted API keys**: granular permission scoping to reduce exposure risk
- **IP allowlisting**: limit API secret keys to specific IP addresses
- **Proactive scanning**: Stripe automatically scans internet for compromised merchant API keys; integrates with GitHub Token Scanner for leaked key detection

## Authentication

- Passkeys (phishing-resistant, recommended)
- Hardware security keys (phishing-resistant, recommended)
- TOTP authenticators
- SAML 2.0 SSO with SCIM integration

## Webhook endpoint IP allowlist

Stripe publishes its IP ranges at https://docs.stripe.com/ips — scanners/firewall rules can allowlist these for Stripe webhook delivery.

## WebHound scanner detection relevance

When scanning Stripe-integrated applications:
- Missing Stripe-Signature validation on webhook endpoint = critical finding
- API keys committed to source code = critical finding (Stripe's GitHub scanner will detect and alert)
- API keys not scoped to minimum required permissions = medium finding
- Webhook endpoint without HTTPS = critical finding (Stripe requires HTTPS in production)
- Missing TLS v1.2 minimum = medium finding
