---
title: "Engine: TLS"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: TLS

## Purpose
Inspects TLS/SSL configuration: protocol version, cipher suites, certificate validity, expiry, chain of trust.

## Inputs
- TLS handshake data from target
- Certificate chain

## Outputs
- Findings for weak protocols (TLS 1.0/1.1), weak ciphers, expired certs
- Certificate metadata

## Related Findings
- TLS 1.0/1.1 in use → downgrade attack risk
- Expired certificate → trust failure
- Self-signed cert → MITM risk

## Related Taxonomy
- CWE-295 (Improper Certificate Validation)
- CWE-326 (Inadequate Encryption Strength)
- [[12-Taxonomy/index|Taxonomy]]

## Related WADE Logic
- WADE cross-scan: "recurring TLS instability" rule in `wade_correlation.py`
  — fires when ≥2 TLS-config changes across N scans
- [[08-WADE/index|WADE]]

## Repo Path
`apps/api/services/engines.py`

#webhound #scanner #tls
