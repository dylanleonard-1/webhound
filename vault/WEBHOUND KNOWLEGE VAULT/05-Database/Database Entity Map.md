---
title: Database Entity Map
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Database Entity Map

All entities grounded in `apps/api/models/`.

## Core Entities

### User (`models/user.py`)
Fields: id, email, hashed_password, is_active, is_verified, org_id, created_at, updated_at

### Org (`models/org.py`)
Fields: id, name, slug, plan_tier, created_at

### Website (`models/website.py`)
Fields: id, org_id, url, verified, created_at, group_id

### WebsiteGroup (`models/website_group.py`)
Fields: id, org_id, name

### ScanJob (`models/scan_job.py`)
Fields: id, website_id, status (ScanStatus enum), triggered_by, created_at, completed_at

### ScanResult (`models/scan_result.py`)
Fields: id, scan_job_id, website_id, score, summary, metadata (JSON)

### Finding (`models/finding.py`)
Fields: id, scan_result_id, scanner_finding_id, title, severity, category, scanner_engine, affected_url, confidence, description, remediation, evidence (JSON), framework (JSON)

### GroupedFinding (`models/grouped_finding.py`)
Fields: id, scan_result_id, category, severity, count, description

### ScanDelta (`models/scan_delta.py`)
Fields: id, scan_result_id, prior_scan_result_id, drift fields (WADE cross-scan correlation)

### Baseline (`models/baseline.py`)
Fields: id, website_id, snapshot data for drift comparison

### Suppression (`models/suppression.py`)
Fields: id, org_id, rule, pattern, scanner_engine, created_by

## Provider Entities

### ProviderConnection (`models/provider_connection.py`)
Fields: id, org_id, provider (cloudflare/vercel), credentials ref, status

### ProviderProfile (`models/provider_profile.py`)
Fields: id, connection_id, site identifier, firewall config state

## Security & Access

### TrustedAccess (`models/trusted_access.py`)
Fields: id, website_id, ip_ranges, headers — scanner allowlist profile

### EncryptedSecret (`models/encrypted_secret.py`)
Fields: id, org_id, key_ref, encrypted_value — vault for provider tokens

## Billing

### Subscription (`models/subscription.py`)
Fields: id, org_id, stripe_sub_id, tier, status, period_end

## Observability

### Report (`models/report.py`)
Fields: id, scan_result_id, format, storage_url

### Notification (`models/notification.py`)
Fields: id, org_id, type, payload, sent_at

### Alert (`models/alert.py`)
Fields: id, org_id, website_id, condition, threshold

### Incident (`models/incident.py`)
Fields: id, org_id, scan_result_id, severity, status

### AdminAuditLog (`models/admin_audit_log.py`)
Fields: id, actor, action, target, metadata, created_at

## Threat Intel

### ThreatIndicator (`models/threat_indicator.py`)
Fields: id, indicator_type, value, source, score, first_seen, last_seen

## Enum Reference (`models/enums.py`)

- `ScanStatus`: pending, running, completed, failed
- `DriftSeverity`: low, medium, high, critical
- `SubscriptionTier`: free, pro, enterprise

## Entity Relationship Summary

```
Org ──< User
Org ──< Website ──< ScanSchedule ──< ScanJob ──< ScanResult ──< Finding
                                                              ──< GroupedFinding
                                                              ──< ScanDelta
Org ──< Subscription
Org ──< ProviderConnection ──< ProviderProfile
Website ──< TrustedAccess
Finding ──< Suppression
ScanResult ──< Report
```

## See Also

- [[05-Database/index|Database Index]] · [[04-Backend/index|Backend]] · [[07-Scanner/index|Scanner]]
- [[08-WADE/index|WADE]] · [[10-Providers/index|Providers]] · [[21-Billing/index|Billing]]

#webhound #database #entities
