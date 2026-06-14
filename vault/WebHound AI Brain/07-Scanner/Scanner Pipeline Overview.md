---
title: Scanner Pipeline Overview
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Scanner Pipeline Overview

## Trigger Points

| Trigger | Source |
|---------|--------|
| Scheduled | `ScanSchedule` → `scan_schedules.py` |
| Manual | `POST /scans` → `scan_jobs.py` |
| Public/demo | `public_scan.py` |
| Admin | `admin/run_scan.py` |

## Execution Flow

```
1. ScanJob created (status=pending)
2. Engine dispatch → services/engines.py
3. Target validation → target_validation.py
4. Provider access check → scanner_access_diagnosis.py
   ├─ Cloudflare bypass if needed → cloudflare_scanner_access.py
   └─ Vercel bypass if needed → vercel_scanner_access.py
5. 14 modules execute (parallel where possible)
6. Results aggregated → result_persistence.py
7. ScanResult created with findings
8. ScanDelta computed → scan_delta.py
9. WADE correlation → wade_correlation.py
10. Notifications dispatched → notifications.py
```

## Scanner Block Detection

`services/scanner_block_detection.py` — detects when scanner is being blocked (WAF, rate limit, auth wall) and flags for provider access review.

## Scanner Identity

`apps/api/routers/scanner_identity.py` — manages scanner IP identity for allowlisting with providers.

## DB Objects Produced

- `ScanJob` (one per run)
- `ScanResult` (aggregated output)
- `Finding[]` (per-issue findings)
- `GroupedFinding[]` (grouped by category)
- `ScanDelta` (diff vs prior scan)

## See Also

- [[07-Scanner/index|Scanner Index]] · [[08-WADE/index|WADE]] · [[05-Database/Database Entity Map|Entity Map]]

#webhound #scanner #pipeline
