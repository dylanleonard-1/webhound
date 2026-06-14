---
title: "Engine: Reporting"
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Engine: Reporting

## Purpose
Aggregates scan output into structured reports: finding summaries, severity distribution, remediation guidance, scan delta, timeline.

## Inputs
- `ScanResult` with all `Finding[]` and `GroupedFinding[]`
- `ScanDelta` (vs prior scan)
- WADE confidence scores

## Outputs
- `Report` record (`models/report.py`)
- PDF / JSON export (stored URL in `Report.storage_url`)
- Scan summary score

## Report Content
- Overall security score
- Finding breakdown by severity (critical/high/medium/low/info)
- New vs resolved findings (from ScanDelta)
- Grouped findings with remediation steps
- Trend over time (requires multiple scans)

## Related DB Objects
- `Report` · `ScanResult` · `GroupedFinding` · `ScanDelta`
- [[05-Database/Database Entity Map|Entity Map]]

## See Also
- [[07-Scanner/index|Scanner Index]] · [[23-Reports/index|Reports Section]]
- [[08-WADE/index|WADE]]

#webhound #scanner #reporting
