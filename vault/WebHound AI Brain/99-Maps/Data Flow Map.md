---
title: Data Flow Map
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Data Flow Map

How data flows from scan trigger to final report.

```
USER ACTION: "Scan domain example.com"
      │
      ▼
[Backend] POST /scans → ScanJob created (status=pending)
      │
      ▼
[Scanner] 14 modules execute:
  ├─ Crawler       → page inventory
  ├─ Headers       → security header checks
  ├─ Cookies       → cookie attribute checks
  ├─ TLS           → certificate + protocol checks
  ├─ DNS           → record + DMARC checks
  ├─ Sensitive Paths → exposed files/panels
  ├─ Forms         → CSRF + input checks
  ├─ JavaScript    → secrets + outdated libs
  ├─ Third-Party   → external domain inventory
  ├─ CMS           → platform detection
  ├─ API Discovery → endpoint enumeration
  ├─ Compromise    → active threat detection
  ├─ Threat Intel  → IP/domain reputation check
  └─ Reporting     → aggregate + score
      │
      ▼
[Persistence] ScanResult + Finding[] stored → PostgreSQL
      │
      ▼
[WADE] Post-processing:
  ├─ FP rule application (Suppression rules)
  ├─ Cross-scan correlation (wade_correlation.py)
  ├─ Knowledge retrieval (AI Brain)
  └─ TI enrichment (VirusTotal, GreyNoise)
      │
      ▼
[AI Brain Query] WADE → HybridRetrieval:
  ├─ Lexical search → corpus chunks (1161)
  ├─ Vector search  → LightRAG (19 entities)
  ├─ Graph search   → Neo4j/Graphiti (172 nodes)
  └─ Merged context → WADE reasoning
      │
      ▼
[Output] Enriched findings → GroupedFinding[] → Report
      │
      ▼
[Delivery] Notifications → Alerts → User dashboard
```

## Data Stores Touched

| Store | Data Written |
|-------|-------------|
| PostgreSQL | ScanJob, ScanResult, Finding, GroupedFinding, ScanDelta |
| LightRAG storage | Not touched per-scan (pre-indexed) |
| Neo4j | ThreatIndicator records (via Graphiti future) |

#webhound #maps #data-flow
