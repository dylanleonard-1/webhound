# sqlmap — DBMS Fingerprinting

**Tool:** sqlmap · **Concept:** SQLi fingerprinting / DBMS identification

Before and during exploitation sqlmap **fingerprints the back-end DBMS** so it can
pick the right payloads. It identifies the database (MySQL, PostgreSQL, MSSQL,
Oracle, SQLite, etc.) and version via: error-message banners, DBMS-specific
functions and syntax that succeed only on one engine (e.g. `@@version`,
`version()`, `BANNER`), characteristic string/number casting, comment styles, and
time-delay primitives unique to each DBMS. It also fingerprints the web tech, the
parameter's place (GET/POST/header/cookie), and any WAF/IPS in front (then applies
**tamper** scripts to evade filters).

**Why it matters for WebHound:** fingerprinting is *enrichment that improves
precision* — knowing the stack lets a detector choose payloads that will actually
fire and interpret responses correctly, reducing both false positives and
negatives. WebHound's technology-detection and SQLi reasoning can use this pattern:
identify the target first, then specialise the probe and the evidence
interpretation.

**Related:** [[sqlmap-detection-overview]], [[sqlmap-confidence-model]].
