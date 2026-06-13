# Fastly Next-Gen WAF (Signal Sciences) Overview

Source: https://www.fastly.com/documentation/guides/next-gen-waf/getting-started/start-here/
Provider: Fastly | Authority: Tier A
Ingested: 2026-06-13 | Terms: Fastly docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

## Overview

Fastly Next-Gen WAF (formerly Signal Sciences WAF, acquired by Fastly 2020) is a cloud-based WAF that inspects HTTP traffic using a signal-based detection system. Unlike traditional WAF rules, it tags requests with signals that identify attack patterns.

## Signal system

Signals are labels identifying important request properties. Each request can receive multiple signals. The platform tags requests based on payload analysis.

Signal categories:
- Standard attack signals (SQLi, XSS, path traversal, command injection, XML encoding errors)
- ATO and API signals (registrations, logins, API requests) — Advanced tier only
- CVE virtual patch signals — protection against specific CVEs without code changes
- Custom signals — tag specific traffic patterns (high-value actions, business logic)

When scanning tools like Nikto are used against protected sites, requests containing attack payloads receive tags such as **Directory Traversal** and **XML Encoding Error**.

## Agent modes (protection modes)

Three operating modes:

1. **Blocking** — active protection; blocks matching requests and logs them
2. **Not Blocking (Logging)** — visibility only; logs without active protection (DEFAULT mode)
3. **Off** — disables all request processing

Default is "Not Blocking" — meaning a new Fastly WAF deployment is in monitoring mode until explicitly switched to Blocking.

## Blocking mechanisms

- **Threshold blocking**: flags IP when attack signal count exceeds defined threshold; subsequent requests blocked/logged for set period
- **Immediate blocking**: blocks all requests containing at least one attack signal
- **Malicious IP blocking**: blocks requests from known bad actors (IP reputation)

## Request data and privacy

Captures request data from detected attacks and anomalies. Optional sampling of legitimate traffic via custom signals and request rules. Default sensitive data redaction; custom field redaction configurable.

## Scanner implications

A scanner hitting a Fastly Next-Gen WAF site in Blocking mode:
- Attack payloads in requests → tagged with attack signals → blocked (HTTP 406 or custom response)
- Response headers: `x-sigsci-requestid` on blocked requests; `x-sigsci-tags` on flagged-but-passed requests
- Threshold blocking can ban scanner IP after repeated attack signals

Allowlisting scanner IPs:
- Fastly WAF Console → Corp → Allowlisted IPs → add CIDR
- Signal Sciences API: `POST /v0/corps/{corp_name}/networks`

## CDN identification headers

Sites fronted by Fastly CDN (distinct from Next-Gen WAF):
- `x-served-by: cache-xxx-xxxx` — Fastly cache node ID
- `x-cache: HIT` or `MISS`
- `x-cache-hits: 1`
- `via: 1.1 varnish`
- ASN: AS54113 (FASTLY)
