# Vercel Firewall

Source: https://vercel.com/docs/vercel-firewall
Provider: Vercel | Authority: Tier A
Ingested: 2026-06-13 | Terms: Developer docs are publicly available; ingesting factual summary only.
Note: SUMMARIZED detection-relevant extract, not a verbatim mirror.

The Vercel Firewall is a robust, multi-layered security system designed to protect applications from a wide range of threats. Every incoming request goes through the following layers:

**Layer 1: Platform-wide firewall** — DDoS mitigation available to all customers at no cost, no configuration required. Blocks large-scale attacks (DDoS, TCP floods). Automatic, not configurable by users.

**Layer 2: Vercel WAF** — Customizable layer with custom rules, IP blocking, managed rulesets, and Attack Mode.

## Rule execution order

1. DDoS mitigation rules
2. WAF IP blocking rules
3. WAF custom rules
4. WAF Managed Rulesets

## Firewall actions

**Log** — request proceeds normally; details logged in Firewall and Monitoring tabs. No visitor impact.

**Deny** — returns `403 Forbidden`; request does not reach application; does not incur CDN/data transfer costs.

**Challenge** — JS browser challenge ("Vercel Security Checkpoint" screen); browser must execute JS to prove legitimacy. Session valid for 1 hour. Non-browser clients (bots, scripts, curl) fail challenge. API routes behind challenge rules cannot be accessed by automated tools outside a valid session.

**Bypass** — skips custom or managed rules; request proceeds directly to application.

## DDoS mitigation

Targets OSI layers 3, 4, and 7:
- L3: targets specific IPs/networks
- L4: SYN floods, targeting TCP handshake
- L7: GET/POST floods leveraging app-layer vulnerabilities; Vercel provides proprietary L7 mitigation with continuous tuning

## JA3 and JA4 TLS fingerprinting

Vercel Firewall uses JA3 and JA4 TLS fingerprints to identify and restrict malicious traffic.

**How it works:** TLS fingerprints are created from TLS client hello packet details (TLS version, cipher suites, extensions). The hash uniquely identifies a client session.

**Why it matters:** A DDoS attack spread across multiple user agents, IPs, or geos may share the same TLS fingerprint. Vercel blocks all traffic matching that fingerprint.

**JA4** (preferred): more granular and flexible; part of JA4+ suite. Better for identifying, tracking, and categorizing encrypted traffic.

**JA3**: focuses on TLS client hello packet; generates hash from TLS version, cipher suites, extensions.

## Request headers for TLS fingerprints

These headers are sent to every deployment (readable in Functions):

- `x-vercel-ja4-digest` — JA4 fingerprint hash (preferred)
- `x-vercel-ja3-digest` — JA3 fingerprint hash

## Persistent actions

When a WAF rule blocks a request with a persistent action, the source IP is stored in the platform firewall so future requests from that source are blocked for a specified period at the platform level.

## Observability

- **Firewall tab** in dashboard: live traffic window, firewall alerts
- **Monitoring tab**: team-level traffic queries and visualization
- **Log Drains**: send logs to SIEM systems
