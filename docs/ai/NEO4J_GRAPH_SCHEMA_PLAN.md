# Neo4j Graph Schema Plan

Phase 8A graph schema for the WebHound knowledge graph.

## Overview

The WebHound knowledge graph represents relationships between scanning artifacts,
knowledge sources, providers, vulnerabilities, and WADE decisions. Neo4j's property
graph model suits this domain: entities are nodes, semantic connections are relationships.

## Node Types

### Knowledge Layer Nodes

| Node | Key Properties | Description |
|------|----------------|-------------|
| `KnowledgeSource` | doc_id, title, source_type, authority_tier, phase | A document in the knowledge corpus |
| `Chunk` | chunk_id, text, chunk_index, file_path, topic_tags | A semantic chunk from a KnowledgeSource |
| `Engine` | name, type (passive/active), version | A scanner engine (Nuclei, ZAP, DalFox) |

### Vulnerability / Classification Nodes

| Node | Key Properties | Description |
|------|----------------|-------------|
| `FindingCategory` | name, cwe_id, owasp_category, severity_range | A vulnerability class |
| `EvidenceType` | name, weight | A type of evidence (active_confirm, passive_observe...) |
| `CWE` | cwe_id, name, description | Common Weakness Enumeration entry |
| `CVE` | cve_id, cvss_score, published | CVE record (from Nuclei templates) |
| `OWASPCategory` | code, name, year | OWASP Top 10 category (e.g. A03:2021) |

### Provider Nodes

| Node | Key Properties | Description |
|------|----------------|-------------|
| `Provider` | name, category (cdn/waf/cloud/saas), phase_ingested | A provider tracked in corpus |

### Threat Intelligence Nodes

| Node | Key Properties | Description |
|------|----------------|-------------|
| `ThreatIntelSource` | name, type (ip_rep/hash/url), phase | External TI feed |

### WADE Decision Nodes

| Node | Key Properties | Description |
|------|----------------|-------------|
| `WADEDecision` | decision_id, confidence, outcome, timestamp | A WADE finding assessment |

### Scan / Finding Nodes

These represent runtime data (not in Phase 8A corpus — for future phases):

| Node | Key Properties | Description |
|------|----------------|-------------|
| `Customer` | customer_id (anonymized) | A customer account |
| `Domain` | fqdn, tld | A scanned domain |
| `Scan` | scan_id, started_at, status | A scan run |
| `Page` | url, status_code, response_time | A scanned page |
| `Script` | url, hash | A third-party script resource |
| `Finding` | finding_id, type, severity, confidence | A raw scanner finding |
| `Report` | report_id, generated_at | A delivered report |

## Relationship Types

### Knowledge Relationships

```cypher
(:KnowledgeSource)-[:HAS_CHUNK]->(:Chunk)
(:KnowledgeSource)-[:SUPPORTS]->(:FindingCategory)
(:FindingCategory)-[:MAPS_TO]->(:CWE)
(:CWE)-[:BELONGS_TO]->(:OWASPCategory)
(:CWE)-[:CORRELATED_WITH]->(:CWE)
```

### Provider Relationships

```cypher
(:Provider)-[:OBSERVED_ON]->(:Domain)
(:Provider)-[:CONFIRMED_BY]->(:ThreatIntelSource)
(:Provider)-[:FLAGGED_BY]->(:Engine)
```

### Finding Relationships

```cypher
(:Finding)-[:EXPLAINED_BY]->(:KnowledgeSource)
(:Finding)-[:SUPPRESSED_BY]->(:WADEDecision)
(:Finding)-[:MAPS_TO]->(:CWE)
(:Finding)-[:OBSERVED_ON]->(:Page)
(:Page)-[:BELONGS_TO]->(:Domain)
(:Domain)-[:CHANGED_SINCE]->(:Scan)
```

### Evidence Relationships

```cypher
(:WADEDecision)-[:SUPPORTED_BY]->(:EvidenceType)
(:WADEDecision)-[:USES_CHUNK]->(:Chunk)
(:Engine)-[:GENERATED]->(:Finding)
```

## Example Cypher Queries

### "What knowledge supports XSS findings?"

```cypher
MATCH (ks:KnowledgeSource)-[:SUPPORTS]->(fc:FindingCategory)-[:MAPS_TO]->(c:CWE {cwe_id: "CWE-79"})
RETURN ks.title, ks.authority_tier, ks.source_type
ORDER BY ks.authority_tier
```

### "Which providers have WAF-related FP suppressions?"

```cypher
MATCH (p:Provider)-[:OBSERVED_ON]->(d:Domain)<-[:OBSERVED_ON]-(f:Finding)
      -[:SUPPRESSED_BY]->(w:WADEDecision)
WHERE p.category = "waf"
RETURN p.name, count(w) AS fp_suppressions
ORDER BY fp_suppressions DESC
```

### "Find chunks related to Cloudflare WAF"

```cypher
MATCH (p:Provider {name: "cloudflare"})<-[:SUPPORTED_BY]-(ks:KnowledgeSource)
      -[:HAS_CHUNK]->(ch:Chunk)
WHERE "waf" IN ch.topic_tags
RETURN ch.chunk_id, ch.text LIMIT 10
```

## Implementation Notes

- **Phase 8A scope**: Schema design only. Neo4j is not installed or running.
- **Runtime nodes** (`Scan`, `Finding`, `Report`, etc.) require future integration with the scanner pipeline
- **Knowledge nodes** (`KnowledgeSource`, `Chunk`, `Provider`) can be loaded from the existing corpus/manifest
- **Local Neo4j**: Use Neo4j Community 5.x via Docker for development

## Seeding Knowledge Nodes

```cypher
// Load from manifest (via APOC or Python driver)
CALL apoc.load.json('corpus/manifests/manifest.jsonl') YIELD value
CREATE (:KnowledgeSource {
  doc_id: value.doc_id,
  title: value.title,
  authority_tier: value.authority_tier,
  source_type: value.source_type,
  phase: value.phase
})
```

## Files Created (Phase 8A)

- `docs/ai/NEO4J_GRAPH_SCHEMA_PLAN.md` (this file)
