# Knowledge Graph Schema

The relationship types the Knowledge Layer graph models (built incrementally in
Phase 5+; Phase 4 defines the schema only). Nodes reference manifest `doc_id`s so
every edge is grounded in provenance.

## Relationship types
| Edge | From → To | Meaning |
|------|-----------|---------|
| `source→document` | source → document | a source produced a corpus document |
| `document→chunk` | document → chunk | a normalized chunk derives from a document (lineage) |
| `chunk→entity` | chunk → entity | a chunk mentions an entity (provider, CWE, malware family, tool) |
| `provider→allowlist_method` | provider → allowlist_method | how a provider's scanner access is granted (api / manual) |
| `tool→capability` | tool → capability | what a tool/MCP can do |
| `finding_type→false_positive_rule` | finding_type → FP rule | a finding type maps to an FP lesson (`false-positive-catalog/`) |
| `finding_type→playbook` | finding_type → playbook | remediation playbook for a finding type |
| `finding_type→verification_method` | finding_type → verification | how to verify a finding before flagging |
| `scanner_engine→finding_type` | engine → finding_type | which engine emits which finding types |
| `finding_type→owasp_mapping` | finding_type → OWASP/CWE | standards mapping |
| `threat_feed→indicator` | feed → indicator | a feed supplies an indicator (runtime store owns indicators) |
| `indicator→domain` | indicator → domain | an indicator targets a domain |
| `script→domain` | script → domain | a script is served from / beacons to a domain |
| `scan→security_graph` | scan → security_graph | a scan produced a per-scan Security Graph |
| `security_graph→evidence_node` | security_graph → node | the Security Graph's evidence nodes (read-only into KL) |
| `knowledge_note→manifest_doc_id` | note → doc_id | a curated note cites corpus evidence |
| `memory_summary→knowledge_note` | memory → note | a memory summary points to a curated note |

## Rules
- **Provenance-grounded:** nodes carry/reference manifest `doc_id`s; no edge invents
  a relationship not backed by a document/observation.
- **Authority preserved:** an edge never upgrades a source's tier.
- **Security Graph is read-only & one-way** into the Knowledge Layer
  (`scan→security_graph→evidence_node`); the Knowledge Layer never writes back to the
  runtime Security Graph or changes scanner decisions (see
  `SECURITY_GRAPH_BRIDGE.md`).
- **Threat indicators** live in the runtime store (`scanner/webhound/threat_intel`);
  the graph references them, it does not duplicate them.

## Distinct from the Security Graph
This is the **long-term knowledge graph** (sources/docs/chunks/entities/playbooks).
`scanner/webhound/graph/` is the **per-scan runtime** Security Graph. Bridged
read-only; never merged.
