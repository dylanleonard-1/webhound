---
title: Knowledge Map
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# Knowledge Map

How knowledge flows from corpus sources to WADE retrieval.

```
External Sources:
  MITRE CWE (16) · OWASP (6) · VirusTotal · GreyNoise
  Nuclei (18) · DalFox (6) · ZAP (9) · Firecrawl (9) · Semgrep (9)
  Cloudflare (9) · Vercel (7) · Railway (5) · GitHub MCP (12)
  LightRAG docs (10) · WebHound internal (211+)
           │
           ▼
    ┌─────────────────────┐
    │   KNOWLEDGE CORPUS  │
    │   487 records       │
    │   corpus/manifests/ │
    │   manifest.jsonl    │
    └──────────┬──────────┘
               │ chunked (1161 chunks)
     ┌─────────┼──────────────────────┐
     ▼         ▼                      ▼
┌─────────┐ ┌──────────┐    ┌──────────────────┐
│Embeddings│ │LightRAG  │    │Graphiti episodes │
│all-MiniLM│ │indexing  │    │13 seeds          │
│384-dim   │ │phi3:mini │    │phi3:mini LLM     │
│1161 vecs │ │19 entities│   │nomic-embed 768d  │
└────┬─────┘ └────┬─────┘   └────────┬─────────┘
     │            │                  │
     └────────────┴──────────────────┘
                  │
           ┌──────▼──────┐
           │   NEO4J     │
           │ 172 nodes   │
           │ 191 rels    │
           └──────┬──────┘
                  │
           ┌──────▼──────┐
           │  RETRIEVAL  │
           │ WADE query  │
           │ → lexical   │
           │ → vector    │
           │ → graph     │
           └─────────────┘
```

## Coverage by Category

| Category | Records | In Retrieval |
|----------|---------|-------------|
| Scanner engine notes | 222 | ✅ Lexical + vector |
| Canonical notes | 198 | ✅ Lexical + vector |
| Policy docs | 24 | ✅ Lexical |
| Provider notes | 14 | ✅ Lexical + vector |
| FP notes | 10 | ✅ Lexical + Graphiti |
| TI docs | 9 | ✅ Lexical + Graphiti |
| Phase reports | 6 | ✅ Lexical |
| Decision logs | 3 | ✅ Graphiti episodes |

#webhound #maps #knowledge
