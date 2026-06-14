---
title: WebHound Architecture Overview
status: active
source: webhound-ai-brain
created: 2026-06-14
phase: 8A
scope: internal
---
<!-- WEBHOUND-GENERATED -->


# WebHound Architecture Overview

WebHound is an automated security intelligence platform. Phase 8A adds retrieval-augmented knowledge to the scanner + WADE pipeline.

## Components

- Scanner Engines: Nuclei, ZAP, DalFox
- WADE: confidence scoring + FP suppression
- Knowledge Corpus: 487 docs, 1161 chunks
- Hybrid Retrieval: 35% lexical + 65% dense
- AI Brain: graph/memory layer (Phase 8A+)

## See Also

- [[AI Brain Map]]
- [[WADE Overview]]
- [[Scanner Engines Overview]]
- [[Corpus Overview]]

#architecture #webhound
