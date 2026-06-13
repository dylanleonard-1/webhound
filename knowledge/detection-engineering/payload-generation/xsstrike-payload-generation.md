# XSStrike — Payload Generation

**Tool:** XSStrike · **Concept:** payload generation / fuzzing

XSStrike generates payloads **dynamically per context** rather than firing a fixed
wordlist. Given the detected context and any observed filtering, its fuzzing engine
assembles a breakout from components (tags, attributes, event handlers, encodings)
and mutates them to bypass blacklists and WAFs — varying case, inserting null/
unicode/HTML-entity encodings, using alternate event handlers, and splitting
keywords. It scores candidate payloads by *efficiency* (likelihood of executing in
the target context) so it tries the most promising first. The goal is a **minimal,
guaranteed-working** payload, not brute force.

**Why it matters for WebHound:** payload generation is detection knowledge, not just
attack tooling — it encodes *which transformations a real filter must survive*. For
WebHound this informs (a) how to confirm reflected/stored XSS with a high-signal
probe and (b) how to reason about whether an output encoding is actually safe.
Payload **samples must be handled as contextualised evidence**, never dumped as a
raw exploit list.

**Related:** [[xsstrike-context-analysis]], [[dalfox-parameter-mining]], [[nuclei-matchers]].
