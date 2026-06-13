# XSStrike — Context Analysis

**Tool:** XSStrike · **Type:** XSS scanner · **Concept:** context analysis

XSStrike's core idea: **"instead of injecting payloads blindly, analyse the response
context and craft guaranteed-working payloads."** It reflects a unique probe string,
locates every place it appears in the response, and classifies the **injection
context** at each — HTML body, inside a single/double-quoted attribute, inside an
unquoted attribute, within a `<script>` block, inside an event handler, in a URL/
`href`, or in a comment. The required breakout (which quote/tag/encoding to escape)
depends entirely on that context, so XSStrike's fuzzing engine generates only
payloads that can actually execute *there*, and it accounts for the page's WAF and
any reflected filtering/encoding.

**Why it matters for WebHound:** context-aware reflection analysis is the difference
between a noisy "string was reflected" heuristic and a real XSS detector. WebHound's
JavaScript/reflection reasoning and WADE confidence should weight a finding by
*whether the reflection lands in an executable context with a viable breakout* —
that is the proof that distinguishes exploitable XSS from harmless reflection.

**Related:** [[xsstrike-payload-generation]], [[xsstrike-dom-xss]], [[dalfox-xss-validation]].
