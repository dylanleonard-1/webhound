# libinjection — Detection Theory

**Tool:** libinjection · **Concept:** signature methodology / detection theory

libinjection embodies several detection-theory lessons. **Model the parser, not the
surface:** detecting by token structure beats matching literal strings because
attackers mutate surface form (encoding, comments, case) but must preserve parseable
structure. **Curate from data:** its fingerprint set was tuned against real attack
and benign corpora to balance precision/recall, illustrating that signatures should
be evidence-driven, not guessed. **Know the limits:** it classifies *input
likelihood*, has false positives on benign inputs that happen to look like SQL, and
says nothing about exploitability — so it belongs *early* in a pipeline as a
high-speed filter feeding dynamic confirmation.

**Why it matters for WebHound:** these principles generalise to all signature-based
engines in WebHound (secrets, obfuscation, third-party-script heuristics): prefer
structural/contextual signals over brittle regex, derive thresholds from data, and
treat signature hits as triage that must be corroborated. They also frame the
static-vs-dynamic trade-off WADE must manage.

**Related:** [[libinjection-classification-model]], [[libinjection-parser-logic]], [[static-vs-dynamic-comparison]].
