# libinjection — Classification Model

**Tool:** libinjection · **Concept:** SQLi/XSS classification

libinjection reduces "is this string an injection attempt?" to **fingerprint
classification**. After tokenising, the input is normalised into a short fingerprint
string; the library ships a hand-curated allow/deny set of fingerprints empirically
derived from huge corpora of real attacks and benign inputs. A match means "this
parses like an injection." For XSS it similarly looks for HTML/JS constructs that
indicate markup injection. The model is deliberately **binary and high-precision**:
it answers *attack-like / not attack-like*, optimised to minimise false positives on
ordinary user input (which is why WAFs like ModSecurity adopted it).

**Why it matters for WebHound:** this is a clean example of separating
**classification (attack-like input) from confirmation (a real vulnerability)**.
libinjection flags suspicious *input*; it does **not** prove the app is exploitable —
that still needs dynamic proof. WADE should treat such signature classifications as a
*confidence input/triage signal*, not a standalone finding, and combine them with
dynamic verification before reporting.

**Related:** [[libinjection-parser-logic]], [[libinjection-detection-theory]], [[static-vs-dynamic-comparison]].
