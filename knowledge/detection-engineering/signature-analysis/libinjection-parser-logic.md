# libinjection — Parser Logic

**Tool:** libinjection · **Type:** classification library · **Concept:** parser/tokeniser logic

libinjection detects SQLi (and XSS) not by regex blacklists but by a tiny
**SQL tokeniser**. It lexes an input string into a sequence of token types — keyword,
operator, string/quote, number, comment, variable, function — folds that sequence
into a compact **fingerprint** (e.g. `s&1` = string, AND, number), and looks the
fingerprint up in a curated set of fingerprints known to indicate injection. Because
it models how a SQL parser would actually see the input, it is fast (no
backtracking) and resists the trivial evasions that defeat regex (comments,
whitespace, case, encoding).

**Why it matters for WebHound:** libinjection is the reference for **structure-based
(not pattern-based) signature detection**. It is a cheap *pre-filter*: run it on
URL/form inputs to cheaply flag likely SQLi/XSS candidates before expensive dynamic
testing. Its tokenise→fingerprint→classify approach is more robust than regex and is
a model for any low-cost first-pass detector in WebHound.

**Related:** [[libinjection-classification-model]], [[libinjection-detection-theory]], [[sqlmap-detection-overview]].
