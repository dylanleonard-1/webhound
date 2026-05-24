# WebHound — scanner/webhound/engines/javascript/js_analyzer.py
# Passive pattern analysis of inline JavaScript content.
#
# Safe-mode: reads inline script content only.
# JavaScript is never executed, interpreted, or evaluated.
# External script content is not fetched.

from __future__ import annotations

import re
from typing import NamedTuple

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "js_analyzer"

# Maximum snippet length to include as evidence context.
_SNIPPET_LEN = 150


class _PatternDef(NamedTuple):
    name: str
    pattern: re.Pattern
    severity: Severity
    short_desc: str
    description: str
    remediation: str


_PATTERNS: list[_PatternDef] = [
    _PatternDef(
        "eval_call",
        re.compile(r"\beval\s*\("),
        Severity.LOW,
        "Script uses eval() to run code from strings",
        "An inline script calls `eval()`. eval() runs whatever string you give it as "
        "JavaScript code. If even one of those strings can be influenced by user input "
        "(a URL parameter, a cookie, a form field), it becomes a way to inject code "
        "into your page.",
        "Replace eval() with safer alternatives: `JSON.parse()` for parsing data, "
        "or explicit function definitions for everything else. Most modern code has "
        "no legitimate need for eval().",
    ),
    _PatternDef(
        "new_function",
        re.compile(r"\bnew\s+Function\s*\("),
        Severity.MEDIUM,
        "Script builds functions from strings at runtime",
        "An inline script uses the `new Function(...)` constructor, which compiles "
        "JavaScript from a string at runtime — same security risk as eval(). If the "
        "string contains anything from user input, an attacker can inject code.",
        "Use ordinary function declarations or arrow functions. There's almost never "
        "a legitimate reason to build a function body from a string in production code.",
    ),
    _PatternDef(
        "document_write",
        re.compile(r"\bdocument\s*\.\s*write\s*\("),
        Severity.LOW,
        "Script uses the deprecated document.write()",
        "An inline script calls `document.write()`. Browsers have effectively "
        "deprecated this API — it can rewrite arbitrary HTML into the page, which "
        "is a classic source of DOM-based XSS bugs.",
        "Replace with modern DOM APIs: `createElement()` + `appendChild()`, "
        "`textContent` for plain text, or template literals. Frameworks (React, "
        "Vue, etc.) handle this automatically.",
    ),
    _PatternDef(
        "innerhtml_assign",
        re.compile(r"\.innerHTML\s*="),
        Severity.LOW,
        "Script assigns HTML directly via innerHTML",
        "An inline script writes to `.innerHTML`. Anything assigned this way is "
        "parsed as HTML — including any `<script>` tags or event handlers. If the "
        "value comes from user input, that's a textbook cross-site scripting bug.",
        "Use `.textContent` for plain text (never interprets HTML). If you need to "
        "render user-supplied HTML, sanitize with DOMPurify first: "
        "`el.innerHTML = DOMPurify.sanitize(userInput)`.",
    ),
    _PatternDef(
        "atob_call",
        re.compile(r"\batob\s*\("),
        Severity.LOW,
        "Script decodes base64 (atob)",
        "An inline script calls `atob()`, which decodes base64 strings. Used "
        "legitimately (e.g., for source maps, data URLs). It's flagged here only "
        "because it's also one of the building blocks attackers use to hide "
        "payloads from static scanners.",
        "If this is your own code, no action needed. If you don't recognise this "
        "script and it also matches the obfuscation patterns (eval, fromCharCode), "
        "investigate as a possible injection.",
    ),
    _PatternDef(
        "from_char_code",
        re.compile(r"\bfromCharCode\s*\("),
        Severity.LOW,
        "Script builds strings from character codes",
        "An inline script uses `String.fromCharCode(...)`, which assembles strings "
        "from numeric codes. Legitimate uses are rare in modern code; this is more "
        "commonly seen in obfuscated payloads that hide URLs or keywords from "
        "static analysis.",
        "If this is your own minified code, no action needed. If unrecognised, "
        "decode the surrounding numeric arrays to see what strings are being built.",
    ),
    _PatternDef(
        "unescape_call",
        re.compile(r"\bunescape\s*\("),
        Severity.LOW,
        "Script uses the deprecated unescape()",
        "An inline script calls `unescape()`, which was deprecated in JavaScript a "
        "long time ago. It's still seen in obfuscated code that decodes "
        "percent-encoded payloads.",
        "Replace with `decodeURIComponent()`. If you didn't write this script, "
        "treat it as suspicious.",
    ),
    _PatternDef(
        "cookie_access",
        re.compile(r"\bdocument\s*\.\s*cookie\b"),
        Severity.LOW,
        "Script reads or writes document.cookie",
        "An inline script accesses `document.cookie`. In a legitimate app this is "
        "usually fine, but if an attacker can inject script onto the page (XSS), "
        "this is how session cookies get stolen. Cookies marked HttpOnly are "
        "invisible to JavaScript, which closes this door.",
        "Mark session cookies as `HttpOnly` so JavaScript can't read them. If you "
        "need a cookie value in JavaScript, store the non-sensitive part separately "
        "from the session cookie.",
    ),
    _PatternDef(
        "local_storage",
        re.compile(r"\blocalStorage\b"),
        Severity.INFO,
        "Script uses localStorage",
        "An inline script accesses `localStorage`. Anything stored there is "
        "visible to every script on the page (including malicious ones if XSS "
        "happens) and persists across browser sessions.",
        "Don't store session tokens, API keys, or personal data in localStorage. "
        "Use HttpOnly cookies for authentication and keep PII server-side.",
    ),
    _PatternDef(
        "session_storage",
        re.compile(r"\bsessionStorage\b"),
        Severity.INFO,
        "Script uses sessionStorage",
        "An inline script accesses `sessionStorage`. Same XSS exposure as "
        "localStorage but scoped to the current tab.",
        "Same rule as localStorage: no tokens, keys, or PII.",
    ),
    _PatternDef(
        "location_redirect",
        re.compile(r"\b(?:window\.)?location(?:\.href)?\s*=\s*"),
        Severity.LOW,
        "Script does a JavaScript-based redirect",
        "An inline script assigns to `window.location` or `location.href` to "
        "redirect the browser. If the destination URL is built from a URL "
        "parameter, hash, or other user-controllable input, attackers can "
        "redirect your visitors to phishing pages.",
        "Validate redirect destinations against an allowlist of known-safe URLs. "
        "Never build a redirect URL by concatenating user input.",
    ),
    _PatternDef(
        "form_action_manip",
        # Require the property owner to look form-related: an identifier that
        # contains 'form' (case-insensitive) anywhere, a `forms[...]` index, or
        # a standard DOM getter. The previous bare `\.action\s*=\s*` produced
        # false positives on unrelated objects (reducer.action, myObj.action) —
        # especially Redux-style code where `.action` is an everyday property.
        re.compile(
            r"(?:"
            r"\b\w*[Ff]orm\w*"                                 # *form*-named var
            r"|\bforms\[[^\]]+\]"                              # document.forms[..]
            r"|\bgetElementById\([^)]+\)"                      # DOM lookup
            r"|\bquerySelector\([^)]+\)"                       # DOM lookup
            r")(?:\s*\.\s*\w+)*\.action\s*="
        ),
        Severity.MEDIUM,
        "Script changes a form's submit destination at runtime",
        "An inline script reassigns a form's `.action` attribute — the URL the "
        "form posts to. If the new value comes from user input, an attacker can "
        "redirect form submissions (including passwords, payment data) to a server "
        "they control.",
        "Don't compute form action URLs from user input. If the destination needs "
        "to vary, pick from a server-side allowlist keyed by an opaque token.",
    ),
    # ── Client-side risk patterns added in commit 2/4 ─────────────────────────
    _PatternDef(
        "settimeout_string",
        # setTimeout / setInterval where the first argument is a string literal
        # (so the runtime will eval() it). Detects both single and double quotes.
        re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]"),
        Severity.MEDIUM,
        "Script schedules a string as code (setTimeout/setInterval with string arg)",
        "An inline script passes a string as the first argument to `setTimeout` "
        "or `setInterval`. Browsers run that string through eval() at the "
        "scheduled time — same code-injection risk as eval() itself. If any part "
        "of the string is built from user input, an attacker can run JavaScript.",
        "Always pass a function reference, never a string:\n"
        "  setTimeout(() => doThing(), 1000)   // safe\n"
        "  setTimeout('doThing()', 1000)        // unsafe\n"
        "If you genuinely need to schedule code built from input, you're "
        "almost certainly designing the wrong abstraction.",
    ),
    _PatternDef(
        "dom_xss_sink_hash",
        # location.hash flowing into a DOM sink. Heuristic: location.hash referenced
        # within ~120 chars of innerHTML/document.write — likely a sink/source pair.
        re.compile(
            r"\.hash\b[^\n]{0,120}?\b(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML)\b"
            r"|\b(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML)\b[^\n]{0,120}?\.hash\b"
        ),
        Severity.HIGH,
        "Script writes the URL hash directly into the page (DOM XSS)",
        "An inline script reads `location.hash` (the `#...` part of the URL) and "
        "writes it into the page using innerHTML or document.write. Anyone can "
        "craft a URL whose hash contains a `<script>` tag — when a victim "
        "clicks the link, the script runs on your domain. This is the canonical "
        "DOM-based XSS pattern.",
        "Treat `location.hash` (and `location.search`, `document.referrer`, "
        "`postMessage` data) as untrusted input. Render via `.textContent`, or "
        "sanitize HTML through DOMPurify before assigning to innerHTML.",
    ),
    _PatternDef(
        "proto_pollution",
        # Direct assignment to __proto__, Object.assign over user-controlled
        # source, or use of Object.prototype as a target.
        re.compile(
            r"\b__proto__\s*\["
            r"|\b__proto__\s*\.\s*\w+\s*="
            r"|\bObject\.prototype\s*\["
        ),
        Severity.MEDIUM,
        "Script touches __proto__ or Object.prototype",
        "An inline script writes to `__proto__` or `Object.prototype`. If the "
        "value or key comes from user input (e.g., merging an untrusted JSON "
        "object into a config), it's a prototype pollution vulnerability — the "
        "attacker can add or change properties on every object in the page.",
        "Don't assign to `__proto__` or `Object.prototype`. When merging "
        "objects with user data, use a hardened merge (lodash.merge >=4.17.21, "
        "or `Object.create(null)` for plain dicts).",
    ),
    _PatternDef(
        "source_map_url",
        # //# sourceMappingURL=... — common, but in production a publicly-readable
        # source map is a meaningful leak (original source, sometimes secrets).
        re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*\S+", re.I),
        Severity.LOW,
        "Inline script links to a source map",
        "An inline script has a `sourceMappingURL` comment pointing at a `.map` "
        "file. If that file is publicly readable, anyone can download the "
        "original (un-minified) source code — including any comments, internal "
        "API URLs, and sometimes credentials checked in by accident.",
        "On production builds, strip `sourceMappingURL` from the deployed "
        "bundles OR make sure the `.map` files aren't served publicly (deny "
        "them in nginx / your CDN). Most build tools have a `sourcemap: 'hidden'` "
        "option for this.",
    ),
]


# Per-pattern base confidence — patterns that commonly appear in legitimate
# platform-generated scripts get a lower starting confidence.
_PATTERN_CONFIDENCE: dict[str, float] = {
    "eval_call": 0.65,
    "new_function": 0.70,
    "document_write": 0.65,
    "innerhtml_assign": 0.60,
    "atob_call": 0.45,         # Very common in minified/platform code
    "from_char_code": 0.55,
    "unescape_call": 0.60,
    "cookie_access": 0.60,
    "local_storage": 0.40,     # Ubiquitous in SPAs, not itself a vulnerability
    "session_storage": 0.40,
    "location_redirect": 0.55,
    "form_action_manip": 0.65,
    # New patterns from commit 2/4
    "settimeout_string": 0.85,     # very rare in legit code
    "dom_xss_sink_hash": 0.7,      # heuristic source-near-sink
    "proto_pollution": 0.8,        # __proto__ assignment is unambiguous
    "source_map_url": 0.95,        # syntactic match — only false-positive is intentional
}


class JsAnalyzerEngine:
    """Passive pattern analysis of inline JavaScript content.

    Call ``analyze(artifacts)`` to receive a list of security findings.
    Only inline script content is analyzed — external script bodies are not fetched.
    Safe-mode: no code execution.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        if not artifacts.inline_scripts:
            return []

        findings: list[Finding] = []
        # Deduplicate: at most one finding per (pattern, script) pair.
        seen: set[tuple[str, int]] = set()

        for idx, content in enumerate(artifacts.inline_scripts):
            for pat in _PATTERNS:
                key = (pat.name, idx)
                if key in seen:
                    continue
                m = pat.pattern.search(content)
                if not m:
                    continue
                seen.add(key)
                snippet = _extract_snippet(content, m)
                ev = Evidence(
                    evidence_type=EvidenceType.JAVASCRIPT,
                    content=snippet,
                    location=artifacts.url,
                    source_engine=_ENGINE,
                    extra={"pattern": pat.name, "script_index": idx},
                )
                confidence = _PATTERN_CONFIDENCE.get(pat.name, 0.65)
                findings.append(Finding(
                    title=pat.short_desc,
                    description=pat.description,
                    severity=pat.severity,
                    category=FindingCategory.JAVASCRIPT,
                    evidence=[ev],
                    confidence=confidence,
                    remediation=pat.remediation,
                    framework=FrameworkAlignment(
                        owasp_top10=["A03:2021"],
                        cwe_ids=["CWE-79"],
                        nist_controls=["SI-10"],
                    ),
                    scanner_engine=_ENGINE,
                    metadata={"url": artifacts.url},
                ))

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_snippet(content: str, match: re.Match) -> str:
    """Return a short context window around the regex match."""
    half = _SNIPPET_LEN // 2
    start = max(0, match.start() - half)
    end = min(len(content), match.end() + half)
    snippet = content[start:end].strip()
    if start > 0:
        snippet = "…" + snippet
    if end < len(content):
        snippet = snippet + "…"
    return snippet
