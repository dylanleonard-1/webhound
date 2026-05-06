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
        "eval() call detected",
        "eval() executes arbitrary string content as JavaScript code. "
        "If attacker-controlled input reaches eval(), it enables XSS or remote code execution.",
        "Avoid eval(). Use JSON.parse() for data, or refactor to static function definitions.",
    ),
    _PatternDef(
        "new_function",
        re.compile(r"\bnew\s+Function\s*\("),
        Severity.MEDIUM,
        "new Function() constructor detected",
        "new Function() constructs and executes code from strings, equivalent to eval(). "
        "Attacker-controlled input reaching this pattern enables code injection.",
        "Replace with static function definitions. Avoid runtime code construction.",
    ),
    _PatternDef(
        "document_write",
        re.compile(r"\bdocument\s*\.\s*write\s*\("),
        Severity.LOW,
        "document.write() call detected",
        "document.write() is deprecated and can cause DOM-based XSS if user-supplied "
        "content is passed without sanitization.",
        "Use DOM APIs (createElement, textContent) instead of document.write().",
    ),
    _PatternDef(
        "innerhtml_assign",
        re.compile(r"\.innerHTML\s*="),
        Severity.LOW,
        "innerHTML assignment detected",
        "Assignment to innerHTML renders HTML and can cause XSS if the value "
        "originates from attacker-controllable input.",
        "Use textContent for plain text. Sanitize HTML with DOMPurify before "
        "assigning to innerHTML.",
    ),
    _PatternDef(
        "atob_call",
        re.compile(r"\batob\s*\("),
        Severity.LOW,
        "atob() base64 decode detected",
        "atob() decodes base64-encoded data. Used legitimately, but commonly present "
        "in obfuscated malicious scripts to hide payloads.",
        "Review whether base64 decoding is necessary here. "
        "Investigate if combined with eval() or dynamic code execution.",
    ),
    _PatternDef(
        "from_char_code",
        re.compile(r"\bfromCharCode\s*\("),
        Severity.LOW,
        "String.fromCharCode() detected",
        "fromCharCode() converts character codes to strings. Frequently used in "
        "obfuscated scripts to encode malicious payloads and evade static detection.",
        "Review scripts using fromCharCode for obfuscation indicators. "
        "Investigate if combined with eval() or atob().",
    ),
    _PatternDef(
        "unescape_call",
        re.compile(r"\bunescape\s*\("),
        Severity.LOW,
        "unescape() call detected",
        "unescape() is deprecated and commonly used in obfuscated scripts to decode "
        "percent-encoded payloads.",
        "Replace with decodeURIComponent(). Investigate scripts using unescape() "
        "for obfuscation patterns.",
    ),
    _PatternDef(
        "cookie_access",
        re.compile(r"\bdocument\s*\.\s*cookie\b"),
        Severity.LOW,
        "document.cookie access detected",
        "Script reads or writes document.cookie. In a malicious script this may "
        "indicate cookie exfiltration. Cookies should be HttpOnly where possible.",
        "Mark session cookies as HttpOnly to prevent JavaScript access. "
        "Review whether client-side cookie access is required here.",
    ),
    _PatternDef(
        "local_storage",
        re.compile(r"\blocalStorage\b"),
        Severity.INFO,
        "localStorage access detected",
        "Script accesses localStorage. Sensitive data (tokens, PII) stored in "
        "localStorage is accessible to any script on the page and persists across sessions.",
        "Avoid storing session tokens or sensitive PII in localStorage. "
        "Use HttpOnly cookies for authentication tokens.",
    ),
    _PatternDef(
        "session_storage",
        re.compile(r"\bsessionStorage\b"),
        Severity.INFO,
        "sessionStorage access detected",
        "Script accesses sessionStorage. Sensitive data stored here is accessible "
        "to any script on the page for the duration of the session.",
        "Avoid storing session tokens or sensitive PII in sessionStorage.",
    ),
    _PatternDef(
        "location_redirect",
        re.compile(r"\b(?:window\.)?location(?:\.href)?\s*=\s*"),
        Severity.LOW,
        "Dynamic redirect via location assignment",
        "Script assigns to window.location or location.href, performing a redirect. "
        "If the target URL is derived from attacker-controllable input, open redirect "
        "or DOM-based XSS may be possible.",
        "Validate redirect targets against an allowlist. "
        "Never build redirect URLs from unvalidated user input.",
    ),
    _PatternDef(
        "form_action_manip",
        re.compile(r"\.action\s*=\s*"),
        Severity.MEDIUM,
        "Dynamic form.action manipulation detected",
        "Script dynamically sets a form's action attribute. If the target URL is "
        "attacker-controllable, form submissions could be redirected to a malicious endpoint.",
        "Validate form action targets. Avoid setting form.action from user-supplied input.",
    ),
]


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
                findings.append(Finding(
                    title=pat.short_desc,
                    description=pat.description,
                    severity=pat.severity,
                    category=FindingCategory.JAVASCRIPT,
                    evidence=[ev],
                    confidence=0.7,
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
