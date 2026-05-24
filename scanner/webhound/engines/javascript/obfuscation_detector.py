# WebHound — scanner/webhound/engines/javascript/obfuscation_detector.py
# Passive detection of obfuscated or packed inline JavaScript.
#
# Safe-mode: reads inline script content only.
# JavaScript is never executed, evaluated, or interpreted.
# Applies heuristic checks — low-confidence; designed to surface suspicious patterns.

from __future__ import annotations

import math
import re
from collections import Counter

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "obfuscation_detector"

# A sequence of 80+ consecutive valid base64 characters is likely a payload blob.
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

# Eight or more consecutive hex escape sequences: \x41\x42...
_HEX_ESCAPE_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")

# Dean Edwards / generic packer pattern.
_PACKER_PATTERN = re.compile(
    r"\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e",
    re.I,
)

# Three or more eval() calls in one script is strongly suspicious.
_EVAL_CALL = re.compile(r"\beval\s*\(")

# Threshold: scripts longer than this are eligible for entropy analysis.
_ENTROPY_MIN_LEN = 500
_ENTROPY_THRESHOLD = 5.5


class ObfuscationDetectorEngine:
    """Heuristic detection of obfuscated or packed inline JavaScript.

    Call ``analyze(artifacts)`` to receive a list of findings.
    Confidence is set to 0.6 — these are indicators, not confirmed malice.
    Safe-mode: no code execution.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        if not artifacts.inline_scripts:
            return []

        findings: list[Finding] = []
        for idx, content in enumerate(artifacts.inline_scripts):
            findings.extend(self._check_base64_blob(content, artifacts.url, idx))
            findings.extend(self._check_hex_escape_run(content, artifacts.url, idx))
            findings.extend(self._check_packer(content, artifacts.url, idx))
            findings.extend(self._check_multi_eval(content, artifacts.url, idx))
            findings.extend(self._check_high_entropy(content, artifacts.url, idx))

        return findings

    # ------------------------------------------------------------------
    # Large base64 blob
    # ------------------------------------------------------------------

    def _check_base64_blob(
        self, content: str, url: str, idx: int
    ) -> list[Finding]:
        m = _BASE64_BLOB.search(content)
        if not m:
            return []
        blob_len = len(m.group())
        ev = _js_ev(f"Base64 blob ({blob_len} chars): {m.group()[:60]}…", url, idx)
        return [_finding(
            title="Large base64 chunk inside an inline script",
            description=(
                f"An inline script contains a {blob_len}-character base64 blob. "
                "Legitimate uses exist (inlined images, source maps), but blobs "
                "this size are also the way attackers hide malicious payloads "
                "from scanners — the suspect string is encoded so static checks "
                "can't see what it actually does."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            confidence=0.6,
            remediation=(
                "Trace where this script came from. If it's your own bundle, "
                "no action needed — the blob is likely an inlined font / image / "
                "source map. If you don't recognise it, decode the base64 to see "
                "what's inside before deciding whether to keep it."
            ),
        )]

    # ------------------------------------------------------------------
    # Dense hex-escape sequences
    # ------------------------------------------------------------------

    def _check_hex_escape_run(
        self, content: str, url: str, idx: int
    ) -> list[Finding]:
        m = _HEX_ESCAPE_RUN.search(content)
        if not m:
            return []
        run = m.group()
        count = run.count("\\x")
        ev = _js_ev(f"{count} consecutive hex escapes: {run[:60]}…", url, idx)
        return [_finding(
            title="Run of hex-escaped characters in inline script",
            description=(
                f"An inline script contains a run of {count} consecutive `\\xNN` "
                "hex escape sequences. This pattern is used to disguise strings "
                "(URLs, function names, payload commands) so that simple keyword "
                "search and AV signatures don't match. Modern minifiers don't "
                "usually emit this — when you see it, suspect injected code."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            confidence=0.65,
            remediation=(
                "Decode the hex run to see what it spells. If it's an unfamiliar "
                "URL, keyword, or shellcode-like sequence, treat the script as a "
                "compromise indicator and remove it."
            ),
        )]

    # ------------------------------------------------------------------
    # Known packer patterns
    # ------------------------------------------------------------------

    def _check_packer(self, content: str, url: str, idx: int) -> list[Finding]:
        m = _PACKER_PATTERN.search(content)
        if not m:
            return []
        snippet = content[m.start():min(len(content), m.start() + 80)]
        ev = _js_ev(f"Packer pattern: {snippet}…", url, idx)
        return [_finding(
            title="Inline script is packed by a known JavaScript packer",
            description=(
                "An inline script matches the signature of the Dean Edwards / "
                "p,a,c,k,e,r obfuscator. Packers hide a script's real contents "
                "behind an unpacker function that runs at page load. Modern build "
                "tools don't use this — when you see it on a production site, "
                "it's almost always either a long-dead third-party library or "
                "injected malware."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            confidence=0.8,
            remediation=(
                "Identify what's actually in the script. Online unpackers like "
                "beautifier.io can reverse the obfuscation. If you don't recognise "
                "the unpacked content, remove the script — it's likely injected."
            ),
        )]

    # ------------------------------------------------------------------
    # Multiple eval() calls
    # ------------------------------------------------------------------

    def _check_multi_eval(self, content: str, url: str, idx: int) -> list[Finding]:
        matches = _EVAL_CALL.findall(content)
        count = len(matches)
        # Threshold bumped from 3 to 5 — legacy frameworks (some older
        # jQuery plugins, AMD shims) legitimately call eval a few times
        # for module loading. Five or more in one inline script is
        # genuinely unusual.
        if count < 5:
            return []
        ev = _js_ev(f"{count} eval() calls in one script", url, idx)
        return [_finding(
            title=f"Inline script calls eval() {count} times",
            description=(
                f"An inline script contains {count} separate `eval()` calls. "
                "One or two eval() calls can be a code smell; this many is "
                "almost always either a packer's runtime unpacker or "
                "deliberately obfuscated malicious code that builds and runs "
                "its payload in pieces."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            confidence=0.75,
            remediation=(
                "Identify what each eval() is doing. If this is a third-party "
                "library you can't audit, replace it with a maintained "
                "alternative. If you don't recognise the script at all, "
                "treat it as a compromise indicator."
            ),
        )]

    # ------------------------------------------------------------------
    # High entropy
    # ------------------------------------------------------------------

    def _check_high_entropy(self, content: str, url: str, idx: int) -> list[Finding]:
        if len(content) < _ENTROPY_MIN_LEN:
            return []
        entropy = _shannon_entropy(content)
        if entropy <= _ENTROPY_THRESHOLD:
            return []
        ev = _js_ev(
            f"Script entropy: {entropy:.2f} bits/char (threshold: {_ENTROPY_THRESHOLD})",
            url,
            idx,
        )
        return [_finding(
            title="Inline script has unusually random-looking content",
            description=(
                f"An inline script has a Shannon entropy of {entropy:.2f} bits per "
                f"character — above the {_ENTROPY_THRESHOLD} threshold. Modern "
                "minifiers (Webpack, esbuild, Terser) can produce code that "
                "approaches this, so the signal alone is weak. Combined with "
                "any of the other obfuscation findings on the same script, it "
                "becomes a stronger indicator of injected or packed code."
            ),
            severity=Severity.LOW,
            url=url,
            evidence=ev,
            confidence=0.45,
            remediation=(
                "If this script is a known minified bundle from your build "
                "pipeline, no action needed. Otherwise check what other findings "
                "exist on the same script — high entropy plus eval / base64 / "
                "packer patterns together is the real signal."
            ),
        )]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _shannon_entropy(text: str) -> float:
    """Compute the Shannon entropy of *text* in bits per character."""
    if not text:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _js_ev(content: str, url: str, script_index: int) -> Evidence:
    return Evidence(
        evidence_type=EvidenceType.JAVASCRIPT,
        content=content,
        location=url,
        source_engine=_ENGINE,
        extra={"script_index": script_index},
    )


def _finding(
    title: str,
    description: str,
    severity: Severity,
    url: str,
    evidence: Evidence,
    confidence: float = 0.6,
    remediation: str | None = None,
) -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=FindingCategory.JAVASCRIPT,
        evidence=[evidence],
        confidence=confidence,
        remediation=remediation,
        framework=FrameworkAlignment(
            owasp_top10=["A03:2021"],
            cwe_ids=["CWE-116"],
            nist_controls=["SI-10"],
        ),
        scanner_engine=_ENGINE,
        metadata={"url": url},
    )
