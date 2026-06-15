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
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "obfuscation_detector"

# Enterprise metadata per check. Obfuscation findings are compromise
# indicators rather than vulnerabilities, so they cluster around CWE-506
# (embedded malicious code) and OWASP A03 / A08.
_FA: dict[str, FrameworkAlignment] = {
    "base64_blob": FrameworkAlignment(
        owasp_top10=["A03:2021"], cwe_ids=["CWE-506", "CWE-116"], nist_controls=["SI-10", "SI-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=3.7,
        iso_27001=["A.8.28"], soc2=["CC7.1"],
        exploitability=Exploitability.THEORETICAL,
    ),
    "hex_escape_run": FrameworkAlignment(
        owasp_top10=["A03:2021"], cwe_ids=["CWE-506"], nist_controls=["SI-10", "SI-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=3.7,
        iso_27001=["A.8.28"], soc2=["CC7.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "packer": FrameworkAlignment(
        owasp_top10=["A03:2021", "A08:2021"], cwe_ids=["CWE-506", "CWE-829"], nist_controls=["SI-10", "SI-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N", cvss_score=7.1,
        pci_dss=["11.5.1"], iso_27001=["A.8.28"], soc2=["CC7.1"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "multi_eval": FrameworkAlignment(
        owasp_top10=["A03:2021"], cwe_ids=["CWE-95", "CWE-506"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", cvss_score=5.4,
        iso_27001=["A.8.28"], soc2=["CC7.1"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "high_entropy": FrameworkAlignment(
        owasp_top10=["A03:2021"], cwe_ids=["CWE-506"], nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", cvss_score=2.6,
        iso_27001=["A.8.28"],
        exploitability=Exploitability.THEORETICAL,
    ),
}

# A sequence of 80+ consecutive valid base64 characters is likely a payload blob.
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")

# Eight or more consecutive hex escape sequences: \x41\x42...
_HEX_ESCAPE_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")

# Dean Edwards / generic packer pattern.
_PACKER_PATTERN = re.compile(
    r"\beval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e",
    re.I,
)

# FP guard for packer: a genuine packed payload has a pipe-encoded token list
# (the dictionary of obfuscated identifiers) as a string argument. Bare packer
# function *definitions* embedded in utility libraries match _PACKER_PATTERN but
# have no encoded payload. We require ≥5 pipe separators in a quoted string
# within 2000 chars of the packer signature before calling it a real pack.
_PACKER_PAYLOAD_RE = re.compile(
    r"""["'][^"']{3,}(?:\|[^"']{0,50}){5,}["']""",
)

# Three or more eval() calls in one script is strongly suspicious.
_EVAL_CALL = re.compile(r"\beval\s*\(")

# Dynamic code construction via the Function() constructor — same blast
# radius as eval but skips simple eval()-keyword scans.
_FUNCTION_CTOR = re.compile(r"\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"]")

# Decoder loops + base64 helpers. atob() on its own is normal; combined
# with a base64 blob it's the standard "decode-and-execute" pattern.
_DECODER_PATTERN = re.compile(
    r"\batob\s*\(|"
    r"\bString\.fromCharCode\s*\(|"
    r"\bdecodeURIComponent\s*\(\s*['\"]%[0-9a-fA-F]"
)

# Network-call patterns the encoded payload would use to exfiltrate / fetch
# a second stage.
_NET_CALL = re.compile(
    r"\b(?:fetch|XMLHttpRequest|navigator\.sendBeacon)\s*\(|"
    r"new\s+WebSocket\s*\("
)

# Credential / secret-shaped tokens. Catching these inline next to a blob
# is the difference between "minified framework" and "exfiltration code".
_SECRET_PATTERN = re.compile(
    r"\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token|"
    r"password|client[_-]?secret|aws_access|stripe_sk_)\b",
    re.I,
)

# Threshold: scripts longer than this are eligible for entropy analysis.
_ENTROPY_MIN_LEN = 500
# Raised 5.5 -> 5.8 (audit #5): modern minifiers (Webpack/esbuild/Terser) routinely reach
# ~5.5 bits/char, so 5.5 fired on benign minified bundles. 5.8 keeps the signal for
# genuinely packed/random content while dropping ordinary minified code.
_ENTROPY_THRESHOLD = 5.8

# Markers of a framework/bundler-generated script (Next.js RSC, webpack, SystemJS …) —
# high entropy on these is EXPECTED and benign, so they're excluded from the standalone
# entropy finding (the strong base64/eval/packer checks still run, and correlation still
# combines real signals). This is the lone-entropy-on-a-minified-bundle FP from the audit.
_MINIFIED_MARKERS = re.compile(
    r"webpackChunk|__webpack_require__|self\.__next_f|self\.webpackJsonp|__NEXT_DATA__|"
    r"System\.register|\(self\.__next|\b__turbopack|\bparcelRequire\b",
    re.I,
)


def _looks_like_minified_bundle(content: str) -> bool:
    """True if the inline script is a framework/bundler artifact (Next.js RSC, webpack,
    …) or a giant single-line minified blob — where high entropy is normal, not malicious."""
    if _MINIFIED_MARKERS.search(content[:4000]):
        return True
    # A long script with almost no newlines is minified output (one giant statement).
    newlines = content.count("\n")
    if len(content) >= 2000 and (len(content) / (newlines + 1)) >= 500:
        return True
    return False


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
        """Base64 blobs are a weak standalone signal. We only escalate to
        MEDIUM if the same script *also* contains something suspicious
        nearby — eval, Function(), atob/decode loops, hidden network calls,
        or credential-like patterns. Otherwise the finding is LOW + low
        confidence and tagged as a heuristic so the dashboard doesn't pull
        framework bundles + source maps into Fix-First."""
        m = _BASE64_BLOB.search(content)
        if not m:
            return []
        blob_len = len(m.group())

        # Look for corroborating malicious-pattern signals in the same script.
        has_eval = bool(_EVAL_CALL.search(content) or _FUNCTION_CTOR.search(content))
        has_decoder = bool(_DECODER_PATTERN.search(content))
        has_net = bool(_NET_CALL.search(content))
        has_secret = bool(_SECRET_PATTERN.search(content))
        strong_signals = sum([has_eval, has_decoder, has_net, has_secret])

        # Accuracy policy: base64 is a *weak signal alone* — unless combined
        # with eval/Function/decoder/network/credential patterns, in which
        # case it's the actual obfuscation tell. Two+ corroborators → MEDIUM
        # confirmed. One corroborator → MEDIUM likely. Zero → LOW heuristic.
        if strong_signals >= 2:
            severity = Severity.MEDIUM
            confidence = 0.75
            tags = ["likely", "corroborated"]
            title = "Large base64 blob with multiple suspicious patterns"
            description = (
                f"An inline script contains a {blob_len}-char base64 blob "
                "**and** multiple suspicious supporting patterns "
                f"(eval={has_eval}, decoder={has_decoder}, "
                f"network={has_net}, secret-like={has_secret}). "
                "Converging signals are the real obfuscation tell."
            )
        elif strong_signals == 1:
            severity = Severity.MEDIUM
            confidence = 0.65
            tags = ["likely", "single_corroboration"]
            corroborator = next(
                name for name, hit in
                (("eval/Function call", has_eval),
                 ("base64 decoder pattern", has_decoder),
                 ("inline network call", has_net),
                 ("credential-like token", has_secret))
                if hit
            )
            title = "Inline script: base64 blob + suspicious pattern"
            description = (
                f"An inline script contains a {blob_len}-character base64 "
                f"blob alongside a {corroborator}. Either signal on its "
                "own is common in legitimate code, but together they're "
                "the prep work for decoded-and-executed payloads."
            )
        else:
            # Weak standalone signal — LOW + heuristic so framework bundles
            # + inlined fonts + source maps don't pollute Fix-First.
            severity = Severity.LOW
            confidence = 0.35
            tags = ["heuristic", "weak_signal"]
            title = "Inline script contains a large base64 chunk (heuristic)"
            description = (
                f"An inline script contains a {blob_len}-character base64 "
                "blob. On its own this is **not** evidence of obfuscation: "
                "inlined fonts, images, source maps, and framework bundles "
                "routinely embed base64. This finding only escalates when "
                "the same script also contains eval/Function calls, "
                "decoder loops, network calls, or credential-like strings."
            )

        ev = _js_ev(f"Base64 blob ({blob_len} chars): {m.group()[:60]}…\n"
                    f"corroborating signals: eval={has_eval}, "
                    f"decoder={has_decoder}, network={has_net}, "
                    f"secret-like={has_secret}",
                    url, idx)
        f = _finding(
            title=title, description=description, severity=severity,
            url=url, evidence=ev, confidence=confidence,
            remediation=(
                "If the script is from your build pipeline, no action needed "
                "— the blob is likely an inlined font/image/source map. "
                "Investigate only when the eval/decoder/network/secret "
                "co-signals fire."
            ),
            kind="base64_blob",
        )
        f.tags = tags
        return [f]

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
            kind="hex_escape_run",
        )]

    # ------------------------------------------------------------------
    # Known packer patterns
    # ------------------------------------------------------------------

    def _check_packer(self, content: str, url: str, idx: int) -> list[Finding]:
        m = _PACKER_PATTERN.search(content)
        if not m:
            return []
        # FP guard: a utility library may embed the packer *function template*
        # without any encoded payload. Genuine packed code always includes a
        # pipe-separated token string (the obfuscated identifier dictionary)
        # within the call. Without it we skip — this is the main source of
        # packer false-positives on minified bundles that embed legacy libraries.
        window = content[m.start(): min(len(content), m.start() + 2000)]
        if not _PACKER_PAYLOAD_RE.search(window):
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
            kind="packer",
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
            kind="multi_eval",
        )]

    # ------------------------------------------------------------------
    # High entropy
    # ------------------------------------------------------------------

    def _check_high_entropy(self, content: str, url: str, idx: int) -> list[Finding]:
        if len(content) < _ENTROPY_MIN_LEN:
            return []
        # Don't flag entropy on framework/bundler/minified scripts — that's the benign
        # FP (Next.js RSC, webpack chunks). The base64/eval/packer checks above still run.
        if _looks_like_minified_bundle(content):
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
            kind="high_entropy",
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
    kind: str = "high_entropy",
) -> Finding:
    return Finding(
        title=title,
        description=description,
        severity=severity,
        category=FindingCategory.JAVASCRIPT,
        evidence=[evidence],
        confidence=confidence,
        remediation=remediation,
        framework=_FA[kind],
        scanner_engine=_ENGINE,
        metadata={"url": url},
    )
