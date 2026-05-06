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
            title="Large base64 blob in inline script",
            description=(
                f"An inline script contains a base64-encoded blob of {blob_len} "
                "characters. Large base64 strings in inline scripts often carry "
                "obfuscated payloads (shellcode, packed JavaScript, exfiltration data)."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            confidence=0.6,
            remediation=(
                "Investigate the source of the base64 string. "
                "Decode and review its content. Remove if unexpected or injected."
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
            title="Dense hex-escape encoding in inline script",
            description=(
                f"An inline script contains a run of {count} consecutive hex escape "
                "sequences (\\xNN). This encoding pattern is commonly used to "
                "obfuscate malicious strings and evade static keyword detection."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            confidence=0.65,
            remediation=(
                "Investigate the script for injected content. "
                "Decode the hex-encoded strings and review their purpose."
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
            title="JavaScript packer/obfuscator pattern detected",
            description=(
                "An inline script matches the signature of a JavaScript packer "
                "(e.g., Dean Edwards p,a,c,k,e,r). Packed scripts hide their true "
                "content until runtime, making static analysis difficult and "
                "indicating potential malicious obfuscation."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            confidence=0.8,
            remediation=(
                "Unpack and review the script content. "
                "Legitimate packed scripts can be replaced with minified originals. "
                "Remove if the source is unknown."
            ),
        )]

    # ------------------------------------------------------------------
    # Multiple eval() calls
    # ------------------------------------------------------------------

    def _check_multi_eval(self, content: str, url: str, idx: int) -> list[Finding]:
        matches = _EVAL_CALL.findall(content)
        count = len(matches)
        if count < 3:
            return []
        ev = _js_ev(f"{count} eval() calls in one script", url, idx)
        return [_finding(
            title=f"Multiple eval() calls detected ({count}×) in inline script",
            description=(
                f"An inline script contains {count} eval() calls. "
                "Multiple eval() invocations in a single script are a strong "
                "indicator of obfuscated or malicious code that executes "
                "dynamically constructed payloads."
            ),
            severity=Severity.HIGH,
            url=url,
            evidence=ev,
            confidence=0.75,
            remediation=(
                "Audit all eval() usage. Legitimate code rarely needs more than "
                "one eval(). Investigate for injected or obfuscated payloads."
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
            title=f"High-entropy inline script (entropy={entropy:.2f})",
            description=(
                f"An inline script has a Shannon entropy of {entropy:.2f} bits per "
                f"character, above the {_ENTROPY_THRESHOLD} threshold. "
                "Packed, compressed, or obfuscated code typically exhibits high "
                "character entropy that exceeds normal source code."
            ),
            severity=Severity.MEDIUM,
            url=url,
            evidence=ev,
            confidence=0.5,
            remediation=(
                "Review the script for packed or obfuscated content. "
                "High entropy alone is not conclusive — combine with other indicators."
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
