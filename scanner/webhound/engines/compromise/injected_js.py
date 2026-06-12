# WebHound — scanner/webhound/engines/compromise/injected_js.py
# Passive detection of injected/malicious JavaScript patterns.
#
# Safe-mode: reads pre-extracted PageArtifacts only. No JavaScript
# execution, no exploitation.

from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity

_ENGINE = "injected_js"

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_PAYMENT_TERMS = re.compile(
    r"\b(?:card_?number|cc_?num(?:ber)?|cvv|cvc2?|expir(?:y|ation)|"
    r"cardhold(?:er)?|pan\b|track_?data|payment_?data|"
    r"credit_?card|debit_?card)\b",
    re.I,
)

_SEND_TERMS = re.compile(
    r"\b(?:fetch\s*\(|XMLHttpRequest|sendBeacon\s*\(|"
    r"\.send\s*\(|\.post\s*\(|\.ajax\s*\()",
    re.I,
)

_DYNAMIC_SCRIPT_INJECT = re.compile(
    r"createElement\s*\(\s*['\"]script['\"]\s*\)",
    re.I,
)

_BEACON_PATTERNS = re.compile(
    r"new\s+Image\s*\(\s*\)\s*\.src\s*=|"
    r"navigator\.sendBeacon\s*\(|"
    r"\bXMLHttpRequest\b.*?\bsend\b",
    re.I,
)

_SKIMMER_KEYWORDS = re.compile(
    r"\b(?:formjack(?:ing)?|magecart|skimmer|keylog(?:ger)?|"
    r"exfiltrat(?:e|ion)|cc_?harvest|card_?steal|card_?grab)\b",
    re.I,
)

# Obfuscation indicators: `atob(<base64>)` or `eval(atob(…))` / `Function(atob(…))`.
_EVAL_DECODE = re.compile(
    r"(?:\beval\s*\(\s*atob\s*\(|"
    r"\bFunction\s*\(\s*atob\s*\(|"
    r"\bnew\s+Function\s*\(\s*atob\s*\(|"
    r"\b(?:eval|Function)\s*\(\s*decodeURIComponent\s*\(\s*escape)",
    re.I,
)

# `document.write` is itself fine, but combined with `<script` or external
# src= it's the classic injection pattern.
_DOCUMENT_WRITE_SCRIPT = re.compile(
    r"document\.write(?:ln)?\s*\(\s*['\"][^'\"]*<script",
    re.I,
)

# Large base64 blobs inside `atob('...')` — heuristic for packed malicious
# JS. We require ≥200 base64 chars to drop false positives on small icons /
# inline images.
_LARGE_ATOB_BLOB = re.compile(
    r"\batob\s*\(\s*['\"]([A-Za-z0-9+/=]{200,})['\"]",
)

# Inline event-handler attribute values that contain script-execution
# primitives are usually injected (the legitimate use is just a function
# call like `myHandler()`).
_EVENT_HANDLER_PAYLOAD = re.compile(
    r"\b(?:eval|Function|setTimeout|setInterval|atob|fetch|"
    r"document\.write|window\.location|location\.href)\b",
    re.I,
)

# A `javascript:` URL inside any href= / src= attribute value.
_JAVASCRIPT_URI = re.compile(r"^\s*javascript:", re.I)

# Framework DATA-TRANSPORT scripts serialize the page's own content (headings, copy)
# into <script> bodies — Next.js App-Router RSC/Flight (self.__next_f.push([...])),
# Pages-Router __NEXT_DATA__, Remix, SvelteKit, Nuxt, or a plain JSON island. The
# malware/skimmer signatures must NOT scan these: a security/educational page whose
# COPY says "exfiltration" lands here verbatim and is not executable attacker logic.
# We only scan actual executable JavaScript, per the cardinal rule.
_DATA_PAYLOAD_MARKERS = re.compile(
    r"self\.__next_f|__next_f\.push|__NEXT_DATA__|__remixContext|"
    r"__sveltekit_|window\.__NUXT__|__NUXT_DATA__",
    re.I,
)


def _is_data_payload_script(script: str) -> bool:
    """True if the inline script is a framework data-transport payload (serialized page
    content) rather than executable logic. Such scripts carry the page's own copy and
    must be excluded from malware-keyword/skimmer detection."""
    head = script[:2000]
    if _DATA_PAYLOAD_MARKERS.search(head):
        return True
    stripped = script.lstrip()
    if stripped[:1] in "{[":  # a JSON island (e.g. <script type=application/json>)
        try:
            json.loads(stripped)
            return True
        except (ValueError, TypeError):
            return False
    return False

_RISKY_TLDS = frozenset({
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "icu",
    "pw", "buzz", "live", "online", "site", "space", "work",
    "rest", "monster", "fit", "loan",
})


# ---------------------------------------------------------------------------
# FrameworkAlignment preset table
# ---------------------------------------------------------------------------

_FA: dict[str, FrameworkAlignment] = {
    "payment_skimmer": FrameworkAlignment(
        owasp_top10=["A08:2021", "A03:2021"],
        cwe_ids=["CWE-506", "CWE-494", "CWE-79"],
        nist_controls=["SI-3", "SI-7", "IR-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cvss_score=9.6,
        pci_dss=["6.4.3", "11.6.1", "12.10.1"],
        iso_27001=["A.8.7", "A.8.25", "A.8.28"],
        soc2=["CC7.1", "CC7.2"],
        hipaa=["164.308(a)(1)(ii)(D)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "dynamic_inject": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-494", "CWE-829"],
        nist_controls=["SI-3", "SI-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=8.0,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.25"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "beacon_exfil": FrameworkAlignment(
        owasp_top10=["A08:2021", "A02:2021"],
        cwe_ids=["CWE-200", "CWE-359"],
        nist_controls=["SI-3", "SI-12", "AU-9"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        cvss_score=8.2,
        pci_dss=["10.2.1", "11.6.1"],
        iso_27001=["A.8.16", "A.8.25"],
        soc2=["CC7.2"],
        hipaa=["164.312(b)"],
        exploitability=Exploitability.PRACTICAL,
    ),
    "skimmer_keyword": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-506"],
        nist_controls=["SI-3", "IR-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
        cvss_score=10.0,
        pci_dss=["6.4.3", "11.6.1", "12.10.1"],
        iso_27001=["A.8.7", "A.8.25"],
        soc2=["CC7.2", "CC7.3"],
        hipaa=["164.308(a)(6)"],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "obfuscation": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-506", "CWE-94"],
        nist_controls=["SI-3", "SI-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=8.0,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.7", "A.8.25"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "document_write_script": FrameworkAlignment(
        owasp_top10=["A08:2021", "A03:2021"],
        cwe_ids=["CWE-79", "CWE-494"],
        nist_controls=["SI-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=8.0,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.25"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "event_handler_payload": FrameworkAlignment(
        owasp_top10=["A03:2021", "A08:2021"],
        cwe_ids=["CWE-79", "CWE-94"],
        nist_controls=["SI-10", "SI-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        cvss_score=8.0,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "javascript_uri": FrameworkAlignment(
        owasp_top10=["A03:2021"],
        cwe_ids=["CWE-79"],
        nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
        cvss_score=5.4,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "risky_tld_script": FrameworkAlignment(
        owasp_top10=["A08:2021"],
        cwe_ids=["CWE-829"],
        nist_controls=["SI-3", "CM-7"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
        cvss_score=9.0,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.7", "A.8.25"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
}


class InjectedJsEngine:
    """Passive detection of injected/malicious JavaScript.

    Scans inline scripts AND HTML event-handler attribute values (onclick,
    onerror, onload, …) for skimmer signatures, obfuscation primitives,
    classic injection patterns (document.write of a script tag), large
    base64-encoded blobs decoded at runtime, javascript:-URLs in attribute
    values, and external script sources hosted on commonly-abused TLDs.
    All regex-only, no JavaScript executed.
    """

    NAME = _ENGINE

    def analyze(
        self,
        artifacts: PageArtifacts,
        html_body: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        scripts = artifacts.inline_scripts

        for idx, script in enumerate(scripts):
            if not script:
                continue
            # Skip framework data-transport scripts (RSC/Flight/__NEXT_DATA__/JSON
            # islands): they serialize the page's own copy, so scanning them for
            # skimmer/malware keywords flags educational/security page TEXT as malware.
            # Only executable logic is scanned.
            if _is_data_payload_script(script):
                continue
            findings.extend(self._check_payment_harvest(script, idx, artifacts))
            findings.extend(self._check_dynamic_inject(script, idx, artifacts))
            findings.extend(self._check_beacon_exfil(script, idx, artifacts))
            findings.extend(self._check_skimmer_keywords(script, idx, artifacts))
            findings.extend(self._check_eval_decode(script, idx, artifacts))
            findings.extend(self._check_document_write_script(script, idx, artifacts))
            findings.extend(self._check_large_atob_blob(script, idx, artifacts))

        findings.extend(self._check_event_handlers(artifacts))
        findings.extend(self._check_javascript_uris_in_handlers(artifacts))
        findings.extend(self._check_suspicious_external_scripts(artifacts))
        return findings

    # ------------------------------------------------------------------

    def _check_payment_harvest(self, script, idx, artifacts):
        if not (_PAYMENT_TERMS.search(script) and _SEND_TERMS.search(script)):
            return []
        snippet = _snippet(script)
        return [Finding(
            title="Payment-card skimmer pattern detected in inline script",
            description=(
                "An inline script references payment-card field names (card "
                "number, CVV, expiry) AND data-transmission primitives (fetch, "
                "XMLHttpRequest, navigator.sendBeacon) in the same body. "
                "That's the textbook fingerprint of a Magecart-style skimmer: "
                "code that reads the checkout form fields as the customer "
                "types and ships them to an attacker-controlled URL. The "
                "skimmer usually loads minutes-to-hours before the customer's "
                "card is charged for the first time."
            ),
            severity=Severity.CRITICAL,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=snippet,
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx},
            )],
            confidence=0.85,
            remediation=(
                "Treat this as an active incident: take the page out of "
                "rotation, snapshot the inline-scripts for forensics, and "
                "audit your CMS, server, and CDN for the injection vector. "
                "Most Magecart compromises arrive through a vulnerable plugin "
                "or a stolen admin credential. Long-term: lock down "
                "script-src in CSP, enable Subresource Integrity for every "
                "external script, and move card collection onto a hosted "
                "payment field (Stripe Elements / Adyen Drop-in) so the "
                "skimmer never sees raw card data even if it does run."
            ),
            framework=_FA["payment_skimmer"],
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx},
        )]

    def _check_dynamic_inject(self, script, idx, artifacts):
        if not _DYNAMIC_SCRIPT_INJECT.search(script):
            return []
        snippet = _snippet(script)
        return [Finding(
            title="Inline script dynamically creates a <script> element",
            description=(
                "The page contains JavaScript that calls "
                "`document.createElement('script')` and then sets the `src` "
                "property at runtime. This is a legitimate pattern for "
                "asynchronous tag loading (Google Analytics, ad networks) — "
                "but it's also how injected malware sidesteps a static CSP "
                "script-src whitelist: the destination URL is built up from "
                "string fragments only the JS engine ever sees in one piece."
            ),
            severity=Severity.MEDIUM,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=snippet,
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx},
            )],
            confidence=0.7,
            remediation=(
                "Trace what the dynamically-injected script's final URL "
                "resolves to. If it's a known vendor (analytics, ads, chat "
                "widget), add the vendor host to `script-src` in your CSP "
                "and use `<script src=… integrity=…>` for static loads. "
                "If you can't identify the destination, assume the script "
                "block was injected and audit the page template."
            ),
            framework=_FA["dynamic_inject"],
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx},
        )]

    def _check_beacon_exfil(self, script, idx, artifacts):
        if not _BEACON_PATTERNS.search(script):
            return []
        # If we already would fire payment_skimmer for this script, skip the
        # beacon finding — it'd be redundant and rank-noise.
        if _PAYMENT_TERMS.search(script):
            return []
        snippet = _snippet(script)
        return [Finding(
            title="Silent data-exfiltration beacon pattern in inline script",
            description=(
                "The inline script uses one of the three browser primitives "
                "that send data without rendering a visible response: "
                "`new Image().src = '…/log?data=' + …`, "
                "`navigator.sendBeacon(…)`, or `XMLHttpRequest.send(…)` with "
                "no UI-side response handler. All three are designed for "
                "fire-and-forget telemetry — which means they're also the "
                "preferred technique for skimmers and cookie stealers, since "
                "the user sees nothing and rate limiters log nothing distinct."
            ),
            severity=Severity.HIGH,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=snippet,
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx},
            )],
            confidence=0.65,
            remediation=(
                "Identify the destination URL the beacon writes to. If it's "
                "your own analytics, document that and consider tightening "
                "`connect-src` / `img-src` in your CSP to only the analytics "
                "host. If you can't account for it, treat the page as "
                "potentially compromised and audit recent template changes."
            ),
            framework=_FA["beacon_exfil"],
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx},
        )]

    def _check_skimmer_keywords(self, script, idx, artifacts):
        m = _SKIMMER_KEYWORDS.search(script)
        if not m:
            return []
        snippet = _snippet(script, around=m.start())
        return [Finding(
            title=f"Known skimmer/malware keyword in inline script: '{m.group()}'",
            description=(
                f"The inline script contains the keyword '{m.group()}', which "
                "comes from the vocabulary of published Magecart / formjacking "
                "toolkits. Legitimate code doesn't have variables or comments "
                "named after the attack itself. Treat this as an active "
                "compromise indicator until proven otherwise."
            ),
            severity=Severity.CRITICAL,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=snippet,
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx, "keyword": m.group()},
            )],
            confidence=0.9,
            remediation=(
                "Treat this as an active incident. Snapshot the inline "
                "scripts and HTML, then audit server-side access logs from "
                "the time the file was last modified backwards for "
                "unauthorised CMS logins or file changes. Rotate every "
                "admin credential that touched the affected file."
            ),
            framework=_FA["skimmer_keyword"],
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx, "keyword": m.group()},
        )]

    def _check_eval_decode(self, script, idx, artifacts):
        if not _EVAL_DECODE.search(script):
            return []
        snippet = _snippet(script)
        return [Finding(
            title="JavaScript decodes-and-evaluates a runtime payload",
            description=(
                "The inline script combines `eval(…)` or `new Function(…)` "
                "with `atob(…)` or `decodeURIComponent(escape(…))`. That "
                "pattern only exists for one reason: to evaluate JavaScript "
                "that's hidden from static analysis. Legitimate scripts "
                "don't need to base64-encode their own code; injected "
                "malware does it precisely to evade scanners and CSPs that "
                "block inline `<script>` content."
            ),
            severity=Severity.HIGH,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=snippet,
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx},
            )],
            confidence=0.85,
            remediation=(
                "Manually inspect what the decoded payload does. If it's "
                "third-party code you don't recognise, treat as malware. "
                "Add `'unsafe-eval'` removal to your CSP — once that's "
                "blocked, even injected eval-based payloads can't run."
            ),
            framework=_FA["obfuscation"],
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx},
        )]

    def _check_document_write_script(self, script, idx, artifacts):
        if not _DOCUMENT_WRITE_SCRIPT.search(script):
            return []
        snippet = _snippet(script)
        return [Finding(
            title="Inline script writes a <script> tag via document.write",
            description=(
                "The inline script uses `document.write('<script…')` to "
                "inject another script tag. This is one of the oldest "
                "injection patterns on the web — modern build pipelines "
                "have no reason to emit it, and Chrome has been gradually "
                "blocking the pattern since 2019. When it does appear in a "
                "recent codebase it usually means a vulnerable ad-network "
                "tag or an outright injection by a compromised template."
            ),
            severity=Severity.HIGH,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=snippet,
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx},
            )],
            confidence=0.85,
            remediation=(
                "Trace the surrounding code — most often it's a tag-manager "
                "snippet that should be replaced with the vendor's modern "
                "async-loader template. If you can't account for the call, "
                "treat the script as injected and audit the page template "
                "for unauthorised edits."
            ),
            framework=_FA["document_write_script"],
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx},
        )]

    def _check_large_atob_blob(self, script, idx, artifacts):
        m = _LARGE_ATOB_BLOB.search(script)
        if not m:
            return []
        blob_len = len(m.group(1))
        return [Finding(
            title=f"Large base64-encoded payload in atob() ({blob_len} chars)",
            description=(
                f"The inline script base64-decodes a {blob_len}-character "
                "blob at runtime. Big base64 blobs are sometimes legitimate "
                "(an inline image, a sourcemap), but combined with "
                "`atob(…)` they're often packed JavaScript intended to "
                "bypass content-based detection. Worth inspecting what the "
                "decoded payload contains."
            ),
            severity=Severity.MEDIUM,
            category=FindingCategory.COMPROMISE,
            evidence=[Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=f"atob() blob of length {blob_len}, "
                        f"prefix: {m.group(1)[:60]}…",
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"script_index": idx, "blob_length": blob_len},
            )],
            confidence=0.6,
            remediation=(
                "Decode the base64 and look at the resulting bytes. If it "
                "starts with `<svg`, `data:image/`, or recognisable "
                "JSON/binary it's probably fine. If it decodes to "
                "JavaScript source you can read, that's a strong signal "
                "of obfuscation — investigate further."
            ),
            framework=_FA["obfuscation"],
            scanner_engine=_ENGINE,
            metadata={"url": artifacts.url, "script_index": idx,
                      "blob_length": blob_len},
        )]

    def _check_event_handlers(self, artifacts):
        """Scan inline event-handler attributes (onclick=…, onerror=…) for
        script-execution primitives. The extractor already harvests these
        into artifacts.event_handlers as (tag, attr, value) triples."""
        findings: list[Finding] = []
        seen: set[str] = set()
        for tag, attr, value in (artifacts.event_handlers or []):
            if not value or attr.lower() not in {
                "onload", "onerror", "onclick", "onmouseover", "onmouseout",
                "onfocus", "onblur", "onchange", "onsubmit", "onkeydown",
                "onkeyup", "onkeypress", "ontoggle",
            }:
                continue
            if not _EVENT_HANDLER_PAYLOAD.search(value):
                continue
            key = (attr, value[:80])
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                title=f"Inline event handler executes JS primitive ({attr})",
                description=(
                    f"The page contains `<{tag} {attr}=\"…\">` whose value "
                    "calls one of `eval`, `Function`, `setTimeout`, "
                    "`atob`, `fetch`, `document.write`, or assigns to "
                    "`window.location`. Inline event-handler attributes "
                    "are the most common place stored XSS payloads land — "
                    "and any payload that takes its source from user "
                    "input here would be both invisible to a static "
                    "script-src CSP and execute every time the page renders."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=f"<{tag} {attr}=\"{value[:200]}\">",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                    extra={"tag": tag, "attr": attr},
                )],
                confidence=0.8,
                remediation=(
                    "Move the logic into a regular `<script>` block that "
                    "binds the handler programmatically. Modern CSPs "
                    "(`script-src 'self'; no inline`) block inline event "
                    "handlers entirely — that's the long-term fix. If the "
                    "handler value contains user-supplied content, this is "
                    "a stored-XSS finding: sanitise the input on the way "
                    "into the database."
                ),
                framework=_FA["event_handler_payload"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "tag": tag, "attr": attr},
            ))
        return findings

    def _check_javascript_uris_in_handlers(self, artifacts):
        """`href=\"javascript:…\"` or `src=\"javascript:…\"` style URIs."""
        findings: list[Finding] = []
        for tag, attr, value in (artifacts.event_handlers or []):
            # The extractor stores event_handlers tuples — but href/src
            # values also flow through if the extractor includes them in the
            # list. For safety we re-check on attribute name as well.
            if not value or not _JAVASCRIPT_URI.match(value):
                continue
            if attr.lower() not in {"href", "src", "formaction", "action"}:
                continue
            findings.append(Finding(
                title=f"`javascript:` URI used in <{tag} {attr}=…>",
                description=(
                    f"The element <{tag} {attr}=\"{value[:60]}…\"> uses a "
                    "`javascript:` URL. `javascript:` URIs execute "
                    "arbitrary code in the page origin — a stored XSS "
                    "payload that lands in an href/src field this way "
                    "fires the moment a user clicks. CSP `script-src` "
                    "with `'unsafe-inline'` disabled blocks them, but a "
                    "lot of legacy CSPs don't."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=f"<{tag} {attr}=\"{value[:200]}\">",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                )],
                confidence=0.85,
                remediation=(
                    "Replace `javascript:` URLs with a `<button>` element "
                    "or an `addEventListener` binding. If the attribute "
                    "value is user-supplied, sanitise it server-side to "
                    "strip `javascript:` (and other dangerous schemes) "
                    "before storing."
                ),
                framework=_FA["javascript_uri"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "tag": tag, "attr": attr},
            ))
        return findings

    def _check_suspicious_external_scripts(self, artifacts):
        findings: list[Finding] = []
        for src in artifacts.external_script_urls:
            if not src.startswith("http"):
                continue
            try:
                domain = urlparse(src).netloc.lower()
            except Exception:
                continue
            if not domain:
                continue
            tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
            if tld not in _RISKY_TLDS:
                continue
            findings.append(Finding(
                title=f"External script loaded from cheap/abuse-prone TLD (.{tld})",
                description=(
                    f"A `<script src='{src}'>` loads from the `.{tld}` TLD, "
                    "one of the registry-free or near-free top-level domains "
                    "that show up repeatedly in malware campaigns (Spamhaus "
                    "publishes the World's Most Abused TLDs report — these "
                    "categories dominate the top 20). Legitimate vendors "
                    "almost always use `.com`/`.net`/`.io`/their country "
                    "code, not these."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.JAVASCRIPT,
                    content=f"Script src: {src}",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                )],
                confidence=0.8,
                remediation=(
                    "Verify the script's purpose. If you can't account for "
                    "it, remove it from the template and assume the page "
                    "was compromised — audit recent CMS changes, rotate "
                    "credentials, and reissue any session tokens for users "
                    "who visited the affected pages."
                ),
                framework=_FA["risky_tld_script"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "script_src": src, "tld": tld},
            ))
        return findings


def _snippet(text: str, around: int = 0, length: int = 150) -> str:
    start = max(0, around - length // 2)
    return text[start: start + length].replace("\n", " ").strip()
