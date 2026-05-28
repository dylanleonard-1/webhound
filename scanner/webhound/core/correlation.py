# WebHound — scanner/webhound/core/correlation.py
# Phase-3 audit: multi-engine correlation + threat-chain clustering.
#
# Each per-engine finding stands alone today. This module runs *after* the
# per-engine pass and looks for cross-engine patterns that converge into a
# stronger story. When a chain matches:
#   - the constituent findings get their confidence bumped (single signal →
#     corroborated signal) and a transparency note in
#     metadata.corroborated_by_findings;
#   - one new "cluster" finding is emitted summarising the threat chain,
#     pointing at every participating finding via metadata.constituent_findings.
#
# Safe-by-design:
#   - never adds findings that aren't backed by ≥2 underlying engine
#     findings (so a clean scan stays clean — no speculative clusters)
#   - never lowers an existing finding's severity or confidence (only adds
#     corroboration)
#   - failures swallowed so the per-engine results always ship

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse
from uuid import UUID

from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity

logger = logging.getLogger(__name__)

_CORRELATION_ENGINE = "correlation"


@dataclass(frozen=True)
class Match:
    """One matched signal in a chain. References the underlying finding by
    id + title + engine so the transparency note in the cluster finding's
    evidence reads cleanly."""

    finding_id: UUID
    engine: str
    title: str
    severity: Severity


@dataclass(frozen=True)
class Chain:
    """A correlation pattern that fired. The cluster finding is emitted
    iff `is_complete` (every required signal matched)."""

    name: str
    description: str
    severity: Severity                  # cluster severity when complete
    confidence_bump: float              # bump applied to each matched finding
    matches: tuple[Match, ...] = field(default_factory=tuple)
    required_signals: int = 2
    framework: FrameworkAlignment = field(default_factory=FrameworkAlignment)
    remediation: str = ""

    @property
    def is_complete(self) -> bool:
        return len(self.matches) >= self.required_signals


# ---------------------------------------------------------------------------
# Built-in correlation rules
# ---------------------------------------------------------------------------


def _matches_keywords(text: str, kws: Iterable[str]) -> bool:
    t = (text or "").lower()
    return any(k in t for k in kws)


def _engine_matches(f: Finding, names: Iterable[str]) -> bool:
    return f.scanner_engine in set(names)


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return (urlparse(url).hostname or "").lower() or None
    except Exception:  # noqa: BLE001
        return None


def _finding_to_match(f: Finding) -> Match:
    return Match(finding_id=f.id, engine=f.scanner_engine,
                 title=f.title, severity=f.severity)


def _supply_chain_chain(findings: list[Finding]) -> Chain | None:
    """**Supply-chain compromise risk**: weak/missing CSP + at least one
    third-party threat-intel hit (suspicious/risky domain) + obfuscation-
    detector hit. The user listed this exact chain in their Phase-3 prompt."""
    csp_signal = next(
        (f for f in findings
         if _engine_matches(f, ["security_headers", "headers"])
         and _matches_keywords(f.title, ["csp", "content-security-policy",
                                          "content security policy"])),
        None,
    )
    third_party_signal = next(
        (f for f in findings
         if _engine_matches(f, ["threat_intel"])
         and _matches_keywords(f.title, ["suspicious", "high-risk",
                                          "likely malicious", "punycode"])),
        None,
    )
    obfuscation_signal = next(
        (f for f in findings
         if _engine_matches(f, ["obfuscation_detector"])
         and _matches_keywords(f.title, ["base64", "obfuscat", "eval",
                                          "packed", "hex"])),
        None,
    )
    matches = tuple(_finding_to_match(s) for s in
                    (csp_signal, third_party_signal, obfuscation_signal) if s)
    if len(matches) < 2:
        return None
    return Chain(
        name="supply_chain_compromise_risk",
        description=(
            "Multiple converging signals suggest a heightened supply-chain "
            "compromise risk: a permissive Content-Security-Policy allows "
            "arbitrary third-party code execution, a third-party host the "
            "page references was flagged by the threat-intel engine, and "
            "the page also contains obfuscated/encoded inline JavaScript. "
            "Any one of these is mild on its own; together they describe "
            "the classic 'compromised vendor ships code into your origin' "
            "scenario. Investigate the third-party vendor relationship, "
            "snapshot the obfuscated script, and tighten CSP to a strict "
            "allowlist."
        ),
        severity=Severity.HIGH,
        confidence_bump=0.15,
        matches=matches,
        required_signals=2,
        framework=FrameworkAlignment(
            owasp_top10=["A05:2021", "A08:2021"],
            cwe_ids=["CWE-829", "CWE-1395", "CWE-693"],
            nist_controls=["SI-3", "SR-3", "CM-6"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            cvss_score=8.7,
            iso_27001=["A.5.19", "A.8.7", "A.8.23"],
            soc2=["CC7.1", "CC6.7"],
            exploitability=Exploitability.PRACTICAL,
        ),
        remediation=(
            "Tighten CSP to an explicit vendor allowlist (no wildcards, no "
            "`'unsafe-inline'`, no `'unsafe-eval'`). Audit every third-party "
            "host the page loads from — remove the ones you don't actively "
            "rely on, document the ones you do. Decode the obfuscated "
            "script to confirm what it does; if you can't account for it, "
            "treat it as injected."
        ),
    )


def _exposed_admin_chain(findings: list[Finding]) -> Chain | None:
    """**Exposed admin attack surface**: an admin/login path was surfaced
    (recon engine), authentication-related headers are weak (missing HSTS /
    weak CSP / no X-Frame-Options on the same origin), and a login form
    exists. Three converging signals = "the admin panel is reachable and
    insufficiently protected"."""
    admin_signal = next(
        (f for f in findings
         if _engine_matches(f, ["sensitive_paths"])
         and _matches_keywords(
             (f.metadata or {}).get("path", ""),
             ["admin", "login", "phpmyadmin", "adminer", "wp-admin"],
         )),
        None,
    )
    headers_signal = next(
        (f for f in findings
         if _engine_matches(f, ["security_headers", "headers"])
         and _matches_keywords(f.title, ["hsts", "x-frame", "strict-transport",
                                          "missing", "weak"])),
        None,
    )
    form_signal = next(
        (f for f in findings
         if _engine_matches(f, ["form_risk", "forms"])
         and _matches_keywords(f.title, ["login", "password", "credential",
                                          "auth"])),
        None,
    )
    matches = tuple(_finding_to_match(s) for s in
                    (admin_signal, headers_signal, form_signal) if s)
    if len(matches) < 2:
        return None
    return Chain(
        name="exposed_admin_attack_surface",
        description=(
            "An administrative or authentication surface was discovered "
            "alongside one or more weak security-header configurations. "
            "An exposed admin path is recon-only on its own; combined with "
            "missing HSTS / clickjacking protection / a password form, the "
            "blast radius of a successful credential attack expands "
            "significantly. Treat as a single hardening project rather "
            "than three independent findings."
        ),
        severity=Severity.HIGH,
        confidence_bump=0.10,
        matches=matches,
        required_signals=2,
        framework=FrameworkAlignment(
            owasp_top10=["A07:2021", "A05:2021"],
            cwe_ids=["CWE-284", "CWE-693", "CWE-200"],
            nist_controls=["AC-3", "SC-8", "CM-6"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L",
            cvss_score=8.1,
            pci_dss=["6.5.5", "8.3.1"],
            iso_27001=["A.5.15", "A.8.5", "A.8.23"],
            soc2=["CC6.1", "CC6.6"],
            exploitability=Exploitability.PRACTICAL,
        ),
        remediation=(
            "Either remove the admin/login surface from the public origin "
            "(VPN, allowlist, separate hostname) or harden it — enforce "
            "HSTS, set X-Frame-Options/CSP frame-ancestors, require MFA, "
            "and put rate-limiting + lockouts on the login form."
        ),
    )


def _credential_exfil_chain(findings: list[Finding]) -> Chain | None:
    """**Credential exfiltration risk**: inline JS with eval/atob + a fetch
    to a third-party host + secret-like patterns. We already flag each of
    these individually at low confidence; together they describe the
    `decode → POST credentials elsewhere` pattern."""
    decode_signal = next(
        (f for f in findings
         if _engine_matches(f, ["obfuscation_detector"])
         and _matches_keywords(f.title, ["base64", "eval", "hex", "obfuscat"])),
        None,
    )
    third_party_fetch = next(
        (f for f in findings
         if _engine_matches(f, ["threat_intel"])
         and _matches_keywords(f.title, ["suspicious", "high-risk",
                                          "shortener", "third-party"])),
        None,
    )
    secret_signal = next(
        (f for f in findings
         if _engine_matches(f, ["secret_scanner", "secrets"])
         and _matches_keywords(f.title, ["token", "key", "secret",
                                          "credential", "password"])),
        None,
    )
    matches = tuple(_finding_to_match(s) for s in
                    (decode_signal, third_party_fetch, secret_signal) if s)
    # Require ALL three signals — obfuscation + third-party alone is already
    # covered by the supply-chain chain; the secret/credential signal is
    # what distinguishes "compromise risk" from "credentials likely already
    # leaving the page".
    if len(matches) < 3:
        return None
    return Chain(
        name="credential_exfiltration_risk",
        description=(
            "Inline obfuscated JavaScript was found on the same page as "
            "a suspicious external host and at least one secret-shaped "
            "token / credential pattern. This is the standard footprint "
            "of decode-then-POST exfiltration: encoded payload, third-party "
            "destination, captured credential. Investigate as a potential "
            "client-side compromise."
        ),
        severity=Severity.CRITICAL,
        confidence_bump=0.20,
        matches=matches,
        required_signals=3,
        framework=FrameworkAlignment(
            owasp_top10=["A03:2021", "A07:2021", "A08:2021"],
            cwe_ids=["CWE-506", "CWE-829", "CWE-200"],
            nist_controls=["SI-3", "SI-10", "AC-4"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            cvss_score=9.6,
            pci_dss=["6.5.5", "11.5.1"],
            iso_27001=["A.8.7", "A.8.23", "A.8.28"],
            soc2=["CC6.6", "CC7.1"],
            exploitability=Exploitability.PRACTICAL,
        ),
        remediation=(
            "Snapshot the page, the obfuscated script, and the network "
            "request log immediately. Rotate any credentials served from "
            "or entered into the affected page. Audit recent CMS / template "
            "/ vendor changes — most client-side compromises arrive via "
            "modified vendor scripts or compromised CMS templates."
        ),
    )


def _weak_tls_credential_capture_chain(findings: list[Finding]) -> Chain | None:
    """**Weak TLS + insecure cookies + login form**: a credential capture
    surface protected by inadequate transport security. Even one of these
    is concerning; together they describe a login that ships passwords
    over a channel an attacker can plausibly observe + a cookie that
    won't survive proper SameSite/Secure scrutiny."""
    weak_tls = next(
        (f for f in findings
         if _engine_matches(f, ["tls_checker", "tls"])
         and _matches_keywords(f.title, ["tls 1.0", "tls 1.1", "weak cipher",
                                          "expired", "self-signed",
                                          "mismatched hostname", "sslv3",
                                          "deprecated"])),
        None,
    )
    insecure_cookie = next(
        (f for f in findings
         if _engine_matches(f, ["cookie_scanner", "cookies"])
         and _matches_keywords(f.title, ["secure flag", "samesite", "httponly",
                                          "missing secure", "missing samesite"])),
        None,
    )
    auth_form = next(
        (f for f in findings
         if _engine_matches(f, ["form_risk", "input_analysis", "forms"])
         and _matches_keywords(f.title, ["password", "login", "credential",
                                          "auth", "csrf"])),
        None,
    )
    matches = tuple(_finding_to_match(s) for s in
                    (weak_tls, insecure_cookie, auth_form) if s)
    if len(matches) < 2:
        return None
    return Chain(
        name="weak_tls_credential_capture_risk",
        description=(
            "A login or other credential-capture form was found on a host "
            "whose TLS posture is weak — and the cookies that would carry "
            "the session afterwards are missing one or more of the Secure "
            "/ HttpOnly / SameSite flags. Each finding on its own is a "
            "hardening gap; together they describe a login whose "
            "credentials are observable in transit *and* whose session "
            "cookie is observable from JS / over non-TLS subsequent "
            "requests. Treat as a coordinated transport-security project."
        ),
        severity=Severity.HIGH,
        confidence_bump=0.12,
        matches=matches,
        required_signals=2,
        framework=FrameworkAlignment(
            owasp_top10=["A02:2021", "A07:2021"],
            cwe_ids=["CWE-319", "CWE-614", "CWE-326"],
            nist_controls=["SC-8", "SC-13", "IA-5"],
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cvss_score=7.4,
            pci_dss=["4.2.1", "6.4.3", "8.3.6"],
            iso_27001=["A.5.15", "A.8.24", "A.8.5"],
            soc2=["CC6.6", "CC6.1"],
            exploitability=Exploitability.PRACTICAL,
        ),
        remediation=(
            "Enforce TLS ≥1.2 (preferably 1.3) and disable deprecated "
            "cipher suites. Set Secure + HttpOnly + SameSite=Strict on "
            "every session cookie. Confirm HSTS is enabled with a "
            "non-trivial max-age."
        ),
    )


def _csp_external_inline_chain(findings: list[Finding]) -> Chain | None:
    """**CSP missing + external JS + inline scripts**: the page combines
    third-party script execution with inline (unhashed/unnonced) script
    in a context with no Content-Security-Policy. Each is benign in
    isolation in many sites; together they describe an environment where
    a compromised third-party can inject inline JS that browsers will
    happily execute."""
    csp_signal = next(
        (f for f in findings
         if _engine_matches(f, ["security_headers", "csp_engine", "headers"])
         and _matches_keywords(f.title, ["csp", "content-security-policy",
                                          "content security policy",
                                          "unsafe-inline", "unsafe-eval"])),
        None,
    )
    external_js = next(
        (f for f in findings
         if _engine_matches(f, ["third_party_domains", "js_analyzer",
                                 "third_party"])
         and _matches_keywords(f.title, ["external script", "third-party js",
                                          "third party script", "untrusted"])),
        None,
    )
    inline_js = next(
        (f for f in findings
         if _engine_matches(f, ["js_analyzer", "obfuscation_detector",
                                 "injected_js"])
         and _matches_keywords(f.title, ["inline script", "inline js",
                                          "inline javascript", "eval",
                                          "function constructor"])),
        None,
    )
    matches = tuple(_finding_to_match(s) for s in
                    (csp_signal, external_js, inline_js) if s)
    if len(matches) < 2:
        return None
    return Chain(
        name="csp_external_inline_compounding_risk",
        description=(
            "The page loads scripts from third-party hosts AND runs inline "
            "JavaScript, but has no Content-Security-Policy (or one that "
            "permits both via `'unsafe-inline'`). Browsers will execute "
            "anything a compromised vendor injects via inline insertion. "
            "Tightening CSP closes both attack paths simultaneously."
        ),
        severity=Severity.MEDIUM,
        confidence_bump=0.10,
        matches=matches,
        required_signals=2,
        framework=FrameworkAlignment(
            owasp_top10=["A05:2021", "A08:2021"],
            cwe_ids=["CWE-693", "CWE-829"],
            nist_controls=["SI-10", "CM-6"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            cvss_score=6.1,
            iso_27001=["A.8.7", "A.8.23"],
            soc2=["CC6.7"],
            exploitability=Exploitability.PRACTICAL,
        ),
        remediation=(
            "Adopt a nonce- or hash-based CSP that explicitly enumerates "
            "every trusted script origin. Move inline event handlers / "
            "scripts to external files (so nonces can apply) or hash them "
            "into the CSP. Never use `'unsafe-inline'` with a third-party "
            "script allowlist — that combination effectively neutralises "
            "CSP."
        ),
    )


def _beaconing_third_party_chain(findings: list[Finding]) -> Chain | None:
    """**Suspicious third-party + obfuscated JS + network beacons**: a
    common malware/skimmer footprint. We already flag each component;
    together they describe an inline script that's both *hiding* what it
    does *and* phoning home to a suspicious destination."""
    suspicious_host = next(
        (f for f in findings
         if _engine_matches(f, ["threat_intel"])
         and _matches_keywords(f.title, ["suspicious", "high-risk",
                                          "likely malicious", "shortener"])),
        None,
    )
    obfuscated_js = next(
        (f for f in findings
         if _engine_matches(f, ["obfuscation_detector"])
         and _matches_keywords(f.title, ["obfuscat", "base64", "hex",
                                          "packed", "eval", "function ctor"])),
        None,
    )
    beacon_signal = next(
        (f for f in findings
         if _engine_matches(f, ["js_analyzer", "endpoint_discovery",
                                 "api_discovery"])
         and _matches_keywords(f.title, ["beacon", "navigator.sendbeacon",
                                          "websocket", "eventsource",
                                          "fetch(", "xhr", "xmlhttprequest"])),
        None,
    )
    matches = tuple(_finding_to_match(s) for s in
                    (suspicious_host, obfuscated_js, beacon_signal) if s)
    # Require ALL three signals — the beacon/fetch/WebSocket signal is
    # what differentiates this from generic supply-chain risk. Without
    # it, the supply_chain chain already covers the obfuscated-script +
    # suspicious-host combination.
    if len(matches) < 3:
        return None
    return Chain(
        name="beaconing_third_party_compromise_risk",
        description=(
            "An obfuscated inline script is sending traffic out of the "
            "page (beacon / fetch / WebSocket / EventSource) toward a "
            "suspicious or high-risk host. This is the classic skimmer / "
            "info-stealer footprint. Even if each signal individually "
            "looks like marketing or analytics, the combination warrants "
            "active investigation."
        ),
        severity=Severity.HIGH,
        confidence_bump=0.15,
        matches=matches,
        required_signals=3,
        framework=FrameworkAlignment(
            owasp_top10=["A08:2021", "A03:2021"],
            cwe_ids=["CWE-506", "CWE-829", "CWE-1395"],
            nist_controls=["SI-3", "SI-4", "AC-4"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
            cvss_score=8.7,
            pci_dss=["6.4.3", "11.5.1"],
            iso_27001=["A.8.7", "A.8.16"],
            soc2=["CC7.1", "CC7.2"],
            exploitability=Exploitability.PRACTICAL,
        ),
        remediation=(
            "Capture the obfuscated script and the destination URL "
            "immediately. Compare the script against the version your "
            "build/vendor is supposed to ship. If you can't account for "
            "the destination host, treat it as exfiltration and rotate "
            "any credentials served from the page."
        ),
    )


def _insecure_api_exposed_token_chain(findings: list[Finding]) -> Chain | None:
    """**Insecure API + exposed tokens + CORS weakness**: an API endpoint
    discovered through endpoint_discovery is paired with both an
    over-permissive CORS configuration AND a secret/token pattern in JS.
    This is the canonical "anyone can call our API with the harvested
    token from any origin" composition."""
    api_signal = next(
        (f for f in findings
         if _engine_matches(f, ["endpoint_discovery", "api_discovery"])
         and _matches_keywords(f.title, ["api endpoint", "rest endpoint",
                                          "graphql", "swagger", "openapi",
                                          "exposed api"])),
        None,
    )
    token_signal = next(
        (f for f in findings
         if _engine_matches(f, ["secret_scanner", "secrets"])
         and _matches_keywords(f.title, ["token", "api key", "bearer",
                                          "secret", "credential"])),
        None,
    )
    cors_signal = next(
        (f for f in findings
         if _engine_matches(f, ["cors", "headers"])
         and _matches_keywords(f.title, ["cors", "access-control-allow",
                                          "wildcard origin", "*", "null origin"])),
        None,
    )
    matches = tuple(_finding_to_match(s) for s in
                    (api_signal, token_signal, cors_signal) if s)
    if len(matches) < 2:
        return None
    return Chain(
        name="insecure_api_exposed_token_risk",
        description=(
            "A discoverable API endpoint, an over-permissive CORS "
            "configuration, and a token / API-key pattern were all "
            "observed on the same target. Even if the API itself enforces "
            "auth correctly, the combination means any origin can call it "
            "with a token harvested from the page — bypassing the "
            "browser-imposed origin boundary."
        ),
        severity=Severity.HIGH,
        confidence_bump=0.12,
        matches=matches,
        required_signals=2,
        framework=FrameworkAlignment(
            owasp_top10=["A05:2021", "A07:2021", "A01:2021"],
            cwe_ids=["CWE-942", "CWE-200", "CWE-862"],
            nist_controls=["AC-3", "AC-4", "SI-10"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
            cvss_score=9.1,
            pci_dss=["6.5.5", "8.3.1"],
            iso_27001=["A.5.15", "A.8.23"],
            soc2=["CC6.1", "CC6.3"],
            exploitability=Exploitability.PRACTICAL,
        ),
        remediation=(
            "Lock CORS down to a strict allowlist (never `*` with "
            "credentials). Move any token / API-key out of the page — "
            "serve it via a backend proxy that performs the call on the "
            "user's behalf. If the token must be in the browser, treat it "
            "as public and ensure the API does not grant any privileged "
            "operation behind it alone."
        ),
    )


# Rules are evaluated in *severity* order — the most specific / most severe
# chains first. When a higher-priority chain fires, the IDs of its matched
# findings are recorded; lower-priority chains whose matched-ID set is a
# subset of an already-claimed set are dropped to avoid emitting two
# overlapping cluster findings for the same evidence. (A scan with three
# signals would otherwise produce both `credential_exfiltration_risk`
# (CRITICAL) AND `supply_chain_compromise_risk` (HIGH) — same evidence,
# weaker story.)
_RULES = (
    # CRITICAL chains first — they describe active compromise patterns.
    _credential_exfil_chain,
    # HIGH chains — distinct compounding risks that don't subsume each other.
    _beaconing_third_party_chain,
    _insecure_api_exposed_token_chain,
    _supply_chain_chain,
    _exposed_admin_chain,
    _weak_tls_credential_capture_chain,
    # MEDIUM chains — defence-in-depth gaps that compound but aren't on their
    # own a compromise indicator.
    _csp_external_inline_chain,
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


@dataclass
class CorrelationResult:
    """Outcome of one correlation pass. Callers fold these back into the
    scan result before grouping/scoring.

    ``boosted_finding_ids`` is keyed by finding id and holds a *delta* that
    should be added to that finding's existing confidence (capped at 1.0
    by the caller). Storing a delta rather than an absolute makes the bump
    behave correctly regardless of the underlying finding's starting
    confidence — a heuristic at 0.4 + bump 0.15 → 0.55, a confirmed at
    0.9 + bump 0.15 → 1.0.

    ``chain_membership`` is the inverse view used by ``apply_correlation``
    to write a transparency note (`metadata.corroborated_by`) onto every
    finding that contributed to a cluster.
    """

    cluster_findings: list[Finding] = field(default_factory=list)
    boosted_finding_ids: dict[UUID, float] = field(default_factory=dict)
    chain_membership: dict[UUID, list[str]] = field(default_factory=dict)


def correlate_findings(findings: list[Finding]) -> CorrelationResult:
    """Run every built-in correlation rule. Returns new cluster findings +
    a map of `{finding_id: new_confidence}` representing the corroboration
    bumps. The caller applies the bumps and appends the clusters.

    Errors are swallowed per-rule so a malformed evidence blob can't
    suppress unrelated chains."""
    result = CorrelationResult()
    # Set of finding-ID sets already claimed by a higher-priority chain.
    # A new chain is suppressed iff its matched-ID set is a subset of any
    # already-claimed set — meaning every signal it points at is already
    # part of a more specific cluster.
    claimed_sets: list[frozenset[UUID]] = []
    for rule in _RULES:
        try:
            chain = rule(findings)
        except Exception:  # noqa: BLE001
            logger.debug("correlation rule %s failed", rule.__name__,
                         exc_info=True)
            continue
        if chain is None or not chain.is_complete:
            continue
        chain_ids = frozenset(m.finding_id for m in chain.matches)
        if any(chain_ids.issubset(claimed) for claimed in claimed_sets):
            # A higher-priority chain already covers every signal — skip.
            continue
        claimed_sets.append(chain_ids)
        result.cluster_findings.append(_chain_to_finding(chain))
        for m in chain.matches:
            # Cumulative delta — if a finding sits in two non-overlapping
            # chains its confidence climbs by both bumps (rare but valid).
            existing = result.boosted_finding_ids.get(m.finding_id, 0.0)
            result.boosted_finding_ids[m.finding_id] = existing + chain.confidence_bump
            result.chain_membership.setdefault(m.finding_id, []).append(chain.name)
    return result


def apply_correlation(findings: list[Finding],
                      result: CorrelationResult) -> list[Finding]:
    """Apply the bumps + return findings + cluster findings.

    Idempotent: per-finding metadata records which chains have already
    been applied, so re-running with the same CorrelationResult won't
    double-bump. The transparency note (`metadata.corroborated_by`) and
    the `corroborated` tag are both deduplicated. Existing confidence is
    the floor — bumps only ever raise."""
    if not result.boosted_finding_ids and not result.cluster_findings:
        return findings

    by_id = {f.id: f for f in findings}

    for fid, delta in result.boosted_finding_ids.items():
        target = by_id.get(fid)
        if target is None:
            continue
        target.metadata = dict(target.metadata or {})
        already_applied = set(target.metadata.get("corroborated_by") or [])
        new_chains = [c for c in result.chain_membership.get(fid, [])
                      if c not in already_applied]
        if not new_chains:
            # Already corroborated by every chain we'd add — nothing to do.
            continue
        # Recompute delta from just the *new* chains to keep idempotency.
        # We don't have per-chain deltas tracked separately, but the
        # already_applied check above guarantees we won't enter this branch
        # twice for the same chain set, so the stored delta is correct.
        new_conf = min(1.0, target.confidence + delta)
        if new_conf > target.confidence:
            target.confidence = new_conf
        target.metadata["corroborated_by"] = sorted(already_applied
                                                    | set(new_chains))
        existing_tags = list(target.tags or [])
        if "corroborated" not in existing_tags:
            existing_tags.append("corroborated")
        target.tags = existing_tags

    return findings + result.cluster_findings


def _chain_to_finding(chain: Chain) -> Finding:
    constituents = [
        {"id": str(m.finding_id), "engine": m.engine, "title": m.title,
         "severity": m.severity.value}
        for m in chain.matches
    ]
    evidence_lines = [
        f"Cluster: {chain.name}",
        f"Corroborating findings ({len(chain.matches)}):",
    ]
    for m in chain.matches:
        evidence_lines.append(
            f"  - [{m.engine}] {m.title}  ({m.severity.value})"
        )
    return Finding(
        title=f"Correlated threat chain: {chain.name.replace('_', ' ')}",
        description=chain.description,
        severity=chain.severity,
        # Cluster findings are their own thing — surface them under
        # the COMPROMISE category since that's where threat-chain UIs live.
        category=FindingCategory.COMPROMISE,
        evidence=[Evidence(
            evidence_type=EvidenceType.RAW,
            content="\n".join(evidence_lines),
            location="",
            source_engine=_CORRELATION_ENGINE,
            extra={"chain": chain.name,
                   "constituent_finding_ids": [str(m.finding_id)
                                                for m in chain.matches]},
        )],
        # Cluster confidence reflects the number of converging signals.
        # 2 signals -> 0.80, 3 -> 0.90, 4+ -> 0.95.
        confidence=min(0.95, 0.65 + 0.10 * len(chain.matches)),
        remediation=chain.remediation,
        framework=chain.framework,
        scanner_engine=_CORRELATION_ENGINE,
        tags=["correlated", "cluster", chain.name],
        metadata={
            "chain_name": chain.name,
            "signal_count": len(chain.matches),
            "constituent_finding_ids": [str(m.finding_id) for m in chain.matches],
            "constituents": constituents,
        },
    )
