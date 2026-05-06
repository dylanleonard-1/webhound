# WebHound — scanner/webhound/engines/compromise/suspicious_redirects.py
# Passive detection of suspicious redirect patterns.
#
# Safe-mode: reads pre-extracted PageArtifacts and optional raw HTML.
# No active requests, no JavaScript execution.

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "suspicious_redirects"

_REDIRECT_PARAMS: frozenset[str] = frozenset({
    "redirect", "redirect_to", "redirect_url",
    "url", "next", "goto", "return", "return_url",
    "returnurl", "returnto", "redir", "destination",
    "dest", "forward", "forwardurl", "target",
})

_SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "cli.gs", "pic.gd", "su.pr", "twurl.nl",
    "snipurl.com", "short.to", "BudURL.com", "ping.fm",
    "post.ly", "Just.as", "bkite.com", "snipr.com",
    "fic.kr", "loopt.us", "doiop.com", "short.ie",
    "kl.am", "wp.me", "rubyurl.com", "om.ly", "linkbee.com",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc",
})

_META_REFRESH_URL = re.compile(
    r"url\s*=\s*['\"]?([^'\";\s>]+)",
    re.I,
)

_JS_REDIRECT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:window\.)?location(?:\.href)?\s*=\s*['\"]https?://([^'\"]+)", re.I),
    re.compile(r"location\.replace\s*\(\s*['\"]https?://([^'\"]+)", re.I),
    re.compile(r"location\.assign\s*\(\s*['\"]https?://([^'\"]+)", re.I),
]


def _host_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _is_external(dest: str, page_url: str) -> bool:
    dest_host = _host_from_url(dest)
    page_host = _host_from_url(page_url)
    if not dest_host:
        return False
    return dest_host != page_host


def _is_shortener(url: str) -> bool:
    host = _host_from_url(url)
    return host in _SHORTENER_DOMAINS or host.startswith("www.") and host[4:] in _SHORTENER_DOMAINS


class SuspiciousRedirectsEngine:
    """Passive detection of suspicious redirect patterns.

    Checks:
    - Meta refresh tags pointing to external URLs (HIGH) or URL shorteners (MEDIUM)
    - JavaScript location.href / replace / assign with hardcoded external URLs (MEDIUM)
    - Open redirect parameters in the page's own URL (MEDIUM)

    Call ``analyze(artifacts, html_body=...)`` to receive a list of findings.
    """

    NAME = _ENGINE

    def analyze(
        self,
        artifacts: PageArtifacts,
        html_body: str | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_meta_refresh(artifacts))
        findings.extend(self._check_js_redirects(artifacts))
        findings.extend(self._check_open_redirect_params(artifacts))
        return findings

    # ------------------------------------------------------------------

    def _check_meta_refresh(self, artifacts: PageArtifacts) -> list[Finding]:
        refresh = artifacts.meta_tags.get("refresh", "")
        if not refresh:
            return []

        m = _META_REFRESH_URL.search(refresh)
        if not m:
            return []

        dest = m.group(1).strip().strip("'\"")
        if not dest or not dest.startswith("http"):
            return []

        if _is_shortener(dest):
            return [Finding(
                title="Meta refresh redirect to URL shortener",
                description=(
                    f"A meta refresh tag redirects to '{dest}', which is a URL shortener. "
                    "URL shorteners obscure the final destination and are commonly used "
                    "in phishing and malware campaigns."
                ),
                severity=Severity.MEDIUM,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=f"<meta http-equiv='refresh' content='{refresh[:200]}'>",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                    extra={"destination": dest, "shortener": True},
                )],
                confidence=0.8,
                remediation=(
                    "Replace the URL shortener with the direct destination URL, "
                    "or remove the meta refresh if not intentional."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A01:2021"],
                    cwe_ids=["CWE-601"],
                    nist_controls=["SI-3"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "destination": dest},
            )]

        if _is_external(dest, artifacts.url):
            return [Finding(
                title="Meta refresh redirect to external domain",
                description=(
                    f"A meta refresh tag redirects visitors to '{dest}', which is on a "
                    "different domain. Automatic redirects to external sites are a common "
                    "indicator of a compromised page redirecting users to malicious content."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=f"<meta http-equiv='refresh' content='{refresh[:200]}'>",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                    extra={"destination": dest, "external": True},
                )],
                confidence=0.85,
                remediation=(
                    "Remove or audit the meta refresh tag. If unintentional, "
                    "treat the page as compromised and investigate server-side modifications."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A01:2021"],
                    cwe_ids=["CWE-601"],
                    nist_controls=["SI-3", "IR-4"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "destination": dest},
            )]

        return []

    def _check_js_redirects(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        seen_hosts: set[str] = set()

        for script in artifacts.inline_scripts:
            if not script:
                continue
            for pattern in _JS_REDIRECT_PATTERNS:
                for m in pattern.finditer(script):
                    dest_path = m.group(1)
                    dest_full = f"https://{dest_path}"
                    dest_host = _host_from_url(dest_full)
                    if not dest_host or dest_host in seen_hosts:
                        continue
                    if not _is_external(dest_full, artifacts.url):
                        continue
                    seen_hosts.add(dest_host)
                    snippet = script[max(0, m.start() - 40): m.start() + 110]
                    findings.append(Finding(
                        title="JavaScript redirect to external domain",
                        description=(
                            f"An inline script redirects to '{dest_host}' via "
                            "location.href, location.replace, or location.assign. "
                            "Hardcoded external JS redirects in inline scripts may "
                            "indicate injected malware redirecting users."
                        ),
                        severity=Severity.MEDIUM,
                        category=FindingCategory.COMPROMISE,
                        evidence=[Evidence(
                            evidence_type=EvidenceType.JAVASCRIPT,
                            content=snippet[:200],
                            location=artifacts.url,
                            source_engine=_ENGINE,
                            extra={"destination_host": dest_host},
                        )],
                        confidence=0.65,
                        remediation=(
                            "Verify that this redirect is intentional. "
                            "If not, audit inline scripts for injected code and "
                            "investigate server logs for unauthorized changes."
                        ),
                        framework=FrameworkAlignment(
                            owasp_top10=["A01:2021"],
                            cwe_ids=["CWE-601"],
                            nist_controls=["SI-3"],
                        ),
                        scanner_engine=_ENGINE,
                        metadata={"url": artifacts.url, "destination_host": dest_host},
                    ))
        return findings

    def _check_open_redirect_params(self, artifacts: PageArtifacts) -> list[Finding]:
        try:
            parsed = urlparse(artifacts.url)
            params = parse_qs(parsed.query, keep_blank_values=False)
        except Exception:
            return []

        findings: list[Finding] = []
        for param_name, values in params.items():
            if param_name.lower() not in _REDIRECT_PARAMS:
                continue
            for value in values:
                value = value.strip()
                if not (value.startswith("http://") or value.startswith("https://")):
                    continue
                if not _is_external(value, artifacts.url):
                    continue
                findings.append(Finding(
                    title="Potential open redirect parameter detected",
                    description=(
                        f"The URL parameter '{param_name}' contains an absolute external "
                        f"URL '{value[:80]}'. Open redirect parameters can be abused in "
                        "phishing attacks by crafting links that appear to go to a trusted "
                        "domain but redirect to a malicious one."
                    ),
                    severity=Severity.MEDIUM,
                    category=FindingCategory.COMPROMISE,
                    evidence=[Evidence(
                        evidence_type=EvidenceType.HTTP_RESPONSE,
                        content=f"?{param_name}={value[:100]}",
                        location=artifacts.url,
                        source_engine=_ENGINE,
                        extra={"param": param_name, "value": value},
                    )],
                    confidence=0.75,
                    remediation=(
                        "Validate redirect destinations against an allowlist of "
                        "trusted URLs. Reject or encode absolute URLs in redirect "
                        "parameters. See CWE-601 for mitigation guidance."
                    ),
                    framework=FrameworkAlignment(
                        owasp_top10=["A01:2021"],
                        cwe_ids=["CWE-601"],
                        nist_controls=["SI-10"],
                    ),
                    scanner_engine=_ENGINE,
                    metadata={"url": artifacts.url, "param": param_name, "value": value},
                ))
        return findings
