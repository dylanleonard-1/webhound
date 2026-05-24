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
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity

_ENGINE = "suspicious_redirects"

_REDIRECT_PARAMS: frozenset[str] = frozenset({
    "redirect", "redirect_to", "redirect_url",
    "url", "next", "goto", "return", "return_url",
    "returnurl", "returnto", "redir", "destination",
    "dest", "forward", "forwardurl", "target",
    "continue", "callback",
})

_SHORTENER_DOMAINS: frozenset[str] = frozenset({
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "cli.gs", "pic.gd", "su.pr", "twurl.nl",
    "snipurl.com", "short.to", "buduurl.com", "ping.fm",
    "post.ly", "just.as", "bkite.com", "snipr.com",
    "fic.kr", "loopt.us", "doiop.com", "short.ie",
    "kl.am", "wp.me", "rubyurl.com", "om.ly", "linkbee.com",
    "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly",
    "lnkd.in", "buff.ly",
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

_FA: dict[str, FrameworkAlignment] = {
    "meta_refresh_external": FrameworkAlignment(
        owasp_top10=["A01:2021", "A08:2021"],
        cwe_ids=["CWE-601"],
        nist_controls=["SI-3", "SI-10", "IR-4"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        cvss_score=6.5,
        pci_dss=["6.4.3", "11.6.1"],
        iso_27001=["A.8.7", "A.8.28"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "meta_refresh_shortener": FrameworkAlignment(
        owasp_top10=["A01:2021"],
        cwe_ids=["CWE-601"],
        nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=4.3,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "meta_refresh_data_uri": FrameworkAlignment(
        owasp_top10=["A03:2021", "A08:2021"],
        cwe_ids=["CWE-79", "CWE-601"],
        nist_controls=["SI-3", "SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cvss_score=6.4,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.25"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "js_redirect": FrameworkAlignment(
        owasp_top10=["A01:2021", "A08:2021"],
        cwe_ids=["CWE-601"],
        nist_controls=["SI-3"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=4.3,
        pci_dss=["6.4.3"],
        iso_27001=["A.8.7"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.PRACTICAL,
    ),
    "open_redirect_param": FrameworkAlignment(
        owasp_top10=["A01:2021"],
        cwe_ids=["CWE-601"],
        nist_controls=["SI-10"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        cvss_score=4.3,
        pci_dss=["6.2.4"],
        iso_27001=["A.8.28"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
}


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
    if host in _SHORTENER_DOMAINS:
        return True
    return host.startswith("www.") and host[4:] in _SHORTENER_DOMAINS


class SuspiciousRedirectsEngine:
    """Passive detection of suspicious redirect patterns.

    - Meta refresh to a `data:` URI → injection / phishing payload.
    - Meta refresh to a URL shortener → MEDIUM (obscures the destination).
    - Meta refresh to a different domain → HIGH (compromise indicator).
    - JS `location` assignment to a hardcoded external URL → MEDIUM.
    - Page's own URL carries a `redirect=`/`next=`/`goto=`/etc parameter
      that points to an external URL → MEDIUM (open redirect).
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

    def _check_meta_refresh(self, artifacts):
        refresh = artifacts.meta_tags.get("refresh", "")
        if not refresh:
            return []
        m = _META_REFRESH_URL.search(refresh)
        if not m:
            return []
        dest = m.group(1).strip().strip("'\"")
        if not dest:
            return []

        # data:-URI redirect — typically a phishing data-page injection.
        if dest.lower().startswith("data:"):
            return [Finding(
                title="Meta refresh redirects to a data: URI",
                description=(
                    "The page contains "
                    f"`<meta http-equiv='refresh' content='…url={dest[:80]}…'>` "
                    "and the destination is a `data:` URI. data:-URIs let an "
                    "attacker render arbitrary HTML (with arbitrary inline "
                    "JS) without ever loading anything external — bypassing "
                    "every CSP source whitelist that depends on `script-src` "
                    "or `frame-src`. There is essentially no legitimate use "
                    "for a meta-refresh to data:."
                ),
                severity=Severity.HIGH,
                category=FindingCategory.COMPROMISE,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content=f"<meta http-equiv='refresh' content='{refresh[:200]}'>",
                    location=artifacts.url,
                    source_engine=_ENGINE,
                    extra={"destination": dest[:200], "data_uri": True},
                )],
                confidence=0.9,
                remediation=(
                    "Treat the page as compromised: remove the meta tag, "
                    "audit the template / CMS for unauthorised edits, "
                    "rotate credentials. Add `script-src 'self'` and "
                    "block `data:` in `frame-src` and `script-src` in "
                    "your Content Security Policy."
                ),
                framework=_FA["meta_refresh_data_uri"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "destination": dest[:200]},
            )]

        if not dest.startswith("http"):
            return []

        if _is_shortener(dest):
            return [Finding(
                title="Meta refresh redirects through a URL shortener",
                description=(
                    f"The page meta-refreshes to '{dest}', a URL shortener. "
                    "Shorteners hide the real destination — useful for "
                    "marketing tracking, also useful for phishing and "
                    "malware: the visitor never sees the actual landing "
                    "domain until after they've already been redirected. "
                    "On a legitimate site, a shortener in a meta refresh "
                    "usually means a hijacked tracking link."
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
                    "Replace the shortener with the direct destination so "
                    "users can see where the link leads. If the redirect "
                    "is unintentional, remove it and audit recent template "
                    "changes for compromise."
                ),
                framework=_FA["meta_refresh_shortener"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "destination": dest},
            )]

        if _is_external(dest, artifacts.url):
            return [Finding(
                title="Meta refresh sends visitors to a different domain",
                description=(
                    f"The page meta-refreshes to '{dest}' on a different "
                    "host. A meta refresh that takes the user off-site "
                    "is usually intentional (a moved-page redirect), but "
                    "in a compromise it's how attackers funnel traffic "
                    "from a high-reputation host to a phishing or "
                    "malware-loader domain. Confirm the destination is "
                    "expected."
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
                    "If the redirect is expected, replace the meta-refresh "
                    "with a server-side 301/302 — much faster, and "
                    "search-engine friendlier. If unexpected, treat as "
                    "compromise: snapshot the HTML, audit the CMS / "
                    "templates / database for the destination URL, and "
                    "rotate credentials."
                ),
                framework=_FA["meta_refresh_external"],
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "destination": dest},
            )]

        return []

    def _check_js_redirects(self, artifacts):
        findings = []
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
                        title=f"Inline JS redirects to external domain ({dest_host})",
                        description=(
                            f"An inline script sets `location.href`, calls "
                            f"`location.replace(…)`, or `location.assign(…)` "
                            f"with a hardcoded URL on '{dest_host}'. Most "
                            "real apps don't ship hardcoded external "
                            "redirects in inline scripts; this is the "
                            "pattern used by injected malware to bounce "
                            "users to a malicious landing page (often "
                            "geo-targeted, often only firing on certain "
                            "user agents)."
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
                            "Verify the destination is on your approved-"
                            "vendor list. If not, audit the inline scripts "
                            "for injection and check server-side logs for "
                            "the file that holds the redirect. For "
                            "marketing or analytics redirects, use a "
                            "first-party endpoint that does the redirect "
                            "server-side — easier to audit, harder to "
                            "tamper with."
                        ),
                        framework=_FA["js_redirect"],
                        scanner_engine=_ENGINE,
                        metadata={"url": artifacts.url,
                                  "destination_host": dest_host},
                    ))
        return findings

    def _check_open_redirect_params(self, artifacts):
        try:
            parsed = urlparse(artifacts.url)
            params = parse_qs(parsed.query, keep_blank_values=False)
        except Exception:
            return []
        findings = []
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
                    title=f"Open-redirect parameter in page URL ({param_name})",
                    description=(
                        f"The crawled URL itself includes "
                        f"`?{param_name}={value[:80]}…` — a redirect "
                        "parameter pointing to an external domain. Open "
                        "redirects are useful in phishing: a link that "
                        "starts with your real domain reads as trusted to "
                        "users and to email security filters, but after "
                        "the redirect the victim lands on an attacker-"
                        "controlled page. Microsoft, PayPal, and most "
                        "major sites are routinely phished this way."
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
                        "Validate the destination server-side: only "
                        "permit relative paths or absolute URLs that "
                        "match an allowlist of your own domains. Reject "
                        "protocol-relative (`//evil.example`) and "
                        "`javascript:` URLs explicitly. Another option: "
                        "sign the redirect-target value with an HMAC at "
                        "issue-time and verify the signature before "
                        "redirecting."
                    ),
                    framework=_FA["open_redirect_param"],
                    scanner_engine=_ENGINE,
                    metadata={"url": artifacts.url, "param": param_name,
                              "value": value},
                ))
        return findings
