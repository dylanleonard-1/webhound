# WebHound — scanner/webhound/engines/javascript/third_party_domains.py
# Passive analysis of third-party domains referenced by a page.
#
# Safe-mode: reads pre-extracted PageArtifacts only.
# No DNS lookups, no HTTP fetches, no active probing.

from __future__ import annotations

import re
from urllib.parse import urlparse

import tldextract

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

_ENGINE = "third_party_domains"

# ---------------------------------------------------------------------------
# Domain categorization
# ---------------------------------------------------------------------------

_DOMAIN_CATEGORY: dict[str, str] = {
    # CDN
    "cloudflare.com": "CDN", "cloudflare.net": "CDN",
    "cloudfront.net": "CDN", "fastly.net": "CDN", "fastly.com": "CDN",
    "akamaized.net": "CDN", "akamai.com": "CDN", "akamaihd.net": "CDN",
    "jsdelivr.net": "CDN", "unpkg.com": "CDN", "bootstrapcdn.com": "CDN",
    "googleapis.com": "CDN", "gstatic.com": "CDN", "googleusercontent.com": "CDN",
    "jquery.com": "CDN", "jquery.org": "CDN", "amazonaws.com": "CDN",
    "typekit.net": "CDN", "adobe.com": "CDN", "fonts.com": "CDN",
    "github.io": "CDN", "github.com": "CDN", "githubusercontent.com": "CDN",
    # Analytics
    "google-analytics.com": "Analytics", "googletagmanager.com": "Analytics",
    "googleadservices.com": "Analytics", "googlesyndication.com": "Analytics",
    "doubleclick.net": "Analytics", "hotjar.com": "Analytics",
    "mixpanel.com": "Analytics", "amplitude.com": "Analytics",
    "heap.io": "Analytics", "fullstory.com": "Analytics",
    "logrocket.com": "Analytics", "segment.io": "Analytics", "segment.com": "Analytics",
    # Tracking / Advertising
    "facebook.net": "Tracking", "facebook.com": "Tracking", "fbcdn.net": "Tracking",
    "twitter.com": "Tracking", "twimg.com": "Tracking",
    "pinterest.com": "Tracking", "tiktok.com": "Tracking", "addthis.com": "Tracking",
    # Payments
    "stripe.com": "Payments", "stripe.network": "Payments",
    "paypal.com": "Payments", "paypalobjects.com": "Payments",
    "braintreegateway.com": "Payments",
    "square.com": "Payments", "squareup.com": "Payments",
    # Marketing
    "mailchimp.com": "Marketing", "chimpstatic.com": "Marketing",
    "hubspot.com": "Marketing", "hs-scripts.com": "Marketing", "hsforms.com": "Marketing",
    "klaviyo.com": "Marketing", "constantcontact.com": "Marketing",
    "sendgrid.com": "Marketing",
    # Monitoring / Error Tracking
    "sentry.io": "Monitoring", "newrelic.com": "Monitoring", "nr-data.net": "Monitoring",
    "datadog-browser-agent.com": "Monitoring",
    # Support / Chat
    "intercomcdn.com": "Support", "intercom.io": "Support",
    "zendesk.com": "Support", "zopim.com": "Support",
    "freshworks.com": "Support", "tawk.to": "Support",
    # Social / Media
    "instagram.com": "Social", "linkedin.com": "Social", "licdn.com": "Social",
    "youtube.com": "Video", "ytimg.com": "Video",
    "vimeo.com": "Video", "vimeocdn.com": "Video",
    "wistia.com": "Video", "wistia.net": "Video",
    "brightcove.net": "Video", "brightcove.com": "Video",
    # Security / Auth
    "recaptcha.net": "Security", "hcaptcha.com": "Security", "captcha.net": "Security",
    "disqus.com": "Community", "disquscdn.com": "Community",
    "mapbox.com": "Maps", "openstreetmap.org": "Maps",
}


def _get_category(registered: str) -> str:
    """Return a human-readable category label for a registered domain."""
    return _DOMAIN_CATEGORY.get(registered, "Unknown")


# TLDs frequently associated with free/disposable domains or abuse infrastructure.
_RISKY_TLDS: frozenset[str] = frozenset({
    "tk", "ml", "ga", "cf", "gq",   # Freenom free TLDs, high abuse rate
    "xyz", "top", "win", "date", "review", "racing", "stream",
    "download", "click", "link", "online", "site", "website",
    "cc", "pw", "su",
})

# Registered domains (domain.suffix) that are well-known CDNs or trusted platforms.
# Scripts from these domains are common and not flagged as suspicious.
_TRUSTED_DOMAINS: frozenset[str] = frozenset({
    # Google
    "googleapis.com", "gstatic.com", "googletagmanager.com",
    "google-analytics.com", "google.com", "googleadservices.com",
    "googlesyndication.com", "googleusercontent.com",
    # CDNs
    "cloudflare.com", "cloudflare.net",
    "jsdelivr.net", "unpkg.com",
    "bootstrapcdn.com",
    "jquery.com", "jquery.org",
    "cloudfront.net",
    "fastly.net", "fastly.com",
    "akamaized.net", "akamai.com", "akamaihd.net",
    "amazonaws.com",
    # Social
    "facebook.net", "facebook.com", "fbcdn.net",
    "twitter.com", "twimg.com",
    "linkedin.com", "licdn.com",
    "instagram.com",
    "pinterest.com",
    "tiktok.com",
    # Dev / code hosting
    "github.io", "github.com", "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    # Analytics / monitoring
    "hotjar.com",
    "segment.io", "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "heap.io",
    "fullstory.com",
    "logrocket.com",
    "newrelic.com", "nr-data.net",
    "datadog-browser-agent.com",
    "sentry.io",
    # Support / chat
    "intercomcdn.com", "intercom.io",
    "zendesk.com", "zopim.com",
    "freshworks.com",
    "tawk.to",
    # Payments
    "stripe.com", "stripe.network",
    "paypal.com", "paypalobjects.com",
    "braintreegateway.com",
    "square.com", "squareup.com",
    # E-commerce platforms
    "shopify.com", "cdn.shopify.com", "myshopify.com", "shopifycdn.com",
    "bigcommerce.com",
    "ecwid.com",
    # Website builders
    "squarespace.com", "squarespace-cdn.com", "sqspcdn.com",
    "wix.com", "wixstatic.com",
    "webflow.com", "webflow.io",
    "wordpress.com", "wp.com",
    # Email marketing
    "mailchimp.com", "chimpstatic.com",
    "hubspot.com", "hs-scripts.com", "hsforms.com",
    "klaviyo.com",
    "constantcontact.com",
    "sendgrid.com",
    # Fonts / assets
    "typekit.net", "adobe.com", "fonts.com",
    # Media / video
    "vimeo.com", "vimeocdn.com",
    "youtube.com", "ytimg.com",
    "wistia.com", "wistia.net",
    "brightcove.net", "brightcove.com",
    # Maps
    "mapbox.com",
    "openstreetmap.org",
    # Misc trusted
    "addthis.com",
    "disqus.com", "disquscdn.com",
    "captcha.net", "recaptcha.net",
    "hcaptcha.com",
})

# Heuristic: domain name with very few vowels looks machine-generated.
_VOWELS: frozenset[str] = frozenset("aeiouAEIOU")
_RANDOM_DOMAIN_MIN_LEN = 8
_RANDOM_DOMAIN_VOWEL_THRESHOLD = 0.12


class ThirdPartyDomainEngine:
    """Passive analysis of third-party resource domains referenced by a page.

    Checks external script src domains and external form action domains.
    Call ``analyze(artifacts)`` to receive a list of findings.
    Safe-mode: no network activity.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        page_host = urlparse(artifacts.url).hostname or ""

        findings.extend(self._check_script_domains(artifacts, page_host))
        findings.extend(self._check_form_action_domains(artifacts, page_host))
        findings.extend(self._check_iframe_domains(artifacts))
        findings.extend(self._check_stylesheet_domains(artifacts))
        findings.extend(self._check_js_request_domains(artifacts))

        return findings

    # ------------------------------------------------------------------
    # External script domains
    # ------------------------------------------------------------------

    def _check_script_domains(
        self, artifacts: PageArtifacts, page_host: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_domains: set[str] = set()

        for script in artifacts.scripts:
            if not script.is_external or not script.src or not script.is_external_domain:
                continue
            host = urlparse(script.src).hostname or ""
            registered = _registered_domain(host)
            if not registered or registered in seen_domains:
                continue
            seen_domains.add(registered)

            if _is_trusted(registered):
                continue

            severity, label = _domain_risk(host, registered)
            ev = Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=f"External script from {host}: {script.src}",
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"domain": host, "script_src": script.src},
            )
            findings.append(Finding(
                title=f"Your site loads a script from {host} ({label})",
                description=(
                    f"Your page pulls in JavaScript from `{host}`. Once that script "
                    "runs on your page, it has the same privileges your own code does "
                    "— it can read forms, modify the DOM, steal cookies, and talk to "
                    "any domain. If the third party gets compromised (or always was "
                    "malicious), your visitors are the victims."
                ),
                severity=severity,
                category=FindingCategory.JAVASCRIPT,
                evidence=[ev],
                confidence=0.7,
                remediation=(
                    "Audit every external script your page loads. For each one, add "
                    "a Subresource Integrity (SRI) hash so the browser refuses to "
                    "run a tampered version:\n"
                    f"  <script src=\"https://{host}/...\" integrity=\"sha384-...\" crossorigin=\"anonymous\"></script>\n"
                    "For anything you can self-host, do that instead of trusting the "
                    "third party indefinitely."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A08:2021"],
                    cwe_ids=["CWE-829"],
                    nist_controls=["SI-10", "SA-12"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "domain": host},
            ))

        return findings

    # ------------------------------------------------------------------
    # External form action domains
    # ------------------------------------------------------------------

    def _check_form_action_domains(
        self, artifacts: PageArtifacts, page_host: str
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen_domains: set[str] = set()

        for form in artifacts.forms:
            if not form.action_url:
                continue
            action_host = urlparse(form.action_url).hostname or ""
            if not action_host or action_host == page_host:
                continue
            registered = _registered_domain(action_host)
            if not registered or registered in seen_domains:
                continue
            seen_domains.add(registered)

            ev = Evidence(
                evidence_type=EvidenceType.HTML_ELEMENT,
                content=(
                    f"Form action points to external domain '{action_host}': "
                    f"{form.action_url}"
                ),
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"domain": action_host, "action_url": form.action_url},
            )
            findings.append(Finding(
                title=f"A form on this page posts to {action_host}",
                description=(
                    f"One of the forms on this page submits to `{action_host}` "
                    "instead of your own domain. Anything the visitor types — "
                    "name, email, password, payment details — gets sent to that "
                    "third party. Sometimes this is intentional (a payment "
                    "processor); sometimes it's how form hijacking attackers "
                    "exfiltrate credentials."
                ),
                severity=Severity.MEDIUM,
                category=FindingCategory.JAVASCRIPT,
                evidence=[ev],
                confidence=0.75,
                remediation=(
                    "Confirm the destination is a service you intentionally use "
                    "(Stripe, PayPal, HubSpot forms, etc). If not, search your "
                    "templates for the action URL and remove it. Always require "
                    "HTTPS on form destinations that handle sensitive data."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A08:2021"],
                    cwe_ids=["CWE-829"],
                    nist_controls=["SI-10"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "domain": action_host},
            ))

        return findings


    # ------------------------------------------------------------------
    # External visible iframes (hidden iframes handled by compromise engine)
    # ------------------------------------------------------------------

    def _check_iframe_domains(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        seen_domains: set[str] = set()

        for iframe in artifacts.iframes:
            if iframe.is_hidden or not iframe.is_external_domain or not iframe.src_url:
                continue
            host = urlparse(iframe.src_url).hostname or ""
            registered = _registered_domain(host)
            if not registered or registered in seen_domains:
                continue
            seen_domains.add(registered)
            if _is_trusted(registered):
                continue

            category = _get_category(registered)
            ev = Evidence(
                evidence_type=EvidenceType.HTML_ELEMENT,
                content=f"Cross-domain iframe src: {iframe.src_url}",
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"domain": host, "iframe_src": iframe.src_url, "category": category},
            )
            findings.append(Finding(
                title=f"External iframe from {host} ({category})",
                description=(
                    f"An <iframe> embeds content from '{host}', a third-party domain. "
                    "External iframes load full pages from another origin and can include "
                    "tracking pixels, ads, or unexpected content changes."
                ),
                severity=Severity.LOW,
                category=FindingCategory.JAVASCRIPT,
                evidence=[ev],
                confidence=0.65,
                remediation=(
                    "Verify all cross-domain iframes are from intended, trusted sources. "
                    "Apply a CSP frame-src directive and use the sandbox attribute to "
                    "restrict iframe capabilities."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A08:2021"],
                    cwe_ids=["CWE-829"],
                    nist_controls=["SI-10"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "domain": host},
            ))

        return findings

    # ------------------------------------------------------------------
    # External stylesheet domains
    # ------------------------------------------------------------------

    def _check_stylesheet_domains(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        seen_domains: set[str] = set()

        all_css_urls = list(artifacts.external_stylesheet_urls) + list(artifacts.inline_css_import_urls)
        for url in all_css_urls:
            host = urlparse(url).hostname or ""
            registered = _registered_domain(host)
            if not registered or registered in seen_domains:
                continue
            seen_domains.add(registered)
            if _is_trusted(registered):
                continue

            category = _get_category(registered)
            ev = Evidence(
                evidence_type=EvidenceType.HTML_ELEMENT,
                content=f"External stylesheet: {url}",
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"domain": host, "stylesheet_url": url, "category": category},
            )
            findings.append(Finding(
                title=f"External stylesheet loaded from {host} ({category})",
                description=(
                    f"A CSS stylesheet is loaded from '{host}', a third-party domain. "
                    "External stylesheets can introduce CSS injection risks, load "
                    "additional resources (fonts, images), and enable cross-site tracking."
                ),
                severity=Severity.LOW,
                category=FindingCategory.JAVASCRIPT,
                evidence=[ev],
                confidence=0.65,
                remediation=(
                    "Apply Subresource Integrity (SRI) hashes to external stylesheets. "
                    "Host critical CSS on your own infrastructure. "
                    "Restrict with CSP style-src."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A08:2021"],
                    cwe_ids=["CWE-829"],
                    nist_controls=["SI-10", "SA-12"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "domain": host},
            ))

        return findings

    # ------------------------------------------------------------------
    # Fetch / XHR / WebSocket request destinations from inline scripts
    # ------------------------------------------------------------------

    def _check_js_request_domains(self, artifacts: PageArtifacts) -> list[Finding]:
        findings: list[Finding] = []
        seen_domains: set[str] = set()
        page_host = urlparse(artifacts.url).hostname or ""

        for url in artifacts.inline_js_request_urls:
            host = urlparse(url).hostname or ""
            if not host or host == page_host:
                continue
            registered = _registered_domain(host)
            if not registered or registered in seen_domains:
                continue
            seen_domains.add(registered)
            if _is_trusted(registered):
                continue

            category = _get_category(registered)
            is_ws = url.startswith(("wss://", "ws://"))
            kind = "WebSocket connection" if is_ws else "fetch/XHR request"
            ev = Evidence(
                evidence_type=EvidenceType.JAVASCRIPT,
                content=f"Inline JS {kind} to: {url}",
                location=artifacts.url,
                source_engine=_ENGINE,
                extra={"domain": host, "request_url": url, "type": kind, "category": category},
            )
            findings.append(Finding(
                title=f"Inline JS {kind} to external domain {host} ({category})",
                description=(
                    f"Inline script makes a {kind} to '{host}', a third-party domain. "
                    "External API calls can send page data, user behaviour, or session "
                    "identifiers to third parties."
                ),
                severity=Severity.LOW,
                category=FindingCategory.JAVASCRIPT,
                evidence=[ev],
                confidence=0.70,
                remediation=(
                    "Verify all external API destinations are intentional and documented. "
                    "Restrict outbound connections using CSP connect-src. "
                    "Review data sent in each request for PII or sensitive information."
                ),
                framework=FrameworkAlignment(
                    owasp_top10=["A08:2021"],
                    cwe_ids=["CWE-829"],
                    nist_controls=["SI-10", "SC-8"],
                ),
                scanner_engine=_ENGINE,
                metadata={"url": artifacts.url, "domain": host},
            ))

        return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _registered_domain(hostname: str) -> str | None:
    """Return 'domain.suffix' (e.g., 'cloudflare.com') for a hostname."""
    if not hostname:
        return None
    ext = tldextract.extract(hostname)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


def _is_trusted(registered: str) -> bool:
    return registered in _TRUSTED_DOMAINS


def _looks_random(hostname: str) -> bool:
    """Heuristic: hostname with very few vowels is likely machine-generated."""
    ext = tldextract.extract(hostname)
    name = ext.domain
    if not name or len(name) < _RANDOM_DOMAIN_MIN_LEN:
        return False
    vowel_count = sum(1 for c in name if c in _VOWELS)
    return (vowel_count / len(name)) < _RANDOM_DOMAIN_VOWEL_THRESHOLD


def _domain_risk(hostname: str, registered: str) -> tuple[Severity, str]:
    """Return (severity, label) for a third-party domain based on risk indicators."""
    ext = tldextract.extract(hostname)
    tld = ext.suffix.lower() if ext.suffix else ""

    if tld in _RISKY_TLDS:
        return Severity.MEDIUM, "risky TLD"
    if _looks_random(hostname):
        return Severity.MEDIUM, "random-looking domain"
    return Severity.LOW, "unknown third party"
