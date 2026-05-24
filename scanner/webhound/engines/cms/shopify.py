# WebHound — scanner/webhound/engines/cms/shopify.py
# Passive Shopify fingerprinting + security checks.
#
# Safe-mode: reads pre-extracted PageArtifacts. No active probing.

from __future__ import annotations

import re

from webhound.core.extractor import PageArtifacts
from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import (
    Exploitability,
    Finding,
    FindingCategory,
    FrameworkAlignment,
)
from webhound.models.severity import Severity

_ENGINE = "shopify"

# Shopify Storefront API access tokens are 32-char hex strings published in
# Liquid templates — they're rate-limited and public-by-design, but exposing
# the *Admin API* token by mistake is a different story. We flag any token
# that looks like an Admin API token (`shpat_…`), which should never appear
# in browser-facing HTML.
_ADMIN_TOKEN_RE = re.compile(r"\bshpat_[a-f0-9]{32}\b", re.I)
_ACCESS_TOKEN_RE = re.compile(r"\bshpss_[a-f0-9]{32}\b", re.I)
# Storefront tokens are public — but we still surface them so the operator
# knows they're being read out of the page (and can rotate if needed).
_STOREFRONT_TOKEN_RE = re.compile(
    r"(?:Shopify\.checkout\.[\w\.]+|X-Shopify-Storefront-Access-Token\s*[:=]\s*['\"]([a-f0-9]{32})['\"])",
    re.I,
)

_FA: dict[str, FrameworkAlignment] = {
    "detected": FrameworkAlignment(
        owasp_top10=["A06:2021"],
        cwe_ids=["CWE-1395"],
        nist_controls=["CM-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.1,
        pci_dss=["12.8.5"],
        iso_27001=["A.5.19", "A.8.8"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.THEORETICAL,
    ),
    "admin_token_leak": FrameworkAlignment(
        owasp_top10=["A02:2021", "A07:2021"],
        cwe_ids=["CWE-798", "CWE-200"],
        nist_controls=["IA-5", "SC-28"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cvss_score=10.0,
        pci_dss=["3.5.1", "8.3.1"],
        iso_27001=["A.5.17", "A.8.24"],
        soc2=["CC6.1"],
        hipaa=[],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "session_token_leak": FrameworkAlignment(
        owasp_top10=["A02:2021", "A07:2021"],
        cwe_ids=["CWE-200", "CWE-522"],
        nist_controls=["IA-5", "SC-28"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.1,
        pci_dss=["3.5.1", "8.3.1"],
        iso_27001=["A.5.17", "A.8.24"],
        soc2=["CC6.1"],
        hipaa=[],
        exploitability=Exploitability.KNOWN_EXPLOITED,
    ),
    "app_inventory": FrameworkAlignment(
        owasp_top10=["A06:2021", "A05:2021"],
        cwe_ids=["CWE-1395"],
        nist_controls=["CM-7", "CM-8"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        cvss_score=3.7,
        pci_dss=["6.3.3", "12.8.5"],
        iso_27001=["A.5.19", "A.8.8"],
        soc2=["CC7.1"],
        hipaa=[],
        exploitability=Exploitability.THEORETICAL,
    ),
}

# Common Shopify-app CDN/script-host patterns used to inventory installed apps.
_APP_SCRIPT_PATTERNS = [
    ("Klaviyo", re.compile(r"static[a-z\-]*\.klaviyo\.com", re.I)),
    ("Yotpo", re.compile(r"staticw2\.yotpo\.com|yotpo\.com/widget", re.I)),
    ("Privy", re.compile(r"privy\.com/widget|privywidget", re.I)),
    ("Loox", re.compile(r"loox\.io/widget", re.I)),
    ("Judge.me", re.compile(r"cdn\.judge\.me", re.I)),
    ("Stamped.io", re.compile(r"stamped\.io/widget", re.I)),
    ("ReCharge", re.compile(r"static\.rechargecdn\.com", re.I)),
    ("Bold", re.compile(r"shappify-cdn\.s3\.amazonaws\.com|cdn\.boldapps\.net", re.I)),
    ("Smile.io", re.compile(r"sdk\.smile\.io", re.I)),
    ("Tapcart", re.compile(r"tapcart\.com", re.I)),
    ("Gorgias", re.compile(r"config\.gorgias\.chat|gorgias\.com", re.I)),
    ("Tidio", re.compile(r"code\.tidio\.co", re.I)),
    ("Shogun", re.compile(r"sgun\.io|getshogun\.com", re.I)),
    ("PageFly", re.compile(r"cdn\.pagefly\.io", re.I)),
]


def _is_shopify(artifacts: PageArtifacts) -> bool:
    h = {k.lower(): v for k, v in artifacts.response_headers.items()}
    meta = {k.lower(): v for k, v in artifacts.meta_tags.items()}
    if "shopify" in meta.get("generator", "").lower():
        return True
    if "x-shopify-stage" in h or "x-shopify-request-id" in h:
        return True
    if any("cdn.shopify.com" in u or "shopifycdn.com" in u
           for u in artifacts.external_script_urls):
        return True
    if any("/cdn/shop/" in u for u in artifacts.all_links):
        return True
    return False


class ShopifyEngine:
    """Passive Shopify fingerprinting and risk surfacing.

    Detects Shopify, scans the page (and provided html_body) for leaked
    Admin API tokens, inventories installed apps by script CDN domain,
    and emits informational guidance on the merchant's app stack.
    """

    NAME = _ENGINE

    def analyze(self, artifacts: PageArtifacts, html_body: str = "") -> list[Finding]:
        if not _is_shopify(artifacts):
            return []

        findings: list[Finding] = []
        page_url = artifacts.url

        findings.append(Finding(
            title="Shopify detected",
            description=(
                "The site is running on Shopify. Shopify handles PCI DSS, "
                "TLS, OS patching, and core platform security for you — your "
                "remaining attack surface is mostly third-party apps, custom "
                "Liquid theme code, and any access tokens published in the "
                "storefront. The findings below cover the things Shopify "
                "itself can't protect you from."
            ),
            severity=Severity.INFO,
            category=FindingCategory.TECHNOLOGY,
            evidence=[Evidence(
                evidence_type=EvidenceType.HEADER,
                content=_detection_evidence_text(artifacts),
                location=page_url,
                source_engine=_ENGINE,
            )],
            confidence=0.95,
            remediation=(
                "Audit the installed app list under Settings → Apps and "
                "remove anything you no longer use — apps retain access "
                "tokens and continue running webhooks even when uninstalled "
                "from the storefront. Review which apps have full read/write "
                "access to customer and order data. Turn on two-factor "
                "authentication for every staff account."
            ),
            framework=_FA["detected"],
            scanner_engine=_ENGINE,
            metadata={"page_url": page_url},
        ))

        # ---- Admin token leak (critical) ----
        # Search the HTML body in addition to inline scripts so multi-line
        # templates and JSON blobs are covered.
        haystack = "\n".join(artifacts.inline_scripts) + "\n" + html_body
        admin_hits = list(_ADMIN_TOKEN_RE.finditer(haystack))
        if admin_hits:
            tokens = [m.group(0) for m in admin_hits[:3]]
            findings.append(Finding(
                title="Shopify Admin API token published in storefront HTML",
                description=(
                    "A token starting with `shpat_` is embedded in the page. "
                    "Admin API tokens grant read/write access to the entire "
                    "store — customer records, orders, fulfilments, "
                    "discounts, inventory, even billing — and they were "
                    "never meant to leave the merchant's server. A token "
                    "leaked like this should be considered compromised the "
                    "moment any visitor (or a search engine crawler) loads "
                    "the page."
                ),
                severity=Severity.CRITICAL,
                category=FindingCategory.CMS,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content="Tokens (masked):\n" + "\n".join(_mask(t) for t in tokens),
                    location=page_url,
                    source_engine=_ENGINE,
                    extra={"hit_count": len(admin_hits)},
                )],
                confidence=0.95,
                remediation=(
                    "Rotate the token immediately: in the Shopify admin, "
                    "find the app that owns it and either uninstall and "
                    "reinstall the app or generate a new access token. "
                    "Then trace how the token reached the storefront — "
                    "usually a developer pasted it into a Liquid template, "
                    "a metafield, or a script tag. Move the integration "
                    "behind a server-side proxy: the browser calls your "
                    "endpoint, and your endpoint calls Shopify with the "
                    "secret. Audit recent order webhooks to confirm no "
                    "abuse occurred while the token was exposed."
                ),
                framework=_FA["admin_token_leak"],
                scanner_engine=_ENGINE,
                metadata={"page_url": page_url, "hit_count": len(admin_hits)},
            ))

        # ---- shpss_ shared-secret leak (also critical) ----
        shared_hits = list(_ACCESS_TOKEN_RE.finditer(haystack))
        if shared_hits:
            tokens = [m.group(0) for m in shared_hits[:3]]
            findings.append(Finding(
                title="Shopify shared-secret token (shpss_) leaked in storefront",
                description=(
                    "A token starting with `shpss_` is embedded in the page. "
                    "These are app-shared secrets used to verify webhook "
                    "signatures, and they belong on the merchant's backend. "
                    "Publishing one in the storefront lets an attacker forge "
                    "webhook calls to whatever endpoint expects them, "
                    "potentially triggering fulfilment, refund, or "
                    "discount-issuing logic."
                ),
                severity=Severity.CRITICAL,
                category=FindingCategory.CMS,
                evidence=[Evidence(
                    evidence_type=EvidenceType.HTML_ELEMENT,
                    content="Tokens (masked):\n" + "\n".join(_mask(t) for t in tokens),
                    location=page_url,
                    source_engine=_ENGINE,
                )],
                confidence=0.95,
                remediation=(
                    "Rotate the shared secret in the partner dashboard or "
                    "via the app's settings. Trace the leak source (Liquid "
                    "template, environment variable accidentally inlined "
                    "into a script tag, etc) and move secret handling to "
                    "the backend."
                ),
                framework=_FA["session_token_leak"],
                scanner_engine=_ENGINE,
                metadata={"page_url": page_url},
            ))

        # ---- Installed-app inventory ----
        apps = _detect_apps(artifacts)
        if apps:
            findings.append(Finding(
                title=f"Shopify third-party apps detected ({len(apps)})",
                description=(
                    f"Script tags identify {len(apps)} third-party Shopify apps "
                    f"loading client-side code: {', '.join(apps)}. Each app's "
                    "JavaScript runs with full access to the page — checkout "
                    "fields, cart contents, customer-facing forms — so a "
                    "compromise of any single app vendor would let an "
                    "attacker inject a card-skimmer into your checkout. "
                    "This is informational; the goal is awareness, not "
                    "removal. Most stores legitimately run 10+ apps."
                ),
                severity=Severity.INFO,
                category=FindingCategory.TECHNOLOGY,
                evidence=[Evidence(
                    evidence_type=EvidenceType.RAW,
                    content="Apps detected:\n" + "\n".join(apps),
                    location=page_url,
                    source_engine=_ENGINE,
                    extra={"apps": apps},
                )],
                confidence=0.85,
                remediation=(
                    "Maintain a written inventory of every app and what data "
                    "it accesses. Quarterly: prune apps you no longer use, "
                    "review each survivor's permission scope, and confirm "
                    "the vendor is still active (abandoned apps are a common "
                    "supply-chain vector). For checkout-facing apps "
                    "specifically, follow Shopify's Checkout Extensibility "
                    "model rather than legacy script-tag injection — it "
                    "isolates app code from the payment form."
                ),
                framework=_FA["app_inventory"],
                scanner_engine=_ENGINE,
                metadata={"page_url": page_url, "apps": apps},
            ))

        return findings


def _detection_evidence_text(artifacts: PageArtifacts) -> str:
    h = {k.lower(): v for k, v in artifacts.response_headers.items()}
    meta = {k.lower(): v for k, v in artifacts.meta_tags.items()}
    bits: list[str] = []
    if "shopify" in meta.get("generator", "").lower():
        bits.append(f'meta generator="{meta["generator"]}"')
    for key in ("x-shopify-stage", "x-shopify-request-id"):
        if key in h:
            bits.append(f"{key}: {h[key]}")
    cdn = [u for u in artifacts.external_script_urls
           if "cdn.shopify.com" in u or "shopifycdn.com" in u][:2]
    if cdn:
        bits.append("CDN: " + ", ".join(cdn))
    return "\n".join(bits) or "(Shopify markers detected)"


def _detect_apps(artifacts: PageArtifacts) -> list[str]:
    found: list[str] = []
    haystack = " ".join(artifacts.external_script_urls)
    for name, pattern in _APP_SCRIPT_PATTERNS:
        if pattern.search(haystack):
            found.append(name)
    return found


def _mask(token: str) -> str:
    if len(token) <= 8:
        return "*" * len(token)
    return token[:6] + "*" * (len(token) - 10) + token[-4:]
