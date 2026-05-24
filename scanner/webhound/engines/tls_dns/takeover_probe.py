# WebHound — scanner/webhound/engines/tls_dns/takeover_probe.py
# Active subdomain-takeover detection.
#
# The passive DNS check in dns_checker.py catches the NXDOMAIN case — a CNAME
# that points at a vendor service domain where the underlying name no longer
# resolves. But many vendors return an HTTP 404 (or a custom error page)
# instead of failing DNS resolution; their orphan-app pages are perfectly
# resolvable. The active path below confirms a takeover candidate by GETting
# the CNAME tail and matching the response body against published vendor
# fingerprints.
#
# Detection is conservative: a finding only fires when a fingerprint clearly
# indicates the underlying resource is unclaimed and re-registerable. Random
# 404 pages on unrelated CDNs do NOT fire.

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from webhound.models.evidence import Evidence, EvidenceType
from webhound.models.finding import Exploitability, Finding, FindingCategory, FrameworkAlignment
from webhound.models.severity import Severity

if TYPE_CHECKING:
    from webhound.core.http_client import SafeHttpClient

_ENGINE = "takeover_probe"


@dataclass(frozen=True)
class _Fingerprint:
    vendor: str        # Friendly vendor name
    suffix: str        # CNAME suffix that triggers the active probe
    body_signal: str   # Substring in the HTTP response that indicates orphan state
    status_match: tuple[int, ...] = (200, 404)  # HTTP statuses we trust as decisive


# Curated fingerprints, sourced from public take-over research (EdOverflow's
# can-i-take-over-xyz, Project Discovery's nuclei templates). Conservative —
# we'd rather miss a takeover than fire on a generic 404 page.
_FINGERPRINTS: tuple[_Fingerprint, ...] = (
    _Fingerprint("GitHub Pages",     ".github.io",
                 "There isn't a GitHub Pages site here."),
    _Fingerprint("Heroku",           ".herokuapp.com",
                 "No such app"),
    _Fingerprint("Heroku",           ".herokudns.com",
                 "No such app"),
    _Fingerprint("AWS S3",           ".s3.amazonaws.com",
                 "NoSuchBucket"),
    _Fingerprint("AWS S3",           ".s3-website",
                 "NoSuchBucket"),
    _Fingerprint("AWS CloudFront",   ".cloudfront.net",
                 "The request could not be satisfied."),
    _Fingerprint("Azure App Service",".azurewebsites.net",
                 "Error 404 - Web app not found"),
    _Fingerprint("Azure Traffic Manager", ".trafficmanager.net",
                 "Page not found"),
    _Fingerprint("Pantheon",         ".pantheonsite.io",
                 "The gods are wise"),
    _Fingerprint("Shopify",          ".myshopify.com",
                 "Sorry, this shop is currently unavailable."),
    _Fingerprint("Tumblr",           ".tumblr.com",
                 "There's nothing here."),
    _Fingerprint("WordPress.com",    ".wordpress.com",
                 "Do you want to register"),
    _Fingerprint("Surge.sh",         ".surge.sh",
                 "project not found"),
    _Fingerprint("Netlify",          ".netlify.app",
                 "Not Found - Request ID"),
    _Fingerprint("Netlify",          ".netlify.com",
                 "Not Found - Request ID"),
    _Fingerprint("Vercel",           ".vercel.app",
                 "The deployment could not be found"),
    _Fingerprint("Read the Docs",    ".readthedocs.io",
                 "unknown to Read the Docs"),
    _Fingerprint("Helpjuice",        ".helpjuice.com",
                 "We could not find what you're looking for."),
    _Fingerprint("Help Scout Docs",  ".helpscoutdocs.com",
                 "No settings were found for this company"),
    _Fingerprint("UserVoice",        ".uservoice.com",
                 "This UserVoice subdomain is currently available!"),
    _Fingerprint("Zendesk",          ".zendesk.com",
                 "Help Center Closed"),
    _Fingerprint("Freshdesk",        ".freshdesk.com",
                 "May be this is still fresh!"),
    _Fingerprint("Campaign Monitor", ".campaignmonitor.com",
                 "Trying to access your account?"),
    _Fingerprint("Tilda",            ".tilda.ws",
                 "Please renew your subscription"),
    _Fingerprint("Strikingly",       ".strikinglydns.com",
                 "PAGE NOT FOUND."),
    _Fingerprint("Webflow",          ".webflow.io",
                 "The page you are looking for doesn't exist or has been moved."),
)


class TakeoverProbeEngine:
    """Confirms subdomain-takeover candidates with an active HTTP probe.

    Usage::

        async with SafeHttpClient(opts) as client:
            engine = TakeoverProbeEngine(client)
            findings = await engine.probe(domain, cname_chain)

    `cname_chain` is the resolved CNAME hops for `domain`, ordered. The
    engine inspects the last hop (the "tail") and, if it matches a
    fingerprinted vendor suffix, fetches both http:// and https:// variants
    and looks for the published orphan signal in the response body.
    """

    NAME = _ENGINE

    def __init__(self, client: "SafeHttpClient") -> None:
        self._client = client

    async def probe(self, domain: str, cname_chain: list[str]) -> list[Finding]:
        if not cname_chain:
            return []
        tail = cname_chain[-1].rstrip(".").lower()
        fingerprint = self._match(tail)
        if fingerprint is None:
            return []
        # Probe both schemes. Vendors that respond on one but not the other
        # still count if the orphan signal appears.
        results = await asyncio.gather(
            self._fetch_signal(domain, "https", fingerprint),
            self._fetch_signal(domain, "http",  fingerprint),
            return_exceptions=False,
        )
        signal = next((r for r in results if r is not None), None)
        if signal is None:
            return []
        body_excerpt, fetched_url, status = signal
        return [self._build(domain, tail, fingerprint, body_excerpt, fetched_url, status)]

    def _match(self, hostname: str) -> _Fingerprint | None:
        for fp in _FINGERPRINTS:
            if hostname.endswith(fp.suffix):
                return fp
        return None

    async def _fetch_signal(
        self, domain: str, scheme: str, fp: _Fingerprint
    ) -> tuple[str, str, int] | None:
        url = f"{scheme}://{domain}/"
        try:
            response = await self._client.get(url)
        except Exception:
            return None
        if response.failed:
            return None
        if response.status_code not in fp.status_match and response.status_code != 200 and response.status_code != 404:
            return None
        body = response.body or ""
        if fp.body_signal not in body:
            return None
        # Truncated body excerpt around the signal for evidence.
        idx = body.find(fp.body_signal)
        start = max(0, idx - 80)
        end = min(len(body), idx + len(fp.body_signal) + 80)
        excerpt = body[start:end].strip()
        return excerpt, response.url, response.status_code

    def _build(
        self,
        domain: str,
        tail: str,
        fp: _Fingerprint,
        body_excerpt: str,
        fetched_url: str,
        status: int,
    ) -> Finding:
        ev = Evidence(
            evidence_type=EvidenceType.HTTP_RESPONSE,
            content=(
                f"GET {fetched_url} (HTTP {status})\n"
                f"Vendor fingerprint matched: {fp.vendor}\n"
                f"Body excerpt:\n{body_excerpt}"
            ),
            location=fetched_url,
            source_engine=_ENGINE,
            extra={
                "vendor": fp.vendor,
                "vendor_suffix": fp.suffix,
                "signal": fp.body_signal,
                "cname_tail": tail,
                "fetched_url": fetched_url,
                "http_status": status,
            },
        )
        return Finding(
            title=f"Subdomain takeover CONFIRMED: {domain} -> {fp.vendor} orphan",
            description=(
                f"`{domain}` has a CNAME pointing at `{tail}` (a {fp.vendor} "
                f"service domain). When WebHound fetched the URL, the response "
                f"contained {fp.vendor}'s published 'unclaimed resource' "
                "fingerprint — meaning the app / bucket / page on the vendor "
                "side no longer exists. An attacker who registers the same "
                f"name on {fp.vendor} immediately receives all traffic to "
                f"`{domain}`, served under your domain's TLS via the vendor's "
                "edge. This is one of the highest-impact misconfigurations "
                "we detect."
            ),
            severity=Severity.CRITICAL,
            category=FindingCategory.DNS,
            evidence=[ev],
            confidence=0.97,  # active probe + vendor-specific signal
            remediation=(
                f"Treat this as urgent. Either:\n"
                f"  1. Re-provision the resource on {fp.vendor} so the CNAME "
                f"     target exists again under your control, OR\n"
                f"  2. Delete the orphan CNAME at your DNS provider "
                f"     (`{domain}` → CNAME → `{tail}`).\n"
                "Until one of those happens, anyone monitoring CNAME chains "
                "can claim the resource within hours — automated tooling "
                "already does."
            ),
            framework=FrameworkAlignment(
                owasp_top10=["A05:2021"],
                cwe_ids=["CWE-350", "CWE-285"],
                nist_controls=["SC-20", "CM-7"],
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cvss_score=10.0,
                pci_dss=["6.4.2", "11.5.1"],
                iso_27001=["A.5.14", "A.8.9"],
                soc2=["CC7.1"],
                exploitability=Exploitability.KNOWN_EXPLOITED,
            ),
            scanner_engine=_ENGINE,
            metadata={
                "url": fetched_url,
                "domain": domain,
                "vendor": fp.vendor,
                "cname_tail": tail,
            },
        )
