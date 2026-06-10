# WebHound — scanner/webhound/recon/provider_discovery.py
# Phase 3.1 — Provider Discovery Foundation.
#
# Detect the provider stack (registrar / dns / hosting / cdn / waf / cms /
# framework) for a domain BEFORE scanning, so limited coverage is explained up
# front instead of discovered mid-scan.
#
# REUSE-FIRST, DETECTION-ONLY. This module runs NO new detection of its own —
# it composes existing detectors and maps their output into a ProviderProfile:
#   * TechnologyEngine                         CDN/WAF/CMS/framework (headers/meta/scripts)
#   * challenge_detection._PROVIDER_SIGNATURES provider URL/HTML signatures (adds Vercel/Netlify)
#   * dns_checker.resolve_dns().ns             nameserver → DNS provider
# It NEVER changes scanner findings or scoring. Registrar + deep hosting
# (WHOIS / RDAP / IP-ASN) are deferred — returned as None with extension points.
#
# FOLLOW-UP (deferred — see the Phase-3.1 architecture audit): extract
# TechnologyEngine's inline header/meta/script signatures into a shared
# signature module consumed by BOTH the in-scan engine and this pass. For the
# foundation we consume TechnologyEngine's Findings as a black box (zero change
# to technology.py); the scanner unit test runs the REAL engine so any
# Finding-title drift breaks the test rather than silently breaking discovery.

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from webhound.browser.challenge_detection import _PROVIDER_SIGNATURES
from webhound.core.extractor import Extractor
from webhound.core.http_client import SafeHttpClient
from webhound.engines.recon.technology import TechnologyEngine
from webhound.engines.tls_dns.dns_checker import resolve_dns
from webhound.models.finding import FindingCategory
from webhound.models.target import ScanOptions

logger = logging.getLogger(__name__)

# Lifecycle event names — emitted via an optional callback. The API layer logs
# them; the durable record is the persisted ProviderProfile (detected_at).
EVENT_STARTED = "provider.discovery.started"
EVENT_COMPLETED = "provider.discovery.completed"
EVENT_DETECTED = "provider.detected"
EVENT_FAILED = "provider.discovery.failed"

EventSink = Callable[[str, dict[str, Any]], None]

# --- Attribution maps (NOT detection — detection lives in the reused engines) -

# TechnologyEngine Finding title substring -> (profile fields, canonical name).
# One title can set both cdn and waf (e.g. Cloudflare). Matched case-folded
# against Findings whose category == TECHNOLOGY only.
_FINDING_TITLE_MAP: list[tuple[str, tuple[str, ...], str]] = [
    ("cloudflare cdn/waf",      ("cdn_provider", "waf_provider"), "Cloudflare"),
    ("aws cloudfront cdn",      ("cdn_provider",),                "AWS CloudFront"),
    ("aws load balancer / waf", ("waf_provider",),                "AWS WAF/ELB"),
    ("akamai cdn/waf",          ("cdn_provider", "waf_provider"), "Akamai"),
    ("fastly cdn",              ("cdn_provider",),                "Fastly"),
    ("sucuri waf",              ("waf_provider",),                "Sucuri"),
    ("imperva/incapsula waf",   ("waf_provider",),                "Imperva"),
    ("barracuda waf",           ("waf_provider",),                "Barracuda"),
    ("modsecurity waf",         ("waf_provider",),                "ModSecurity"),
    ("f5 big-ip",               ("waf_provider",),                "F5 BIG-IP"),
    ("wordpress",               ("cms",),                         "WordPress"),
    ("shopify",                 ("cms",),                         "Shopify"),
    ("wix",                     ("cms",),                         "Wix"),
    ("drupal",                  ("cms",),                         "Drupal"),
    ("joomla",                  ("cms",),                         "Joomla"),
]

# challenge_detection provider key -> (fields, canonical name). Lets us reuse
# its URL/HTML signatures to attribute providers (esp. Vercel/Netlify) that the
# TechnologyEngine header pass does not cover.
_CHALLENGE_PROVIDER_MAP: dict[str, tuple[tuple[str, ...], str]] = {
    "cloudflare": (("cdn_provider", "waf_provider"), "Cloudflare"),
    "vercel":     (("cdn_provider",),                "Vercel"),
    "akamai":     (("cdn_provider", "waf_provider"), "Akamai"),
    "fastly":     (("cdn_provider",),                "Fastly"),
    "aws_waf":    (("waf_provider",),                "AWS WAF"),
    "netlify":    (("cdn_provider",),                "Netlify"),
}

# Nameserver substring -> DNS provider, over the NS records dns_checker collects.
_NS_PROVIDER_MAP: list[tuple[str, str]] = [
    ("cloudflare",            "Cloudflare"),
    ("awsdns",                "AWS Route 53"),
    ("azure-dns",             "Azure DNS"),
    ("googledomains",         "Google Cloud DNS"),
    ("domaincontrol.com",     "GoDaddy"),
    ("registrar-servers.com", "Namecheap"),
    ("dnsimple",              "DNSimple"),
    ("nsone.net",             "NS1"),
    ("dnsmadeeasy",           "DNS Made Easy"),
    ("akam.net",              "Akamai"),
    ("ultradns",              "UltraDNS"),
    ("vercel-dns",            "Vercel"),
    ("squarespacedns",        "Squarespace"),
    ("wixdns",                "Wix"),
]

# Hosting provider best-effort from response headers (deep IP/ASN deferred).
# (header-name, value-substring or "" for presence) -> hosting provider.
_HOSTING_HEADER_MAP: list[tuple[str, str, str]] = [
    ("x-vercel-id",      "",          "Vercel"),
    ("server",           "vercel",    "Vercel"),
    ("x-nf-request-id",  "",          "Netlify"),
    ("server",           "netlify",   "Netlify"),
    ("server",           "github.com", "GitHub Pages"),
    ("x-amzn-requestid", "",          "AWS"),
    ("server",           "amazons3",  "AWS S3"),
    ("x-render-origin",  "",          "Render"),
    ("server",           "railway",   "Railway"),
    ("fly-request-id",   "",          "Fly.io"),
]

# Non-HTML fallback for CDN/WAF — mirrors the strongest header signatures in
# technology.py for the rare case where there is no HTML body to extract (e.g.
# a hard 403/JSON). The primary path is TechnologyEngine on real artifacts.
# (header-name, value-substring or "") -> (fields, canonical name).
_HEADER_CDNWAF_FALLBACK: list[tuple[str, str, tuple[str, ...], str]] = [
    ("cf-ray",            "", ("cdn_provider", "waf_provider"), "Cloudflare"),
    ("x-amz-cf-id",       "", ("cdn_provider",),                "AWS CloudFront"),
    ("x-fastly-request-id", "", ("cdn_provider",),              "Fastly"),
    ("x-sucuri-id",       "", ("waf_provider",),                "Sucuri"),
    ("x-iinfo",           "", ("waf_provider",),                "Imperva"),
    ("x-akamai-transformed", "", ("cdn_provider", "waf_provider"), "Akamai"),
    ("x-amzn-requestid",  "", ("waf_provider",),                "AWS WAF/ELB"),
]

_STACK_FIELDS = (
    "registrar", "dns_provider", "hosting_provider",
    "cdn_provider", "waf_provider", "cms", "framework",
)


@dataclass
class ProviderProfile:
    """Detected provider stack for a domain (foundation slice).

    registrar + deep hosting (IP/ASN) are deferred and stay None until a later
    slice adds WHOIS/RDAP. ``confidence`` is an overall 0–100 strength score for
    how much of the stack we could attribute; per-field detail is in ``evidence``.
    """
    domain: str
    registrar: str | None = None
    dns_provider: str | None = None
    hosting_provider: str | None = None
    cdn_provider: str | None = None
    waf_provider: str | None = None
    cms: str | None = None
    framework: str | None = None
    confidence: int = 0
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "registrar": self.registrar,
            "dns_provider": self.dns_provider,
            "hosting_provider": self.hosting_provider,
            "cdn_provider": self.cdn_provider,
            "waf_provider": self.waf_provider,
            "cms": self.cms,
            "framework": self.framework,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


def _norm_headers(headers: Any) -> dict[str, str]:
    """Lowercase-keyed string header map from a dict / httpx-style headers."""
    out: dict[str, str] = {}
    try:
        items = list(headers.items())
    except AttributeError:
        return out
    for k, v in items:
        out[str(k).lower()] = str(v)
    return out


def _framework_from_finding(finding: Any) -> str | None:
    """Framework name from a Finding's structured evidence extra (stable
    contract), preferred over title parsing."""
    for ev in getattr(finding, "evidence", None) or []:
        extra = getattr(ev, "extra", None) or {}
        name = extra.get("framework")
        if name:
            return str(name)
    return None


def _set_if_empty(
    profile: ProviderProfile, fields: tuple[str, ...], value: str,
    evidence: list[str], source: str,
) -> bool:
    """Fill any of *fields* that are still None with *value*. Returns True if at
    least one field was newly set (so callers can count a 'hit')."""
    newly = False
    for fname in fields:
        if getattr(profile, fname) is None:
            setattr(profile, fname, value)
            evidence.append(f"{fname}: {value} ({source})")
            newly = True
    return newly


def assess_provider_profile(
    domain: str,
    *,
    artifacts: Any | None,
    response_headers: dict[str, str] | None,
    nameservers: list[str] | None,
) -> ProviderProfile:
    """Pure aggregation — compose the reused detectors into a ProviderProfile.

    No network and no new detection signatures. ``artifacts`` is a PageArtifacts
    (or None for non-HTML responses — CDN/WAF then come from raw headers).
    ``response_headers`` is the raw response header map. ``nameservers`` is the
    NS list from dns_checker.
    """
    profile = ProviderProfile(domain=domain)
    evidence: list[str] = []
    hits = 0
    headers = _norm_headers(response_headers or {})

    # 1. TechnologyEngine — reuse as a black box (HTML only). Covers CDN/WAF
    #    (from headers) + CMS + framework. A challenge page is still HTML, so
    #    its cf-ray/x-vercel headers are seen here too.
    if artifacts is not None:
        try:
            findings = TechnologyEngine().analyze(artifacts)
        except Exception:  # noqa: BLE001 — detection must never crash discovery
            logger.debug("provider-discovery: TechnologyEngine failed", exc_info=True)
            findings = []
        for f in findings:
            if getattr(f, "category", None) != FindingCategory.TECHNOLOGY:
                continue
            fw = _framework_from_finding(f)
            if fw and profile.framework is None:
                profile.framework = fw
                evidence.append(f"framework: {fw} (technology engine)")
                hits += 1
                continue
            title = (getattr(f, "title", "") or "").lower()
            for needle, fields, name in _FINDING_TITLE_MAP:
                if needle in title:
                    if _set_if_empty(profile, fields, name, evidence, "technology engine"):
                        hits += 1
                    break

    # 2. challenge_detection provider signatures (URL/HTML) — reuse to add
    #    Vercel/Netlify and confirm CDN/WAF. Build a haystack from headers +
    #    (when present) script srcs and links.
    haystack_parts = [" ".join(f"{k} {v}" for k, v in headers.items())]
    if artifacts is not None:
        haystack_parts.append(" ".join(getattr(artifacts, "external_script_urls", None) or []))
        haystack_parts.append(" ".join(getattr(artifacts, "all_links", None) or []))
    haystack = " ".join(haystack_parts).lower()
    for prov_key, sig in _PROVIDER_SIGNATURES.items():
        mapping = _CHALLENGE_PROVIDER_MAP.get(prov_key)
        if not mapping:
            continue
        url_sigs = sig.get("url", [])
        matched = next((pat for pat in url_sigs if pat and pat.lower() in haystack), None)
        if matched:
            fields, name = mapping
            if _set_if_empty(profile, fields, name, evidence, f"challenge signature '{matched}'"):
                hits += 1

    # 3. Raw-header CDN/WAF fallback — fills gaps TechnologyEngine could not
    #    (notably the non-HTML / artifacts-None case).
    for hname, vsub, fields, name in _HEADER_CDNWAF_FALLBACK:
        val = headers.get(hname)
        if val is not None and (not vsub or vsub in val.lower()):
            if _set_if_empty(profile, fields, name, evidence, f"header '{hname}'"):
                hits += 1

    # 4. DNS provider from nameservers.
    for ns in nameservers or []:
        nsl = str(ns).lower()
        for needle, name in _NS_PROVIDER_MAP:
            if needle in nsl:
                if _set_if_empty(profile, ("dns_provider",), name, evidence, f"nameserver '{nsl}'"):
                    hits += 1
                break
        if profile.dns_provider is not None:
            break

    # 5. Hosting provider best-effort from headers (deep IP/ASN deferred).
    for hname, vsub, name in _HOSTING_HEADER_MAP:
        val = headers.get(hname)
        if val is not None and (not vsub or vsub in val.lower()):
            if _set_if_empty(profile, ("hosting_provider",), name, evidence, f"header '{hname}'"):
                hits += 1
            break

    # registrar: deferred (WHOIS/RDAP) — stays None in the foundation.

    # Overall confidence: a strength score for how much of the stack we mapped.
    if hits:
        profile.confidence = min(98, 30 + 12 * hits + (6 if profile.dns_provider else 0))
    profile.evidence = evidence
    return profile


class ProviderDiscoveryService:
    """Run provider discovery for a URL: fetch (SSRF-guarded) + DNS, then the
    pure :func:`assess_provider_profile`. Network failures degrade gracefully
    (a cert/timeout error yields a DNS-only profile rather than nothing)."""

    def __init__(self, *, timeout_seconds: int = 15) -> None:
        self._timeout = timeout_seconds

    async def discover(
        self, url: str, *, on_event: EventSink | None = None,
    ) -> ProviderProfile:
        emit: EventSink = on_event or (lambda *_a, **_k: None)
        domain = (urlparse(url).hostname or url or "").lower()
        emit(EVENT_STARTED, {"domain": domain, "url": url})

        artifacts: Any | None = None
        headers: dict[str, str] = {}
        # verify_tls=False: we are fingerprinting, not validating certs — a cert
        # error must not zero out discovery. SSRF guard is on the transport
        # regardless. Tight timeout: a single fetch, no crawl.
        opts = ScanOptions(verify_tls=False, request_timeout_seconds=self._timeout)
        try:
            async with SafeHttpClient(opts) as client:
                resp = await client.get(url)
            headers = _norm_headers(getattr(resp, "headers", {}))
            artifacts = Extractor().extract(resp)
        except Exception:  # noqa: BLE001 — fetch failure → DNS-only, still useful
            logger.info("provider-discovery: fetch failed for %s", domain, exc_info=True)

        try:
            dns_records = await asyncio.to_thread(resolve_dns, domain, 4.0)
            nameservers = list(getattr(dns_records, "ns", None) or [])
        except Exception:  # noqa: BLE001
            logger.info("provider-discovery: dns lookup failed for %s", domain, exc_info=True)
            nameservers = []

        try:
            profile = assess_provider_profile(
                domain, artifacts=artifacts,
                response_headers=headers, nameservers=nameservers,
            )
        except Exception:  # noqa: BLE001
            emit(EVENT_FAILED, {"domain": domain})
            logger.exception("provider-discovery: assessment failed for %s", domain)
            raise

        for fname in _STACK_FIELDS:
            val = getattr(profile, fname)
            if val:
                emit(EVENT_DETECTED, {"domain": domain, "field": fname, "provider": val})
        emit(EVENT_COMPLETED, {
            "domain": domain, "confidence": profile.confidence,
            "profile": profile.to_dict(),
        })
        return profile
