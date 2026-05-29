# WebHound — scanner/webhound/asm/asset_discovery.py
# Phase-4 slice 5: ASM-lite asset discovery.
#
# Three primitives that compose into a basic attack-surface map:
#
#   * passive_subdomain_discovery(domain, *, transport)
#       Hits the public Certificate Transparency aggregator at
#       crt.sh and returns every subdomain that has had a certificate
#       issued to it. Zero scanning of the target itself — all data
#       comes from CT logs. Safe to run without any prior relationship
#       with the target.
#
#   * common_subdomain_check(domain, *, resolve, allow_active=False)
#       For each well-known subdomain prefix (admin/api/dev/staging/…)
#       checks whether the DNS name resolves. ``resolve`` is a callable
#       so tests + offline mode swap in deterministic resolvers. Active
#       HTTP probing is gated behind ``allow_active`` so a default-mode
#       run is purely DNS-resolution.
#
#   * build_asset_map(target_host, *, ct_subdomains, common_subdomains,
#                     external_hosts)
#       Combines the three signal sources + the scan-wide external
#       host inventory into an :class:`AssetMap` containing the
#       discovered surface + a categorical exposure rollup.
#
# Offline-by-default. The crt.sh HTTP call is the only network reach
# in this module; if you run with allow_network=False the discovery
# function returns an empty set and tags the result so the caller can
# tell "we deferred" from "we found nothing".

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable

logger = logging.getLogger(__name__)

# Public CT-log aggregator. Returns JSON when ?output=json is set.
_CRT_SH_URL = "https://crt.sh/?q={pattern}&output=json"

# Conservative request budget — crt.sh is rate-limited per IP. One
# request per discovery call.
_CRT_SH_TIMEOUT = 8.0


# A subset of common subdomain prefixes that map to actual administrative
# / pre-prod / API surfaces in the wild. Keep this list short on
# purpose — every entry costs a DNS lookup; bloat = slow scans + DNS
# noise toward the target.
COMMON_SUBDOMAIN_PREFIXES: tuple[str, ...] = (
    "www", "api", "admin", "dev", "staging", "stage", "test", "qa",
    "uat", "preprod", "prod", "internal", "intranet",
    "vpn", "mail", "smtp", "imap", "pop",
    "portal", "dashboard", "console", "manage", "ops",
    "auth", "login", "sso", "id", "accounts",
    "files", "static", "cdn", "media",
    "m", "mobile", "app", "apps",
    "git", "gitlab", "jenkins", "ci",
    "monitor", "metrics", "grafana", "kibana",
)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SubdomainResult:
    """One discovery pass's findings. ``deferred`` is True when the
    call was skipped (offline mode, no transport, etc.) — distinct from
    "found nothing"."""

    hostnames: set[str] = field(default_factory=set)
    deferred: bool = False
    source: str = ""
    error: str | None = None


@dataclass
class AssetMap:
    """Aggregate view of one target's attack surface."""

    primary_host: str
    ct_subdomains: set[str] = field(default_factory=set)
    common_subdomains: set[str] = field(default_factory=set)
    external_hosts: set[str] = field(default_factory=set)

    @property
    def all_subdomains(self) -> set[str]:
        return self.ct_subdomains | self.common_subdomains

    @property
    def total_surface_count(self) -> int:
        """Unique known hosts in the surface — primary + subdomains +
        external dependencies. External hosts overlap with neither
        subdomain set by construction (different hostnames)."""
        return 1 + len(self.all_subdomains) + len(self.external_hosts)

    def exposure_signals(self) -> list[str]:
        """Human-readable rollup the dashboard renders as exposure chips."""
        chips: list[str] = []
        admin_like = {s for s in self.all_subdomains
                       if any(k in s.lower() for k in
                              ("admin", "internal", "intranet", "console"))}
        if admin_like:
            chips.append(f"{len(admin_like)} admin-like subdomain(s)")
        preprod = {s for s in self.all_subdomains
                    if any(k in s.lower() for k in
                           ("dev", "staging", "stage", "test", "qa", "uat"))}
        if preprod:
            chips.append(f"{len(preprod)} pre-prod surface(s)")
        if len(self.external_hosts) > 30:
            chips.append(
                f"{len(self.external_hosts)} third-party dependencies",
            )
        if not chips:
            chips.append("no notable exposure patterns")
        return chips


# ---------------------------------------------------------------------------
# Primitive 1 — passive subdomain discovery via CT logs
# ---------------------------------------------------------------------------


async def passive_subdomain_discovery(
    registrable_domain: str,
    *,
    transport: Callable[[str], Awaitable[tuple[int, str]]] | None = None,
    allow_network: bool = False,
) -> SubdomainResult:
    """Ask crt.sh for every certificate issued to any name under
    ``registrable_domain``. ``transport`` is an async callable that
    returns ``(status_code, body)``; tests inject a deterministic
    stub. When ``allow_network=False`` and no transport is provided,
    returns ``deferred=True`` with no hostnames — so the caller can
    distinguish "we chose not to look" from "we looked and found none"."""
    domain = (registrable_domain or "").strip().lower().lstrip(".")
    if not domain:
        return SubdomainResult(deferred=True,
                                source="crt.sh", error="empty domain")
    if transport is None and not allow_network:
        return SubdomainResult(deferred=True, source="crt.sh",
                                error="offline (allow_network=False)")
    if transport is None:
        # Default httpx-backed transport. Lazy-imported to keep tests
        # that supply their own transport from pulling in httpx.
        import httpx

        async def _httpx_transport(url: str) -> tuple[int, str]:
            async with httpx.AsyncClient(timeout=_CRT_SH_TIMEOUT) as c:
                resp = await c.get(url)
                return resp.status_code, resp.text
        transport = _httpx_transport

    url = _CRT_SH_URL.format(pattern=f"%25.{domain}")
    try:
        status, body = await transport(url)
    except Exception as exc:  # noqa: BLE001
        return SubdomainResult(deferred=False, source="crt.sh",
                                error=f"{type(exc).__name__}: {exc}")
    if status != 200:
        return SubdomainResult(source="crt.sh",
                                error=f"HTTP {status}")
    return SubdomainResult(
        hostnames=_extract_hostnames_from_crtsh(body, base_domain=domain),
        source="crt.sh",
    )


_NAME_VALUE_KEY = "name_value"


def _extract_hostnames_from_crtsh(body: str, *, base_domain: str) -> set[str]:
    """Parse crt.sh JSON output. The ``name_value`` field is newline-
    delimited; rows can also contain wildcards and uppercase casing —
    normalise both. Only return names whose registrable domain matches
    ``base_domain`` (defensive against poisoned entries)."""
    import json
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return set()
    if not isinstance(payload, list):
        return set()
    out: set[str] = set()
    for entry in payload:
        raw = entry.get(_NAME_VALUE_KEY) if isinstance(entry, dict) else None
        if not isinstance(raw, str):
            continue
        for line in raw.splitlines():
            host = line.strip().lower().lstrip("*.")
            if not host:
                continue
            # Defensive: only accept entries that actually belong to the
            # target base domain. crt.sh occasionally returns junk.
            if not host.endswith("." + base_domain) and host != base_domain:
                continue
            # Sanity check on hostname shape.
            if not _VALID_HOSTNAME.match(host):
                continue
            out.add(host)
    return out


_VALID_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$",
)


# ---------------------------------------------------------------------------
# Primitive 2 — common-subdomain DNS probe
# ---------------------------------------------------------------------------


async def common_subdomain_check(
    registrable_domain: str,
    *,
    resolve: Callable[[str], Awaitable[bool]],
    prefixes: Iterable[str] = COMMON_SUBDOMAIN_PREFIXES,
) -> SubdomainResult:
    """For each prefix in ``prefixes``, build ``prefix.registrable_domain``
    and ask ``resolve(hostname)`` whether it resolves. ``resolve`` is
    a caller-supplied async callable so this stays offline-safe in
    tests + WSL environments where async DNS can be flaky."""
    domain = (registrable_domain or "").strip().lower().lstrip(".")
    if not domain:
        return SubdomainResult(deferred=True, source="dns_probe",
                                error="empty domain")
    found: set[str] = set()
    for prefix in prefixes:
        host = f"{prefix}.{domain}"
        try:
            if await resolve(host):
                found.add(host)
        except Exception:  # noqa: BLE001
            # One bad lookup must not abort the whole probe.
            continue
    return SubdomainResult(hostnames=found, source="dns_probe")


# ---------------------------------------------------------------------------
# Primitive 3 — asset map aggregation
# ---------------------------------------------------------------------------


def build_asset_map(
    primary_host: str,
    *,
    ct_subdomains: set[str] | None = None,
    common_subdomains: set[str] | None = None,
    external_hosts: set[str] | None = None,
) -> AssetMap:
    """Combine every discovery source into an :class:`AssetMap`. Each
    set is deduplicated against the others — the primary host never
    appears in its own subdomain set, and external_hosts excludes
    anything that matches the primary host or its subdomains."""
    primary = (primary_host or "").lower().strip(".")
    ct = set(ct_subdomains or ()) - {primary}
    common = set(common_subdomains or ()) - {primary} - ct
    ext = (set(external_hosts or ())
           - {primary}
           - ct
           - common)
    return AssetMap(
        primary_host=primary,
        ct_subdomains=ct,
        common_subdomains=common,
        external_hosts=ext,
    )
