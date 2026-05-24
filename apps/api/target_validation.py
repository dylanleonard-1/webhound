# WebHound — apps/api/target_validation.py
# Pre-scan target validation. Prevents users from pointing WebHound at
# internal or cloud-metadata hostnames — both as an SSRF defense (don't let
# our scanner crawl 169.254.169.254 from a cloud worker and leak credentials)
# and as an abuse defense (don't let users probe systems they couldn't
# normally reach).

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Cloud metadata endpoints — never scan these
_METADATA_HOSTS = frozenset({
    "169.254.169.254",      # AWS / GCP / Azure / OpenStack IMDS
    "fd00:ec2::254",        # AWS IMDSv2 IPv6
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
})

# Hostnames that resolve to internal infrastructure
_INTERNAL_HOSTNAMES = frozenset({
    "localhost", "ip6-localhost", "ip6-loopback",
    "kubernetes", "kubernetes.default", "kubernetes.default.svc",
    "consul", "vault", "nomad",
})

# TLDs / suffixes reserved for internal resolution
_INTERNAL_SUFFIXES = (
    ".local", ".localhost", ".lan", ".intranet",
    ".internal", ".corp",
    ".svc", ".svc.cluster.local",
    ".consul", ".nomad",
)


class TargetRejected(Exception):
    """Raised when a target URL is not safe for WebHound to scan."""

    def __init__(self, reason: str, *, code: str = "target_rejected") -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code


def validate_target(url: str, *, resolve_dns: bool = False) -> None:
    """Validate that *url* is a safe scan target.

    Raises TargetRejected on any of:
      - Non-HTTP(S) scheme
      - Hostname matches a known cloud-metadata endpoint
      - Hostname is an explicit internal alias (localhost, kubernetes, …)
      - Hostname ends in a reserved internal suffix (.local, .internal, …)
      - Hostname resolves to (or literally is) a private IP

    DNS resolution is optional (default off) because doing it inline on
    every scan-job creation slows the route and exposes us to slow / hung
    DNS responses. Worker-side validation (after the job is queued) can
    re-run with resolve_dns=True for defense in depth.
    """
    if not url or not isinstance(url, str):
        raise TargetRejected("Target URL must be a non-empty string.")

    try:
        parsed = urlparse(url.strip())
    except (ValueError, TypeError):
        raise TargetRejected(f"Could not parse URL: {url!r}")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise TargetRejected(
            f"Only http:// and https:// targets are allowed (got {scheme!r}).",
            code="invalid_scheme",
        )

    host = (parsed.hostname or "").lower()
    if not host:
        raise TargetRejected("URL has no hostname.", code="no_hostname")

    if host in _METADATA_HOSTS:
        raise TargetRejected(
            "Cloud-metadata endpoints cannot be scanned. This is enforced "
            "to prevent server-side request forgery against the WebHound "
            "infrastructure itself.",
            code="metadata_endpoint",
        )

    if host in _INTERNAL_HOSTNAMES:
        raise TargetRejected(
            f"Internal hostname {host!r} cannot be scanned over the public "
            "internet. WebHound is a remote scanner — it can't reach "
            "private network names, and even if it could, those names "
            "shouldn't be exposed to it.",
            code="internal_hostname",
        )

    for suffix in _INTERNAL_SUFFIXES:
        if host.endswith(suffix):
            raise TargetRejected(
                f"Hostname suffix {suffix!r} is reserved for internal "
                "resolution and cannot be scanned by WebHound.",
                code="internal_suffix",
            )

    # If the host is a literal IP, check it directly
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        _reject_if_private_ip(ip)
        return

    # Block obvious port abuse
    port = parsed.port
    if port is not None and port < 1:
        raise TargetRejected(f"Invalid port {port}.", code="invalid_port")

    if resolve_dns:
        try:
            infos = socket.getaddrinfo(
                host, None, type=socket.SOCK_STREAM,
            )
        except (socket.gaierror, UnicodeError) as exc:
            raise TargetRejected(
                f"DNS resolution failed for {host}: {exc}",
                code="dns_failed",
            )
        for info in infos:
            sockaddr = info[4]
            ip_str = sockaddr[0]
            try:
                resolved_ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            _reject_if_private_ip(resolved_ip, host=host)


def _reject_if_private_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *, host: str | None = None,
) -> None:
    detail = f" (resolved from {host})" if host else ""
    if ip.is_loopback:
        raise TargetRejected(
            f"Loopback address {ip}{detail} cannot be scanned.",
            code="loopback",
        )
    if ip.is_link_local:
        raise TargetRejected(
            f"Link-local address {ip}{detail} cannot be scanned.",
            code="link_local",
        )
    if ip.is_private:
        raise TargetRejected(
            f"Private (RFC1918) address {ip}{detail} cannot be scanned by "
            "WebHound from the public internet.",
            code="private_ip",
        )
    if ip.is_multicast:
        raise TargetRejected(
            f"Multicast address {ip}{detail} cannot be scanned.",
            code="multicast",
        )
    if ip.is_reserved:
        raise TargetRejected(
            f"Reserved address {ip}{detail} cannot be scanned.",
            code="reserved",
        )
    # IPv4-mapped IPv6 trick: ::ffff:10.0.0.1
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        _reject_if_private_ip(ip.ipv4_mapped, host=host)
