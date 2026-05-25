# WebHound — scanner/webhound/core/ssrf_guard.py
# SSRF egress guard for the scanner's HTTP client.
#
# The scanner fetches user-supplied (but ownership-verified) URLs. Verification
# alone does not stop a verified domain from resolving — or redirecting — to an
# internal address (cloud metadata 169.254.169.254, loopback, RFC1918, or
# *.railway.internal). This guard resolves the target host and refuses to
# connect when any resolved address is non-public.
#
# It is installed as an httpx transport wrapper, so it runs for the initial
# request AND for every redirect hop (httpx routes each hop through the
# transport).
#
# Known residual: a DNS-rebinding attacker who returns a public IP to this
# check and an internal IP to httpx's own connect has a TOCTOU window. Closing
# that fully requires pinning the validated IP for the connection; this guard
# covers the realistic cases (internal A records, literal-IP URLs, redirects to
# internal hosts).

from __future__ import annotations

import asyncio
import ipaddress
import socket

import httpx

# Hostnames never worth resolving — block outright.
_BLOCKED_HOST_SUFFIXES = (".internal", ".local", ".localhost")
_BLOCKED_HOSTNAMES = {"localhost", "metadata", "metadata.google.internal"}


class SSRFBlockedError(httpx.RequestError):
    """A request target resolved to a non-public / disallowed address."""


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254) so the embedded
    # v4 address is evaluated, not the v6 wrapper.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local      # 169.254.0.0/16 — covers cloud metadata
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


async def _resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


async def assert_public_target(request: httpx.Request) -> None:
    """Raise SSRFBlockedError if *request* targets a non-public address."""
    url = request.url
    if url.scheme not in ("http", "https"):
        raise SSRFBlockedError(f"blocked URL scheme: {url.scheme!r}", request=request)

    host = (url.host or "").strip().rstrip(".").lower()
    if not host:
        raise SSRFBlockedError("blocked: missing host", request=request)

    # Literal IP in the URL — check directly, no DNS.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if _ip_blocked(ip):
            raise SSRFBlockedError(f"blocked non-public address: {host}", request=request)
        return

    if host in _BLOCKED_HOSTNAMES or host.endswith(_BLOCKED_HOST_SUFFIXES):
        raise SSRFBlockedError(f"blocked internal hostname: {host}", request=request)

    try:
        resolved = await _resolve(host)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"DNS resolution failed for {host}", request=request) from exc

    for addr in resolved:
        try:
            if _ip_blocked(ipaddress.ip_address(addr)):
                raise SSRFBlockedError(
                    f"blocked: {host} resolves to non-public address {addr}",
                    request=request,
                )
        except ValueError:
            # Unparseable address — fail closed.
            raise SSRFBlockedError(f"blocked: unparseable address for {host}", request=request)


class SSRFGuardTransport(httpx.AsyncBaseTransport):
    """Wraps an httpx transport, validating each request target is public."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await assert_public_target(request)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
