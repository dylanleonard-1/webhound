# WebHound — scanner/webhound/core/ssrf_guard.py
# SSRF egress guard for the scanner's HTTP client.
#
# The scanner fetches user-supplied (but ownership-verified) URLs. Verification
# alone does not stop a verified domain from resolving — or redirecting — to an
# internal address (cloud metadata 169.254.169.254, loopback, RFC1918, or
# *.railway.internal).
#
# Protection is enforced at the connection layer via a custom httpcore network
# backend (_PinningBackend): for every TCP connection — the initial request and
# every redirect hop — we resolve the host exactly once, validate ALL resolved
# addresses are public, and connect to the validated IP. Because the socket is
# opened against the IP we just checked (not a re-resolved hostname), there is
# no DNS-rebinding TOCTOU window. TLS SNI and certificate verification still use
# the original hostname (httpcore calls start_tls with the origin host on the
# stream we return), so HTTPS keeps working correctly.
#
# SSRFGuardTransport is retained as a fallback for the unlikely case that the
# httpcore internals needed to install the backend are unavailable.

from __future__ import annotations

import ipaddress

import anyio
import httpcore
import httpx
from httpcore._backends.auto import AutoBackend

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


def _normalize_host(host: str) -> str:
    h = (host or "").strip().rstrip(".").lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h


def _hostname_blocked(host: str) -> bool:
    return host in _BLOCKED_HOSTNAMES or host.endswith(_BLOCKED_HOST_SUFFIXES)


async def resolve_validated_ip(host: str) -> str:
    """Resolve *host*, ensure every address is public, return one validated IP.

    Raises httpcore.ConnectError (mapped by httpx to httpx.ConnectError, a
    RequestError) when the target is non-public or unresolvable. Fails closed:
    if *any* resolved address is non-public the whole host is rejected.
    """
    h = _normalize_host(host)
    if not h:
        raise httpcore.ConnectError("SSRF blocked: missing host")

    # Literal IP — validate directly, no DNS.
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    if ip is not None:
        if _ip_blocked(ip):
            raise httpcore.ConnectError(f"SSRF blocked: non-public address {h}")
        return h

    if _hostname_blocked(h):
        raise httpcore.ConnectError(f"SSRF blocked: internal hostname {h}")

    try:
        infos = await anyio.getaddrinfo(h, None)
    except Exception as exc:  # noqa: BLE001 — any resolution failure fails closed
        raise httpcore.ConnectError(f"SSRF blocked: DNS resolution failed for {h}") from exc

    addrs = [info[4][0] for info in infos]
    if not addrs:
        raise httpcore.ConnectError(f"SSRF blocked: no addresses for {h}")
    for addr in addrs:
        try:
            if _ip_blocked(ipaddress.ip_address(addr)):
                raise httpcore.ConnectError(
                    f"SSRF blocked: {h} resolves to non-public address {addr}"
                )
        except ValueError as exc:
            raise httpcore.ConnectError(f"SSRF blocked: unparseable address for {h}") from exc
    return addrs[0]


class _PinningBackend(AutoBackend):
    """httpcore backend that connects to a validated, pinned IP.

    Resolution and validation happen here, and the TCP socket is opened against
    the validated IP — eliminating the TOCTOU window a DNS-rebinding attacker
    would otherwise have between a separate validation step and httpcore's own
    resolution. start_tls (called by httpcore on the returned stream) still uses
    the original hostname, preserving SNI and certificate verification.
    """

    async def connect_tcp(
        self, host, port, timeout=None, local_address=None, socket_options=None,
    ):
        validated_ip = await resolve_validated_ip(host)
        return await super().connect_tcp(
            validated_ip, port,
            timeout=timeout, local_address=local_address, socket_options=socket_options,
        )


def build_guarded_transport(*, verify: bool) -> httpx.AsyncBaseTransport:
    """Build an httpx async transport that pins connections to validated IPs.

    Falls back to a resolve-and-check wrapper transport if the httpcore
    internals required to install the pinning backend are unavailable.
    """
    transport = httpx.AsyncHTTPTransport(verify=verify)
    try:
        transport._pool._network_backend = _PinningBackend()  # type: ignore[attr-defined]
        return transport
    except Exception:  # noqa: BLE001 — degrade safely, never fail open silently
        return SSRFGuardTransport(httpx.AsyncHTTPTransport(verify=verify))


# ---------------------------------------------------------------------------
# Fallback path — validate the target before delegating (TOCTOU residual).
# ---------------------------------------------------------------------------


async def assert_public_target(request: httpx.Request) -> None:
    """Raise SSRFBlockedError if *request* targets a non-public address."""
    url = request.url
    if url.scheme not in ("http", "https"):
        raise SSRFBlockedError(f"blocked URL scheme: {url.scheme!r}", request=request)
    try:
        await resolve_validated_ip(url.host or "")
    except httpcore.ConnectError as exc:
        raise SSRFBlockedError(str(exc), request=request) from exc


class SSRFGuardTransport(httpx.AsyncBaseTransport):
    """Fallback: validate each request target before delegating to *inner*."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await assert_public_target(request)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
