"""SSRF egress guard — IP validation, DNS-rebinding pinning, scheme blocking."""

from __future__ import annotations

import httpcore
import httpx
import pytest

from webhound.core import ssrf_guard as sg


def _fake_getaddrinfo(addrs: list[str]):
    async def fake(host, port, *a, **k):
        # (family, type, proto, canonname, sockaddr); sockaddr[0] is the IP.
        return [(0, 0, 0, "", (ip, 0)) for ip in addrs]
    return fake


class TestResolveValidatedIp:
    @pytest.mark.anyio
    async def test_public_domain_returns_resolved_ip(self, monkeypatch):
        monkeypatch.setattr(sg.anyio, "getaddrinfo", _fake_getaddrinfo(["93.184.216.34"]))
        assert await sg.resolve_validated_ip("example.com") == "93.184.216.34"

    @pytest.mark.anyio
    async def test_metadata_ip_blocked(self, monkeypatch):
        monkeypatch.setattr(sg.anyio, "getaddrinfo", _fake_getaddrinfo(["169.254.169.254"]))
        with pytest.raises(httpcore.ConnectError):
            await sg.resolve_validated_ip("rebind.attacker.test")

    @pytest.mark.anyio
    async def test_loopback_blocked(self, monkeypatch):
        monkeypatch.setattr(sg.anyio, "getaddrinfo", _fake_getaddrinfo(["127.0.0.1"]))
        with pytest.raises(httpcore.ConnectError):
            await sg.resolve_validated_ip("loopback.attacker.test")

    @pytest.mark.anyio
    async def test_rfc1918_blocked(self, monkeypatch):
        monkeypatch.setattr(sg.anyio, "getaddrinfo", _fake_getaddrinfo(["10.1.2.3"]))
        with pytest.raises(httpcore.ConnectError):
            await sg.resolve_validated_ip("internal.test")

    @pytest.mark.anyio
    async def test_mixed_public_and_private_fails_closed(self, monkeypatch):
        # If a host resolves to both a public and an internal address, reject it.
        monkeypatch.setattr(
            sg.anyio, "getaddrinfo", _fake_getaddrinfo(["93.184.216.34", "10.0.0.1"])
        )
        with pytest.raises(httpcore.ConnectError):
            await sg.resolve_validated_ip("dual.test")

    @pytest.mark.anyio
    async def test_ipv4_mapped_ipv6_metadata_blocked(self, monkeypatch):
        monkeypatch.setattr(
            sg.anyio, "getaddrinfo", _fake_getaddrinfo(["::ffff:169.254.169.254"])
        )
        with pytest.raises(httpcore.ConnectError):
            await sg.resolve_validated_ip("mapped.test")

    @pytest.mark.anyio
    async def test_literal_internal_ip_blocked(self):
        with pytest.raises(httpcore.ConnectError):
            await sg.resolve_validated_ip("169.254.169.254")

    @pytest.mark.anyio
    async def test_literal_public_ip_ok(self):
        assert await sg.resolve_validated_ip("1.1.1.1") == "1.1.1.1"

    @pytest.mark.anyio
    async def test_internal_hostname_suffix_blocked(self):
        with pytest.raises(httpcore.ConnectError):
            await sg.resolve_validated_ip("db.railway.internal")


class TestPinning:
    """The TCP socket must open against the validated IP, never a re-resolved
    hostname — that is what closes the DNS-rebinding TOCTOU window."""

    @pytest.mark.anyio
    async def test_connect_tcp_pins_validated_ip(self, monkeypatch):
        monkeypatch.setattr(sg.anyio, "getaddrinfo", _fake_getaddrinfo(["93.184.216.34"]))
        captured: dict = {}

        async def fake_super(self, host, port, **kwargs):
            captured["host"] = host
            captured["port"] = port
            return object()  # sentinel stream

        monkeypatch.setattr(sg.AutoBackend, "connect_tcp", fake_super)
        await sg._PinningBackend().connect_tcp("example.com", 443)
        # Pinned to the validated IP, not the hostname.
        assert captured == {"host": "93.184.216.34", "port": 443}

    @pytest.mark.anyio
    async def test_connect_tcp_blocks_rebind_before_socket(self, monkeypatch):
        monkeypatch.setattr(sg.anyio, "getaddrinfo", _fake_getaddrinfo(["169.254.169.254"]))
        reached = {"socket": False}

        async def fake_super(self, host, port, **kwargs):
            reached["socket"] = True
            return object()

        monkeypatch.setattr(sg.AutoBackend, "connect_tcp", fake_super)
        with pytest.raises(httpcore.ConnectError):
            await sg._PinningBackend().connect_tcp("rebind.test", 80)
        assert reached["socket"] is False  # blocked before any connection


class TestTransportFactory:
    def test_installs_pinning_backend(self):
        transport = sg.build_guarded_transport(verify=True)
        assert isinstance(transport._pool._network_backend, sg._PinningBackend)

    @pytest.mark.anyio
    async def test_scheme_guard_blocks_non_http(self):
        with pytest.raises(sg.SSRFBlockedError):
            await sg.assert_public_target(httpx.Request("GET", "ftp://example.com/"))
