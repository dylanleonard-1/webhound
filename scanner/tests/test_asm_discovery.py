# WebHound — scanner/tests/test_asm_discovery.py
# Phase-4 slice 5: ASM-lite asset-discovery tests.
#
# Every test uses injected transports/resolvers so the suite is fully
# offline. No real network calls happen here.

from __future__ import annotations

import pytest

from webhound.asm.asset_discovery import (
    AssetMap,
    build_asset_map,
    common_subdomain_check,
    passive_subdomain_discovery,
)


# ---------------------------------------------------------------------------
# passive_subdomain_discovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_passive_subdomain_discovery_parses_crtsh_json() -> None:
    """Multi-name certs return name_value as newline-delimited strings."""
    fake_body = """
    [
        {"name_value": "*.acme.test\\nacme.test"},
        {"name_value": "api.acme.test"},
        {"name_value": "admin.acme.test\\ndashboard.acme.test"}
    ]
    """

    async def _transport(url: str) -> tuple[int, str]:
        assert "acme.test" in url
        return 200, fake_body

    result = await passive_subdomain_discovery(
        "acme.test", transport=_transport,
    )
    assert result.deferred is False
    assert result.error is None
    # Every name parsed, wildcard stripped, lowercased.
    assert "api.acme.test" in result.hostnames
    assert "admin.acme.test" in result.hostnames
    assert "dashboard.acme.test" in result.hostnames
    # The bare domain itself is included (apex names land in name_value).
    assert "acme.test" in result.hostnames


@pytest.mark.asyncio
async def test_passive_subdomain_discovery_filters_unrelated_hosts() -> None:
    """crt.sh occasionally returns poisoned rows. Must drop them."""
    fake_body = """[
        {"name_value": "api.acme.test"},
        {"name_value": "evil.example.com"},
        {"name_value": "phish-acme.attacker.test"}
    ]"""

    async def _transport(url: str) -> tuple[int, str]:
        return 200, fake_body

    result = await passive_subdomain_discovery(
        "acme.test", transport=_transport,
    )
    assert "api.acme.test" in result.hostnames
    assert "evil.example.com" not in result.hostnames
    assert "phish-acme.attacker.test" not in result.hostnames


@pytest.mark.asyncio
async def test_passive_subdomain_discovery_offline_defers() -> None:
    """No transport + allow_network=False = deferred, not silent failure."""
    result = await passive_subdomain_discovery(
        "acme.test", transport=None, allow_network=False,
    )
    assert result.deferred is True
    assert result.hostnames == set()


@pytest.mark.asyncio
async def test_passive_subdomain_discovery_handles_non_200() -> None:
    async def _transport(url: str) -> tuple[int, str]:
        return 503, "Service Unavailable"

    result = await passive_subdomain_discovery(
        "acme.test", transport=_transport,
    )
    assert result.hostnames == set()
    assert "HTTP 503" in (result.error or "")


@pytest.mark.asyncio
async def test_passive_subdomain_discovery_handles_transport_error() -> None:
    async def _broken_transport(url: str) -> tuple[int, str]:
        raise TimeoutError("simulated")

    result = await passive_subdomain_discovery(
        "acme.test", transport=_broken_transport,
    )
    assert result.hostnames == set()
    assert "TimeoutError" in (result.error or "")


@pytest.mark.asyncio
async def test_passive_subdomain_discovery_handles_malformed_json() -> None:
    async def _transport(url: str) -> tuple[int, str]:
        return 200, "<html>not json</html>"

    result = await passive_subdomain_discovery(
        "acme.test", transport=_transport,
    )
    assert result.hostnames == set()


# ---------------------------------------------------------------------------
# common_subdomain_check
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_common_subdomain_check_only_returns_resolving() -> None:
    """The resolve stub controls truth — only hosts it OKs are returned."""
    resolving = {"admin.acme.test", "api.acme.test"}

    async def _resolve(host: str) -> bool:
        return host in resolving

    result = await common_subdomain_check(
        "acme.test", resolve=_resolve,
    )
    assert result.hostnames == resolving


@pytest.mark.asyncio
async def test_common_subdomain_check_swallows_resolver_errors() -> None:
    """One bad lookup must not abort the rest."""
    async def _flaky_resolve(host: str) -> bool:
        if "admin" in host:
            raise RuntimeError("dns blip")
        return host == "api.acme.test"

    result = await common_subdomain_check(
        "acme.test", resolve=_flaky_resolve,
    )
    assert result.hostnames == {"api.acme.test"}


# ---------------------------------------------------------------------------
# build_asset_map
# ---------------------------------------------------------------------------


def test_build_asset_map_dedupes_primary_from_subdomains() -> None:
    am = build_asset_map(
        "acme.test",
        ct_subdomains={"acme.test", "api.acme.test"},
        common_subdomains={"acme.test", "admin.acme.test"},
        external_hosts={"acme.test", "cdn.googleapis.com"},
    )
    assert am.primary_host == "acme.test"
    assert "acme.test" not in am.ct_subdomains
    assert "acme.test" not in am.common_subdomains
    assert "acme.test" not in am.external_hosts


def test_build_asset_map_dedupes_overlap_between_sources() -> None:
    """A subdomain that appeared from both CT logs and the DNS probe
    should only appear once in the aggregate."""
    am = build_asset_map(
        "acme.test",
        ct_subdomains={"api.acme.test"},
        common_subdomains={"api.acme.test", "admin.acme.test"},
        external_hosts=set(),
    )
    assert am.all_subdomains == {"api.acme.test", "admin.acme.test"}
    # common_subdomains has admin only (api was already in ct_subdomains)
    assert am.common_subdomains == {"admin.acme.test"}


def test_asset_map_exposure_signals_flag_admin_like() -> None:
    am = build_asset_map(
        "acme.test",
        ct_subdomains={"admin.acme.test", "console.acme.test"},
    )
    chips = am.exposure_signals()
    assert any("admin-like" in c for c in chips)


def test_asset_map_exposure_signals_flag_preprod() -> None:
    am = build_asset_map(
        "acme.test",
        ct_subdomains={"staging.acme.test", "uat.acme.test"},
    )
    chips = am.exposure_signals()
    assert any("pre-prod" in c for c in chips)


def test_asset_map_exposure_signals_clean_target() -> None:
    am = build_asset_map("acme.test")
    chips = am.exposure_signals()
    assert chips == ["no notable exposure patterns"]


def test_asset_map_surface_count_includes_primary() -> None:
    am = build_asset_map(
        "acme.test",
        ct_subdomains={"api.acme.test"},
        external_hosts={"x.example.com"},
    )
    # primary + 1 subdomain + 1 external = 3
    assert am.total_surface_count == 3
