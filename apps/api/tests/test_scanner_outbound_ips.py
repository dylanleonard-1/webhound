"""STEP 2 — WEBHOUND_SCANNER_OUTBOUND_IPS parsing (pure).
Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

from apps.api.config import parse_scanner_outbound_ips


def test_single_ip():
    assert parse_scanner_outbound_ips("152.55.180.27") == ["152.55.180.27"]


def test_comma_list_strip_dedup_and_drop_empty():
    assert parse_scanner_outbound_ips("1.2.3.4, 5.6.7.0/24 , ,1.2.3.4") == ["1.2.3.4", "5.6.7.0/24"]


def test_order_preserved():
    assert parse_scanner_outbound_ips("9.9.9.9,1.1.1.1") == ["9.9.9.9", "1.1.1.1"]


def test_blank_and_none():
    assert parse_scanner_outbound_ips("") == []
    assert parse_scanner_outbound_ips("   ") == []
    assert parse_scanner_outbound_ips(None) == []


def test_cidr_preserved():
    assert parse_scanner_outbound_ips("152.55.0.0/16") == ["152.55.0.0/16"]


def test_default_is_three_static_egress_ips():
    """Railway Static Outbound IPs: the config default must be all three fixed
    egress IPs (the old single dynamic IP 152.55.180.27 is stale)."""
    from apps.api.config import Settings

    ips = parse_scanner_outbound_ips(Settings().scanner_outbound_ips)
    assert ips == [
        "162.220.234.240", "152.55.180.240", "152.55.180.241",
    ]
    assert "152.55.180.27" not in ips
