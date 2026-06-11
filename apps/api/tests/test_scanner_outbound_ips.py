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
