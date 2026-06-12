"""Phase-2 Platform Access — admin stats aggregation.
Run with --noconftest -p no:cacheprovider.
"""
from __future__ import annotations

from apps.api.services.platform_access import (
    PA_ACCESS_REQUIRED,
    PA_PROVIDER_DETECTED,
    PA_TICKET_CREATED,
    PA_VERIFICATION_FAILED,
    PA_VERIFICATION_SUCCESS,
    build_admin_stats,
    registry_provider_summaries,
)

PROVIDERS = registry_provider_summaries()
IPS = ["162.220.234.240", "152.55.180.240", "152.55.180.241"]


def _ev(et, prov):
    return {"event_type": et, "provider": prov}


def test_registry_summaries_are_ten_with_one_automated():
    assert len(PROVIDERS) == 10
    assert sum(1 for p in PROVIDERS if p["automation_capable"]) == 1


def test_admin_stats_success_rate_and_tops():
    events = [
        _ev(PA_PROVIDER_DETECTED, "cloudflare"),
        _ev(PA_PROVIDER_DETECTED, "cloudflare"),
        _ev(PA_PROVIDER_DETECTED, "vercel"),
        _ev(PA_ACCESS_REQUIRED, "cloudflare"),
        _ev(PA_ACCESS_REQUIRED, "vercel"),
        _ev(PA_VERIFICATION_SUCCESS, "cloudflare"),
        _ev(PA_VERIFICATION_SUCCESS, "cloudflare"),
        _ev(PA_VERIFICATION_SUCCESS, "vercel"),
        _ev(PA_VERIFICATION_FAILED, "vercel"),
        _ev(PA_TICKET_CREATED, "vercel"),
    ]
    s = build_admin_stats(events, providers=PROVIDERS, scanner_ips=IPS)
    assert s["provider_count"] == 10
    assert s["scanner_ips"] == IPS
    assert s["verification"] == {"success": 3, "failed": 1, "total": 4,
                                 "success_rate": 75.0}
    assert s["access_required_count"] == 2
    assert s["tickets_created"] == 1
    assert s["most_common_providers"][0] == {"provider": "cloudflare", "count": 2}
    assert s["most_common_failures"][0] == {"provider": "vercel", "count": 1}
    assert {"provider": "cloudflare", "count": 1} in s["most_common_blocks"]


def test_admin_stats_empty():
    s = build_admin_stats([], providers=PROVIDERS, scanner_ips=IPS)
    assert s["verification"]["success_rate"] is None
    assert s["tickets_created"] == 0
    assert s["most_common_providers"] == []
