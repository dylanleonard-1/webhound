# WebHound — scanner/validation/benchmark_runner.py
# Phase-12 validation lab: run the REAL scanner against ground-truth
# targets (Task 11). Each target's HTML+headers are served by a mock
# transport so the full pipeline (crawl → engines → trust → scoring →
# stories) runs exactly as in production — only the network is faked.
#
# This is what makes the lab meaningful: it measures the actual scanner,
# not a stub.

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx

from validation.ground_truth import ALL_TARGETS, GroundTruthTarget


def _mock_transport(target: GroundTruthTarget) -> httpx.MockTransport:
    headers = dict(target.headers or {})
    headers.setdefault("content-type", "text/html; charset=utf-8")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            return httpx.Response(target.status, text=target.html,
                                  headers=headers)
        return httpx.Response(404, text="Not Found")

    return httpx.MockTransport(handler)


def _patch_tls_dns():
    """Return (restore_fn) after stubbing the blocking TLS/DNS probes so
    the lab never touches the network. Idempotent."""
    from webhound.engines.tls_dns import dns_checker as _dns
    from webhound.engines.tls_dns import tls_checker as _tls
    from webhound.engines.tls_dns.dns_checker import DnsRecords
    from webhound.engines.tls_dns.tls_checker import TlsCertInfo

    orig_tls = _tls.probe_tls
    orig_dns = _dns.resolve_dns
    _tls.probe_tls = lambda *a, **k: TlsCertInfo(
        domain="t.test", connection_failed=True)
    _dns.resolve_dns = lambda *a, **k: DnsRecords(
        domain="t.test", a=["93.184.216.34"])

    def restore() -> None:
        _tls.probe_tls = orig_tls
        _dns.resolve_dns = orig_dns

    return restore


async def scan_target(target: GroundTruthTarget) -> Any:
    """Run the real Scanner against one ground-truth target. Returns the
    ScanResult."""
    from webhound.core.orchestrator import Scanner
    from webhound.models.target import ScanOptions, Target

    restore = _patch_tls_dns()
    try:
        t = Target.from_url("https://t.test", scan_options=ScanOptions(
            max_pages=2, max_depth=1, rate_limit_rps=10.0, verify_tls=False))
        scanner = Scanner(t, _transport=_mock_transport(target))
        return await scanner.scan()
    finally:
        restore()


@dataclass
class TargetRun:
    target: GroundTruthTarget
    result: Any                      # ScanResult


@dataclass
class BenchmarkRun:
    """A full lab run: every target scanned."""

    runs: list[TargetRun] = field(default_factory=list)

    def by_category(self, category: str) -> list[TargetRun]:
        return [r for r in self.runs if r.target.category == category]


async def run_targets(
    targets: tuple[GroundTruthTarget, ...] = ALL_TARGETS,
) -> BenchmarkRun:
    """Scan every target (sequentially — each is a tiny single-page mock)
    and return the collected runs."""
    run = BenchmarkRun()
    for target in targets:
        result = await scan_target(target)
        run.runs.append(TargetRun(target=target, result=result))
    return run


def run_targets_sync(
    targets: tuple[GroundTruthTarget, ...] = ALL_TARGETS,
) -> BenchmarkRun:
    """Synchronous wrapper for CLI / non-async callers."""
    return asyncio.run(run_targets(targets))
