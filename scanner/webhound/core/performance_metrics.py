# WebHound — scanner/webhound/core/performance_metrics.py
# Phase-19 production hardening (Task 6): extract a normalized
# performance metrics block from a completed scan's metadata so cost +
# speed can be tracked and tuned. Pure — reads the metadata the
# orchestrator already wrote (fetch_stats, crawl_duration, browser_pass,
# coverage_summary, engine_diagnostics). No new measurement.

from __future__ import annotations

from typing import Any


def extract_performance_metrics(
    scan_result: Any,
) -> dict[str, Any]:
    """Roll the timings + volumes the scan already recorded into one
    metrics dict. Accepts a ScanResult (uses .metadata + .duration_seconds
    + engine_diagnostics)."""
    meta = getattr(scan_result, "metadata", {}) or {}
    fetch = meta.get("fetch_stats") or {}
    browser = meta.get("browser_pass") or {}
    coverage = meta.get("coverage_summary") or {}

    # Per-engine durations from the diagnostics.
    diagnostics = getattr(scan_result, "engine_diagnostics", []) or []
    engine_durations: dict[str, float] = {}
    for d in diagnostics:
        name = getattr(d, "name", None) or (
            d.get("name") if isinstance(d, dict) else None)
        dur = getattr(d, "duration_ms", None)
        if dur is None and isinstance(d, dict):
            dur = d.get("duration_ms")
        if name and dur is not None:
            engine_durations[name] = round(float(dur), 1)
    slowest = sorted(engine_durations.items(), key=lambda kv: kv[1],
                     reverse=True)[:5]

    total = getattr(scan_result, "duration_seconds", None)
    return {
        "total_scan_seconds": round(float(total), 3)
        if total is not None else None,
        "crawl_duration_seconds": meta.get("crawl_duration_seconds"),
        "browser_render_ms": browser.get("duration_ms"),
        # Volumes.
        "pages_crawled": getattr(scan_result, "urls_crawled", None)
        or coverage.get("pages_crawled"),
        "requests_made": fetch.get("total") or fetch.get("requests"),
        "requests_retried": fetch.get("retried"),
        "requests_skipped": fetch.get("skipped"),
        "browser_pages_rendered": (browser.get("browser_pages_rendered")
                                   or coverage.get("browser_pages_rendered")),
        "scripts_collected": coverage.get("browser_scripts_collected"),
        "apis_observed": (coverage.get("api_endpoints_observed")
                          or browser.get("browser_api_requests")),
        "third_party_domains": coverage.get("third_party_domains_observed"),
        # Engine timing.
        "total_engine_ms": round(sum(engine_durations.values()), 1),
        "slowest_engines": [{"engine": n, "duration_ms": ms}
                            for n, ms in slowest],
        "engine_durations_ms": engine_durations,
    }
