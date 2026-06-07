# WebHound — tests/test_graph_export.py
# Phase-20 Task 11/12/13: export + validation + orchestrator integration.

from __future__ import annotations

from types import SimpleNamespace as NS

import httpx
import pytest

from webhound.graph import (
    EdgeType,
    NodeType,
    build_graph,
    export_evidence_graph,
    export_json,
    export_summary,
    validate_graph,
)


def _script(src):
    return NS(src=src, content=None, is_inline=False, is_external=True,
              is_external_domain=True)


def _arts(url, *, scripts=()):
    return NS(url=url, scripts=list(scripts), forms=[], iframes=[],
              cookies=[], response_headers={})


def _crawl(url, **kw):
    return NS(response=NS(url=url, failed=False), artifacts=_arts(url, **kw))


def _result(grouped=(), metadata=None):
    return NS(target=NS(base_url="https://t.test/"),
              grouped_findings=list(grouped), metadata=metadata or {})


def _gf(title, *, engine, urls=()):
    return NS(title=title, scanner_engine=engine, severity=NS(value="high"),
              confidence=0.9, finding_ids=[f"id-{title}"],
              affected_urls=list(urls), metadata={})


def _graph():
    return build_graph(_result(
        grouped=[_gf("Admin exposed", engine="sensitive_paths",
                     urls=["https://t.test/admin"])]),
        crawl_results=[
            _crawl("https://t.test/admin"),
            _crawl("https://t.test/",
                   scripts=[_script("https://js.stripe.com/v3"),
                            _script("https://unknown-q.test/a.js")])])


# ---------------------------------------------------------------------------
# Export (Task 11)
# ---------------------------------------------------------------------------


def test_export_summary_is_compact() -> None:
    s = export_summary(_graph())
    assert s["node_count"] > 0
    assert "node_types" in s and "edge_types" in s
    assert s["third_party_domain_count"] >= 2
    assert "unknown-q.test" in s["unknown_vendors"]
    # No raw node dump in the summary.
    assert "nodes" not in s


def test_export_json_full() -> None:
    j = export_json(_graph())
    assert "nodes" in j and "edges" in j
    assert j["node_count"] == len(j["nodes"])


def test_export_is_stable() -> None:
    a = export_summary(_graph())
    b = export_summary(_graph())
    assert a == b                              # deterministic


def test_evidence_graph_export() -> None:
    eg = export_evidence_graph(_graph())
    findings = eg["findings"]
    assert any(f["finding"] == "Admin exposed" and f["connected_assets"]
               for f in findings)


# ---------------------------------------------------------------------------
# Validation (Task 12)
# ---------------------------------------------------------------------------


def test_clean_graph_validates() -> None:
    rep = validate_graph(_graph())
    # A clean build has no broken edges / missing metadata / dupes.
    assert rep.broken_edges == []
    assert rep.missing_source == []
    assert rep.duplicate_node_ids == []


def test_validator_flags_orphan_finding() -> None:
    # A finding with no resolvable target (no page, no host) is orphaned.
    g = build_graph(_result(
        grouped=[_gf("Floating finding", engine="unknown_engine")]))
    rep = validate_graph(g)
    assert "Floating finding" in rep.orphan_findings


# ---------------------------------------------------------------------------
# Orchestrator integration (Task 11/13)
# ---------------------------------------------------------------------------


def _transport():
    html = ('<!DOCTYPE html><html><body>'
            '<script src="https://js.stripe.com/v3"></script>'
            '</body></html>')

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/", ""):
            return httpx.Response(200, text=html,
                                  headers={"content-type": "text/html"})
        return httpx.Response(404, text="nf")
    return httpx.MockTransport(handler)


@pytest.mark.anyio
async def test_scan_emits_graph_summary(monkeypatch) -> None:
    from webhound.core.orchestrator import Scanner
    from webhound.engines.tls_dns import dns_checker as _dns
    from webhound.engines.tls_dns import tls_checker as _tls
    from webhound.engines.tls_dns.dns_checker import DnsRecords
    from webhound.engines.tls_dns.tls_checker import TlsCertInfo
    from webhound.models.scan_result import ScanStatus
    from webhound.models.target import ScanOptions, Target

    monkeypatch.setattr(_tls, "probe_tls",
                        lambda *a, **k: TlsCertInfo(domain="t.test",
                                                    connection_failed=True))
    monkeypatch.setattr(_dns, "resolve_dns",
                        lambda *a, **k: DnsRecords(domain="t.test",
                                                   a=["1.2.3.4"]))
    t = Target.from_url("https://t.test", scan_options=ScanOptions(
        max_pages=2, max_depth=1, rate_limit_rps=10.0, verify_tls=False))
    result = await Scanner(t, _transport=_transport()).scan()
    assert result.status == ScanStatus.COMPLETED
    g = result.metadata.get("security_graph_summary")
    assert g is not None
    assert g["node_count"] >= 1
    assert "node_types" in g
    # Compact only — the raw graph is not in scan metadata.
    assert "nodes" not in g
