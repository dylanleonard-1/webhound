"""Phase 8D: WADE Reasoning Engine — test suite.

Tests: single-finding reasoning, multi-finding correlation, attack chains,
root cause, confidence, priority, executive summaries, graph/memory (skip
gracefully when services absent). CI-safe — all infra tests skip without
Neo4j/Graphiti.

Run: .venv-api/Scripts/python -m pytest tests/ai/test_wade_reasoning_engine.py -v
"""
from __future__ import annotations

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, ROOT)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(ft: str, provider: str | None = None) -> "Finding":
    from scripts.wade.reasoning.models import Finding
    return Finding(finding_type=ft, provider=provider, detail="test finding")


def _supply_chain_set():
    return [
        _make_finding("missing_csp"),
        _make_finding("third_party_script_risk"),
    ]


def _session_weakness_set():
    return [
        _make_finding("missing_secure_cookie"),
        _make_finding("missing_httponly_cookie"),
        _make_finding("missing_hsts"),
    ]


def _compromise_set():
    return [
        _make_finding("exposed_env"),
        _make_finding("threat_intel_match"),
        _make_finding("graphql_exposure"),
    ]


# ── Package imports ────────────────────────────────────────────────────────────

def test_reasoning_package_importable():
    import scripts.wade.reasoning  # noqa: F401


def test_all_exports_present():
    from scripts.wade.reasoning import (
        Finding, ReasoningResult, ReasoningEvidence, ReasoningChain,
        ReasoningExplanation, ReasoningConfidence, ConfidenceLevel, PriorityLevel,
        ConfidenceFactors, build_confidence, factors_from_retrieval,
        CorrelationContext, CorrelationExplanation, CorrelationConfidence,
        correlate_findings,
        AttackChainCandidate, AttackChainExplanation, AttackChainConfidence,
        identify_attack_chains,
        RootCauseReasoner, RootCauseResult, RootCauseSummary,
        RootCauseConfidence, RootCauseEvidence,
        PriorityReasoner, PriorityRecommendation, PriorityExplanation,
        ExecutiveSummary, generate_executive_summary,
        GraphReasoner, GraphReasoningResult,
        MemoryReasoner, MemoryReasoningResult,
        WADEShadowReasoner, ShadowReasoningPackage,
    )
    assert callable(correlate_findings)
    assert callable(identify_attack_chains)
    assert callable(generate_executive_summary)


# ── Models ────────────────────────────────────────────────────────────────────

def test_finding_model():
    f = _make_finding("missing_csp", provider="cloudflare")
    assert f.finding_type == "missing_csp"
    assert f.provider == "cloudflare"


def test_reasoning_chain_builds():
    from scripts.wade.reasoning.models import ReasoningChain
    chain = ReasoningChain()
    chain.add("Step 1")
    chain.add("Step 2")
    assert len(chain.steps) == 2
    assert "Step 1 → Step 2" == chain.as_text()


def test_reasoning_result_summary_dict():
    from scripts.wade.reasoning.models import (
        ReasoningResult, ReasoningEvidence, ReasoningChain,
        ReasoningExplanation, ReasoningConfidence, ConfidenceLevel,
    )
    r = ReasoningResult(
        finding_type="missing_csp",
        advisory_label="ADVISORY",
        evidence=[],
        explanation=ReasoningExplanation(
            summary="CSP absent",
            detail="detail",
            chain=ReasoningChain(),
        ),
        confidence=ReasoningConfidence(
            level=ConfidenceLevel.MEDIUM,
            score=0.55,
            explanation="Medium confidence",
        ),
    )
    d = r.summary_dict()
    assert d["finding_type"] == "missing_csp"
    assert d["production_unchanged"] is True
    assert "confidence" in d


# ── Confidence ────────────────────────────────────────────────────────────────

def test_confidence_factors_weighted_score():
    from scripts.wade.reasoning.confidence import ConfidenceFactors
    f = ConfidenceFactors(
        source_authority=0.8,
        evidence_quality=0.8,
        provider_effects=0.9,
        false_positive_signals=0.9,
    )
    score = f.weighted_score()
    assert 0.0 <= score <= 1.0


def test_build_confidence_high():
    from scripts.wade.reasoning.confidence import ConfidenceFactors, build_confidence
    from scripts.wade.reasoning.models import ConfidenceLevel
    f = ConfidenceFactors(
        source_authority=0.9,
        evidence_quality=0.9,
        provider_effects=0.95,
        finding_consistency=0.8,
        false_positive_signals=0.95,
    )
    result = build_confidence(f, finding_type="exposed_env", retrieval_chunks=5)
    assert result.level == ConfidenceLevel.HIGH
    assert result.score > 0.7


def test_build_confidence_low_provider():
    from scripts.wade.reasoning.confidence import ConfidenceFactors, build_confidence
    from scripts.wade.reasoning.models import ConfidenceLevel
    f = ConfidenceFactors(provider_effects=0.2, false_positive_signals=0.3)
    result = build_confidence(f, finding_type="cloudflare_challenge_page")
    assert result.level in (ConfidenceLevel.LOW, ConfidenceLevel.INSUFFICIENT)
    assert "provider" in result.explanation.lower() or "false" in result.explanation.lower()


def test_factors_from_retrieval_provider_type():
    from scripts.wade.reasoning.confidence import factors_from_retrieval
    factors = factors_from_retrieval("cloudflare_challenge_page", [])
    assert factors.provider_effects < 0.5


def test_factors_from_retrieval_with_chunks():
    from scripts.wade.reasoning.confidence import factors_from_retrieval
    chunks = [{"authority": "OWASP"}, {"authority": "CWE"}, {"authority": "corpus"}]
    factors = factors_from_retrieval("missing_csp", chunks)
    assert factors.source_authority >= 0.8


# ── Correlation ───────────────────────────────────────────────────────────────

def test_supply_chain_correlation_fires():
    from scripts.wade.reasoning.correlation import correlate_findings
    results = correlate_findings(_supply_chain_set())
    names = [r.pattern_name for r in results]
    assert "supply_chain_exposure" in names


def test_session_weakness_correlation_fires():
    from scripts.wade.reasoning.correlation import correlate_findings
    results = correlate_findings(_session_weakness_set())
    names = [r.pattern_name for r in results]
    assert "session_protection_weakness" in names


def test_elevated_compromise_correlation_fires():
    from scripts.wade.reasoning.correlation import correlate_findings
    results = correlate_findings(_compromise_set())
    names = [r.pattern_name for r in results]
    assert "elevated_compromise_risk" in names


def test_no_correlation_single_finding():
    from scripts.wade.reasoning.correlation import correlate_findings
    results = correlate_findings([_make_finding("missing_csp")])
    assert results == []


def test_correlation_all_advisory():
    from scripts.wade.reasoning.correlation import correlate_findings
    results = correlate_findings(_supply_chain_set() + _session_weakness_set())
    for r in results:
        assert r.advisory_only is True


def test_correlation_summary_dict():
    from scripts.wade.reasoning.correlation import correlate_findings
    results = correlate_findings(_supply_chain_set())
    d = results[0].summary_dict()
    assert "pattern" in d
    assert "advisory_only" in d


def test_correlation_has_evidence_chain():
    from scripts.wade.reasoning.correlation import correlate_findings
    results = correlate_findings(_supply_chain_set())
    sc = next(r for r in results if r.pattern_name == "supply_chain_exposure")
    assert len(sc.explanation.chain.steps) >= 2


# ── Attack chains ─────────────────────────────────────────────────────────────

def test_supply_chain_attack_chain_fires():
    from scripts.wade.reasoning.attack_chain import identify_attack_chains
    chains = identify_attack_chains(_supply_chain_set())
    names = [c.chain_name for c in chains]
    assert "supply_chain_client_compromise" in names


def test_admin_takeover_chain_fires():
    from scripts.wade.reasoning.attack_chain import identify_attack_chains
    findings = [_make_finding("exposed_env"), _make_finding("wordpress_xmlrpc")]
    chains = identify_attack_chains(findings)
    names = [c.chain_name for c in chains]
    assert "admin_credential_takeover" in names


def test_attack_chains_all_advisory():
    from scripts.wade.reasoning.attack_chain import identify_attack_chains
    chains = identify_attack_chains(_supply_chain_set())
    for c in chains:
        assert c.advisory_only is True


def test_attack_chain_has_mitigations():
    from scripts.wade.reasoning.attack_chain import identify_attack_chains
    chains = identify_attack_chains(_supply_chain_set())
    sc = next(c for c in chains if c.chain_name == "supply_chain_client_compromise")
    assert len(sc.explanation.mitigations) >= 1


def test_attack_chain_summary_dict():
    from scripts.wade.reasoning.attack_chain import identify_attack_chains
    chains = identify_attack_chains(_supply_chain_set())
    d = chains[0].summary_dict()
    assert "chain" in d and "advisory_only" in d


def test_no_chain_provider_only():
    from scripts.wade.reasoning.attack_chain import identify_attack_chains
    chains = identify_attack_chains([_make_finding("cloudflare_challenge_page")])
    assert chains == []


# ── Root cause ────────────────────────────────────────────────────────────────

def test_root_cause_deploy_misconfiguration():
    from scripts.wade.reasoning.root_cause import RootCauseReasoner
    findings = [
        _make_finding("missing_csp"),
        _make_finding("missing_hsts"),
        _make_finding("missing_x_frame_options"),
    ]
    results = RootCauseReasoner().analyse(findings)
    cats = [r.summary.category for r in results]
    assert "deploy_misconfiguration" in cats


def test_root_cause_provider_behavior():
    from scripts.wade.reasoning.root_cause import RootCauseReasoner
    findings = [_make_finding("cloudflare_challenge_page")]
    results = RootCauseReasoner().analyse(findings)
    cats = [r.summary.category for r in results]
    assert "provider_behavior" in cats


def test_root_cause_secret_exposure():
    from scripts.wade.reasoning.root_cause import RootCauseReasoner
    results = RootCauseReasoner().analyse([_make_finding("exposed_env")])
    cats = [r.summary.category for r in results]
    assert "secret_exposure" in cats


def test_root_cause_has_remediation():
    from scripts.wade.reasoning.root_cause import RootCauseReasoner
    results = RootCauseReasoner().analyse([
        _make_finding("missing_csp"),
        _make_finding("missing_hsts"),
    ])
    for r in results:
        assert r.summary.remediation_hint
        assert r.advisory_only is True


def test_root_cause_summary_dict():
    from scripts.wade.reasoning.root_cause import RootCauseReasoner
    results = RootCauseReasoner().analyse([_make_finding("exposed_env")])
    d = results[0].summary_dict()
    assert "root_cause" in d and "advisory_only" in d


# ── Priority ──────────────────────────────────────────────────────────────────

def test_priority_critical_finding():
    from scripts.wade.reasoning.priority import PriorityReasoner
    from scripts.wade.reasoning.models import PriorityLevel
    rec = PriorityReasoner().prioritize(_make_finding("exposed_env"))
    assert rec.advisory_priority == PriorityLevel.IMMEDIATE


def test_priority_provider_deprioritized():
    from scripts.wade.reasoning.priority import PriorityReasoner
    from scripts.wade.reasoning.models import PriorityLevel
    rec = PriorityReasoner().prioritize(_make_finding("cloudflare_challenge_page"))
    assert rec.advisory_priority in (PriorityLevel.LOW, PriorityLevel.MEDIUM)


def test_priority_set_sorted():
    from scripts.wade.reasoning.priority import PriorityReasoner
    findings = [
        _make_finding("exposed_env"),
        _make_finding("missing_hsts"),
        _make_finding("cloudflare_challenge_page"),
    ]
    recs = PriorityReasoner().prioritize_set(findings)
    levels = [r.advisory_priority.value for r in recs]
    order = ["IMMEDIATE", "HIGH", "MEDIUM", "LOW"]
    for i in range(len(levels) - 1):
        assert order.index(levels[i]) <= order.index(levels[i + 1])


def test_priority_advisory_only():
    from scripts.wade.reasoning.priority import PriorityReasoner
    rec = PriorityReasoner().prioritize(_make_finding("missing_csp"))
    assert rec.advisory_only is True


def test_priority_explanation_has_factors():
    from scripts.wade.reasoning.priority import PriorityReasoner
    rec = PriorityReasoner().prioritize(_make_finding("exposed_env"))
    assert rec.explanation.factors
    assert rec.explanation.summary


# ── Executive summary ─────────────────────────────────────────────────────────

def test_executive_summary_empty():
    from scripts.wade.reasoning.executive import generate_executive_summary
    s = generate_executive_summary([])
    assert s.overall_posture == "No findings to summarize"
    assert s.critical_count == 0


def test_executive_summary_critical():
    from scripts.wade.reasoning.executive import generate_executive_summary
    findings = [_make_finding("exposed_env"), _make_finding("exposed_git")]
    s = generate_executive_summary(findings)
    assert "Critical" in s.overall_posture or s.critical_count > 0


def test_executive_summary_informational():
    from scripts.wade.reasoning.executive import generate_executive_summary
    findings = [_make_finding("cloudflare_challenge_page")]
    s = generate_executive_summary(findings)
    assert s.informational_count == 1
    assert s.critical_count == 0


def test_executive_summary_customer_language():
    from scripts.wade.reasoning.executive import generate_executive_summary
    findings = [_make_finding("exposed_env")]
    s = generate_executive_summary(findings)
    assert any("configuration" in c.lower() or "sensitive" in c.lower()
               for c in s.top_concerns)


def test_executive_summary_dict():
    from scripts.wade.reasoning.executive import generate_executive_summary
    s = generate_executive_summary([_make_finding("missing_csp")])
    d = s.summary_dict()
    assert "overall_posture" in d and "narrative" in d


# ── Graph reasoning (skip if Neo4j absent) ───────────────────────────────────

def test_graph_reasoner_degrades_gracefully_offline():
    from scripts.wade.reasoning.graph_reasoning import GraphReasoner
    g = GraphReasoner(uri="bolt://localhost:19999")  # unlikely to be running
    result = g.get_cwe_related_findings("missing_csp")
    assert result.graph_available is False or result.finding_type == "missing_csp"


def test_graph_reasoner_offline_has_caveat():
    from scripts.wade.reasoning.graph_reasoning import GraphReasoner
    g = GraphReasoner(uri="bolt://localhost:19999")
    result = g.get_cwe_related_findings("missing_csp")
    if not result.graph_available:
        assert len(result.caveats) > 0


@pytest.mark.skipif(
    os.environ.get("NEO4J_AVAILABLE") != "1",
    reason="NEO4J_AVAILABLE=1 not set — skipping live graph tests",
)
def test_graph_reasoner_live_query():
    from scripts.wade.reasoning.graph_reasoning import GraphReasoner
    g = GraphReasoner()
    assert g.available
    result = g.get_cwe_related_findings("missing_csp")
    assert result.graph_available is True
    g.close()


# ── Memory reasoning (skip if Graphiti absent) ────────────────────────────────

def test_memory_reasoner_degrades_gracefully():
    from scripts.wade.reasoning.memory_reasoning import MemoryReasoner
    m = MemoryReasoner(neo4j_uri="bolt://localhost:19999")
    result = m.recall_similar_findings(
        "missing_csp",
        tenant_id="test-tenant-001",
    )
    assert result.memory_available is False or result.finding_type == "missing_csp"
    assert result.tenant_isolation_verified is True


def test_memory_reasoner_tenant_isolation_flag():
    from scripts.wade.reasoning.memory_reasoning import MemoryReasoner
    m = MemoryReasoner(neo4j_uri="bolt://localhost:19999")
    result = m.recall_similar_findings("exposed_env", tenant_id="t-123")
    assert result.tenant_id == "t-123"
    assert result.tenant_isolation_verified is True


@pytest.mark.skipif(
    not os.environ.get("GRAPHITI_AVAILABLE"),
    reason="GRAPHITI_AVAILABLE not set — skipping live memory tests",
)
def test_memory_reasoner_live():
    from scripts.wade.reasoning.memory_reasoning import MemoryReasoner
    m = MemoryReasoner()
    assert m.available
    result = m.recall_similar_findings("missing_csp", tenant_id="test-001")
    assert result.memory_available is True


# ── Shadow mode ───────────────────────────────────────────────────────────────

def test_shadow_reasoner_full_pipeline():
    from scripts.wade.reasoning.shadow_mode import WADEShadowReasoner
    findings = _supply_chain_set() + _session_weakness_set()
    pkg = WADEShadowReasoner().analyze(findings, scan_id="test-001")
    assert pkg.production_unchanged is True
    assert len(pkg.correlations) >= 1
    assert len(pkg.priority_recommendations) == len(findings)
    assert pkg.executive_summary is not None


def test_shadow_reasoner_as_dict():
    from scripts.wade.reasoning.shadow_mode import WADEShadowReasoner
    pkg = WADEShadowReasoner().analyze(_supply_chain_set(), scan_id="test-dict")
    d = pkg.as_dict()
    assert d["production_unchanged"] is True
    assert "correlations" in d and "attack_chains" in d


def test_shadow_reasoner_delta_vs_production():
    from scripts.wade.reasoning.shadow_mode import WADEShadowReasoner
    findings = [_make_finding("exposed_env"), _make_finding("missing_hsts")]
    pkg = WADEShadowReasoner().analyze(findings)
    prod = {"exposed_env": "CRITICAL", "missing_hsts": "LOW"}
    delta = pkg.delta_vs_production(prod)
    assert delta["production_unchanged"] is True
    assert "total_findings" in delta


def test_shadow_single_finding():
    from scripts.wade.reasoning.shadow_mode import WADEShadowReasoner
    result = WADEShadowReasoner().analyze_single(_make_finding("missing_csp"))
    assert result.production_unchanged is True
    assert result.finding_type == "missing_csp"
    assert result.advisory_label == "ADVISORY"
    assert result.explanation.chain.steps


def test_shadow_single_with_retrieval():
    from scripts.wade.reasoning.shadow_mode import WADEShadowReasoner
    chunks = [
        {"chunk_id": "c1", "text": "CSP prevents XSS", "authority": "OWASP", "score": 0.9},
        {"chunk_id": "c2", "text": "Content-Security-Policy header", "authority": "CWE", "score": 0.8},
    ]
    result = WADEShadowReasoner().analyze_single(
        _make_finding("missing_csp"),
        retrieval_chunks=chunks,
    )
    assert result.retrieval_chunks_used == 2
    assert len(result.evidence) >= 1


def test_shadow_reasoning_empty_findings():
    from scripts.wade.reasoning.shadow_mode import WADEShadowReasoner
    pkg = WADEShadowReasoner().analyze([], scan_id="empty")
    assert pkg.production_unchanged is True
    assert pkg.findings_analyzed == []
    assert pkg.correlations == []


# ── Production unchanged assertion ────────────────────────────────────────────

def test_production_scoring_unchanged():
    """Verify nothing in the reasoning engine touches production WADE scoring."""
    from scripts.wade.reasoning.shadow_mode import WADEShadowReasoner
    findings = _compromise_set()
    pkg = WADEShadowReasoner().analyze(findings)
    assert pkg.production_unchanged is True
    for rec in pkg.priority_recommendations:
        assert rec.advisory_only is True
    for corr in pkg.correlations:
        assert corr.advisory_only is True
    for chain in pkg.attack_chains:
        assert chain.advisory_only is True
    for rc in pkg.root_causes:
        assert rc.advisory_only is True
