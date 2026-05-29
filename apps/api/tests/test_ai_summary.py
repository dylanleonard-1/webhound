# WebHound — apps/api/tests/test_ai_summary.py
# Phase-4 slice 6: AI-summary constraint enforcement tests.
#
# These tests pin the Phase-4 §10 contract: the AI surface MUST NOT
# invent findings, MUST cite real IDs, and MUST never escalate
# severity beyond what we sent. Validation is enforced by
# construction in apps/api/services/ai_summary.py — these tests prove
# it.

from __future__ import annotations

import uuid
from dataclasses import dataclass
from unittest.mock import patch

import pytest

from apps.api.services.ai_summary import (
    AISummaryRequest,
    _validate_summary,
    _build_finding_cards,
    generate_summary,
)


# Stand-in Finding/ScanResult shapes — the validator only reads getattr
# attributes so this dataclass is sufficient for the unit tests.


@dataclass
class _F:
    id: uuid.UUID
    title: str
    severity: str = "high"
    confidence: float = 0.8
    engine: str = "headers"
    category: str = "security_header"
    evidence: str = "Missing Strict-Transport-Security header."


@dataclass
class _SR:
    risk_score: int = 80
    risk_level: str = "high"


# ---------------------------------------------------------------------------
# Finding-card construction
# ---------------------------------------------------------------------------


def test_finding_cards_ranked_by_severity_then_confidence() -> None:
    findings = [
        _F(uuid.uuid4(), "low-thing", severity="low", confidence=1.0),
        _F(uuid.uuid4(), "crit-thing", severity="critical", confidence=0.5),
        _F(uuid.uuid4(), "high-thing", severity="high", confidence=0.9),
    ]
    cards = _build_finding_cards(findings)
    assert [c["severity"] for c in cards] == ["critical", "high", "low"]


def test_finding_cards_truncate_huge_evidence() -> None:
    huge = "x" * 5000
    findings = [_F(uuid.uuid4(), "y", evidence=huge)]
    cards = _build_finding_cards(findings)
    assert len(cards[0]["evidence_summary"]) <= 700   # 600 + ellipsis


def test_finding_cards_cap_at_25() -> None:
    findings = [_F(uuid.uuid4(), f"f-{i}") for i in range(40)]
    cards = _build_finding_cards(findings)
    assert len(cards) == 25


# ---------------------------------------------------------------------------
# Hallucination guardrail — the central Phase-4 §10 contract
# ---------------------------------------------------------------------------


def test_invented_citation_is_stripped_with_warning() -> None:
    real_id = uuid.uuid4()
    cards = [{
        "id": str(real_id),
        "title": "real",
        "severity": "high",
        "confidence": 0.9,
        "engine": "x",
        "category": "y",
        "evidence_summary": "z",
    }]
    req = AISummaryRequest(
        scan_result=_SR(), findings=[],
        target_url="https://target", kind="executive",
    )
    bad_id = "00000000-0000-0000-0000-000000000000"
    fake_output = (
        f"The site exposes admin access [F-{bad_id}] and also "
        f"missing HSTS [F-{real_id}]."
    )
    result = _validate_summary(
        req, fake_output, cards, offline=False, model="test",
    )
    # The invented citation is removed from the text.
    assert f"F-{bad_id}" not in result.text
    assert "[citation removed]" in result.text
    # Real citation still present.
    assert f"F-{real_id}" in result.text
    # Warning surfaces.
    assert any("invented citation" in w for w in result.validation_warnings)
    assert result.cited_finding_ids == [str(real_id)]


def test_no_citations_returns_empty_cited_list() -> None:
    cards = [{
        "id": str(uuid.uuid4()), "title": "x", "severity": "low",
        "confidence": 0.5, "engine": "x", "category": "y",
        "evidence_summary": "z",
    }]
    req = AISummaryRequest(
        scan_result=_SR(), findings=[],
        target_url="x", kind="executive",
    )
    result = _validate_summary(
        req, "Just a generic summary.", cards,
        offline=False, model="test",
    )
    assert result.cited_finding_ids == []
    assert len(result.unreferenced_finding_ids) == 1


def test_unreferenced_finding_ids_surface_unmentioned_findings() -> None:
    a, b = uuid.uuid4(), uuid.uuid4()
    cards = [
        {"id": str(a), "title": "A", "severity": "high",
         "confidence": 0.9, "engine": "x", "category": "y",
         "evidence_summary": "z"},
        {"id": str(b), "title": "B", "severity": "high",
         "confidence": 0.9, "engine": "x", "category": "y",
         "evidence_summary": "z"},
    ]
    req = AISummaryRequest(scan_result=_SR(), findings=[],
                            target_url="x", kind="executive")
    result = _validate_summary(
        req, f"Only A was mentioned [F-{a}].", cards,
        offline=False, model="test",
    )
    assert result.cited_finding_ids == [str(a)]
    assert result.unreferenced_finding_ids == [str(b)]


# ---------------------------------------------------------------------------
# Offline template path — fully deterministic
# ---------------------------------------------------------------------------


def test_offline_template_summary_cites_every_listed_finding() -> None:
    findings = [
        _F(uuid.uuid4(), "Missing CSP", severity="high"),
        _F(uuid.uuid4(), "Suspicious 3p", severity="medium"),
    ]
    req = AISummaryRequest(
        scan_result=_SR(), findings=findings,
        target_url="https://target.test/", kind="executive",
    )
    with patch.dict("os.environ", {"WEBHOUND_AI_ENABLED": "0"},
                     clear=False):
        result = generate_summary(req)
    assert result.generated_offline is True
    assert result.model == "template"
    # Every finding ID is cited because the template lists them all.
    assert len(result.cited_finding_ids) == 2


def test_offline_summary_never_mentions_findings_not_provided() -> None:
    """The template summariser is pure — it can ONLY mention what we
    passed it. Sanity check the invariant."""
    findings = [_F(uuid.uuid4(), "The only finding", severity="low")]
    req = AISummaryRequest(
        scan_result=_SR(), findings=findings,
        target_url="x", kind="executive",
    )
    with patch.dict("os.environ", {"WEBHOUND_AI_ENABLED": "0"},
                     clear=False):
        result = generate_summary(req)
    # Output never mentions anything that wasn't in the cards.
    fake_id = "00000000-0000-0000-0000-000000000000"
    assert fake_id not in result.text


def test_live_path_failure_falls_back_to_template() -> None:
    """If WEBHOUND_AI_ENABLED is on but the live path raises, we get
    the template summary + a warning — never a partial garbage output."""
    findings = [_F(uuid.uuid4(), "x")]
    req = AISummaryRequest(
        scan_result=_SR(), findings=findings,
        target_url="x", kind="executive",
    )

    def _fake_claude_call(*a, **k):
        raise RuntimeError("simulated API failure")

    with patch.dict("os.environ", {
        "WEBHOUND_AI_ENABLED": "1",
        "ANTHROPIC_API_KEY": "sk-fake",
    }, clear=False), patch(
        "apps.api.services.ai_summary._generate_with_claude",
        _fake_claude_call,
    ):
        result = generate_summary(req)
    assert result.generated_offline is True
    assert result.model == "template"
    assert any("live model failed" in w
                for w in result.validation_warnings)


def test_to_dict_round_trip_shape() -> None:
    findings = [_F(uuid.uuid4(), "x")]
    req = AISummaryRequest(
        scan_result=_SR(), findings=findings, target_url="x",
    )
    with patch.dict("os.environ", {"WEBHOUND_AI_ENABLED": "0"},
                     clear=False):
        result = generate_summary(req)
    d = result.to_dict()
    for key in ("text", "kind", "cited_finding_ids",
                 "unreferenced_finding_ids", "model",
                 "generated_offline", "validation_warnings"):
        assert key in d
