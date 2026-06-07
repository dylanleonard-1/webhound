# WebHound — scanner/webhound/advisor/advisor_engine.py
# Phase-15: the WADE Security Advisor top-level. Given a scan result (+
# optional monitoring context), it assembles the complete advisory: a
# per-finding explanation, priority ordering, business impact, the action
# plan, the remediation roadmap, a trend explanation, and answers to the
# common customer questions (Task 6 Q&A foundation).
#
# Pure — consumes the metadata the scan already produced; writes nothing
# back. The orchestrator stores the result under metadata.advisor.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.advisor.action_plan import build_action_plan
from webhound.advisor.business_impact import assess_impact
from webhound.advisor.change_explainer import explain_change, explain_trend
from webhound.advisor.priority_explainer import explain_priorities
from webhound.advisor.recommendation_engine import build_remediation_roadmap
from webhound.advisor.risk_explainer import explain_finding
from webhound.core.trust_policy import finding_type_of


@dataclass
class FindingAdvice:
    title: str
    finding_type: str
    explanation: dict[str, Any]
    business_impact: dict[str, Any]
    action: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "finding_type": self.finding_type,
            "explanation": self.explanation,
            "business_impact": self.business_impact,
            "action": self.action,
        }


@dataclass
class Advisory:
    findings: list[FindingAdvice] = field(default_factory=list)
    priorities: list[dict[str, Any]] = field(default_factory=list)
    action_plan: dict[str, Any] = field(default_factory=dict)
    roadmap: list[dict[str, Any]] = field(default_factory=list)
    trend: dict[str, Any] | None = None
    qa: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "priorities": list(self.priorities),
            "action_plan": self.action_plan,
            "remediation_roadmap": list(self.roadmap),
            "trend": self.trend,
            "qa": dict(self.qa),
        }


def _answer_questions(
    result_meta: dict[str, Any],
    roadmap: list,
    action_plan: dict[str, Any],
    trend: dict[str, Any] | None,
    priorities: list[dict[str, Any]],
) -> dict[str, str]:
    """Task 6: precomputed answers to the common customer questions."""
    qa: dict[str, str] = {}

    # What should I fix first?
    if action_plan.get("fix_now"):
        first = action_plan["fix_now"][0]["title"]
        qa["what_should_i_fix_first"] = (
            f"Start with: {first}. " + (priorities[0]["explanation"]
                                        if priorities else ""))
    elif roadmap:
        qa["what_should_i_fix_first"] = (
            f"Step 1: {roadmap[0]['title']} — {roadmap[0]['recommendation']}")
    else:
        qa["what_should_i_fix_first"] = (
            "Nothing urgent — focus on the hardening recommendations when "
            "convenient.")

    # Did my website get hacked?
    compromise = [f for f in result_meta.get("security_stories", [])
                  if f.get("correlation_type") == "possible_compromise"]
    threat_corr = result_meta.get("threat_correlations", [])
    if compromise or any(c.get("correlation_type") in
                         ("possible_skimmer", "possible_website_compromise")
                         for c in threat_corr):
        qa["did_my_website_get_hacked"] = (
            "WebHound found indicators consistent with tampering. This is "
            "not a confirmation of a breach, but it warrants prompt "
            "investigation — see the Fix Now items.")
    else:
        qa["did_my_website_get_hacked"] = (
            "No compromise indicators were detected this scan. The findings "
            "are configuration and hardening items, not signs of a breach.")

    # Is this serious?
    level = result_meta.get("risk_level", "safe")
    qa["is_this_serious"] = {
        "critical": "Yes — there are critical issues that need immediate "
                    "attention.",
        "high": "There are high-priority issues worth fixing soon.",
        "medium": "There are meaningful issues to review and schedule.",
        "low": "Mostly minor — a few items to tidy up.",
        "safe": "No — your site is in good shape; remaining items are "
                "hardening.",
    }.get(level, "Review the findings to decide.")

    # Why did my score change? / What improved? / What got worse?
    if trend:
        qa["why_did_my_score_change"] = (
            trend.get("headline", "") + " " + trend.get("detail", "")).strip()
        direction = trend.get("is_alarming")
        qa["what_got_worse" if direction else "what_improved"] = \
            trend.get("detail", "")

    return qa


def build_advisory(
    result: Any,
    *,
    risk_delta: Any = None,
    wade_change_events: list[Any] | None = None,
) -> Advisory:
    """Build the full advisory for a completed scan.

    ``result`` is a ScanResult (uses grouped_findings + metadata).
    ``risk_delta`` (monitoring.RiskDelta or dict) drives the trend
    explanation; ``wade_change_events`` (ChangeEvents) get plain-language
    change explanations folded into the advisory."""
    grouped = list(getattr(result, "grouped_findings", []) or [])
    meta = getattr(result, "metadata", {}) or {}

    # Per-finding advice (skip pure inventory in the headline list but
    # keep it available).
    advice: list[FindingAdvice] = []
    plan = build_action_plan(grouped)
    action_by_title = {i.title: i for i in plan.items}
    for f in grouped:
        advice.append(FindingAdvice(
            title=getattr(f, "title", ""),
            finding_type=finding_type_of(f),
            explanation=explain_finding(f).to_dict(),
            business_impact=assess_impact(f).to_dict(),
            action=(action_by_title.get(getattr(f, "title", ""))
                    .to_dict() if getattr(f, "title", "") in action_by_title
                    else {})))

    priorities = [p.to_dict() for p in explain_priorities(grouped)]
    action_plan = plan.to_dict()
    roadmap = [s.to_dict() for s in build_remediation_roadmap(grouped)]

    trend = None
    if risk_delta is not None:
        trend = explain_trend(risk_delta).to_dict()

    # Change explanations (Task 2) folded into the advisory's qa context.
    if wade_change_events:
        change_expls = [explain_change(e).to_dict()
                        for e in wade_change_events]
        meta = {**meta, "_change_explanations": change_expls}

    qa = _answer_questions(meta, roadmap, action_plan, trend, priorities)

    return Advisory(
        findings=advice, priorities=priorities, action_plan=action_plan,
        roadmap=roadmap, trend=trend, qa=qa)
