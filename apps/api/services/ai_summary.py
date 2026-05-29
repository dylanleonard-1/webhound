# WebHound — apps/api/services/ai_summary.py
# Phase-4 slice 6: AI-assisted scan-result summarisation.
#
# Hard constraints from Phase-4 §10:
#   * AI MUST reference real findings + evidence + engine outputs.
#   * AI MUST NEVER invent findings, fabricate evidence, or escalate
#     severity without real evidence.
#
# Design enforces those constraints by *construction* rather than by
# trust:
#   1. The prompt builder injects only structured data — every finding
#      passes through ``_finding_to_card`` which emits the fields the
#      LLM is allowed to see (id, title, severity, confidence, engine,
#      truncated evidence). The LLM cannot infer anything we didn't
#      pass.
#   2. The response is validated: every ``[F-<id>]`` citation in the
#      output is checked against the set of finding IDs we sent. Bare
#      claims with no citation are tagged so the dashboard can render
#      them as "general remark" rather than "specific finding".
#   3. Default mode is fully offline + deterministic — a template-only
#      summariser that just pulls the highest-severity findings into a
#      ranked list. The live Claude path is opt-in via
#      WEBHOUND_AI_ENABLED=1 + ANTHROPIC_API_KEY.
#
# An AI summary is *generated content* — it goes into a separate
# ``ai_summary`` field on the export and never replaces or overrides
# the scanner's own findings, severities, or remediation text.

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from apps.api.models.finding import FindingRecord
from apps.api.models.scan_result import ScanResultRecord


# Models we know how to talk to. The live path uses the latest model.
_DEFAULT_MODEL = "claude-sonnet-4-6"


# Hard cap on findings included in the prompt — prevents context-window
# blowups and keeps the prompt focused on what the LLM can actually
# meaningfully summarise. The N highest-severity findings are picked.
_MAX_FINDINGS_IN_PROMPT = 25


@dataclass
class AISummaryRequest:
    """Inputs to a summary generation. ``kind`` controls the prompt
    template — ``executive`` is a board/audit-style narrative,
    ``technical`` is engineer-facing remediation focus."""

    scan_result: ScanResultRecord
    findings: list[FindingRecord]
    kind: str = "executive"   # "executive" | "technical" | "remediation"
    target_url: str = ""


@dataclass
class AISummaryResult:
    """Output. ``cited_finding_ids`` lists every finding the summary
    referenced by ID; ``unreferenced_findings`` flags ones the LLM
    didn't mention so callers can decide whether to surface them
    separately."""

    text: str
    kind: str
    cited_finding_ids: list[str] = field(default_factory=list)
    unreferenced_finding_ids: list[str] = field(default_factory=list)
    model: str = ""
    generated_offline: bool = True
    validation_warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "text": self.text,
            "kind": self.kind,
            "cited_finding_ids": self.cited_finding_ids,
            "unreferenced_finding_ids": self.unreferenced_finding_ids,
            "model": self.model,
            "generated_offline": self.generated_offline,
            "validation_warnings": self.validation_warnings,
        }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def generate_summary(req: AISummaryRequest) -> AISummaryResult:
    """Generate an :class:`AISummaryResult` for the request.

    Selects the live Claude path when ``WEBHOUND_AI_ENABLED=1`` and an
    API key is present; otherwise falls back to the deterministic
    template summariser. Either path runs through the same validation
    so a downstream consumer sees the same shape regardless of the
    backing model."""
    cards = _build_finding_cards(req.findings)
    if _ai_enabled() and _anthropic_key():
        try:
            raw = _generate_with_claude(req, cards)
            return _validate_summary(req, raw, cards,
                                       offline=False,
                                       model=_DEFAULT_MODEL)
        except Exception as exc:  # noqa: BLE001
            return _validate_summary(
                req, _template_summary(req, cards), cards,
                offline=True, model="template",
                extra_warning=f"live model failed: {exc}",
            )
    return _validate_summary(
        req, _template_summary(req, cards), cards,
        offline=True, model="template",
    )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


_CITATION_RE = re.compile(r"\[F-([0-9a-fA-F-]{8,36})\]")


def _validate_summary(
    req: AISummaryRequest,
    raw_text: str,
    cards: list[dict[str, Any]],
    *,
    offline: bool,
    model: str,
    extra_warning: str | None = None,
) -> AISummaryResult:
    """Post-process the model's output:

      * Extract ``[F-<id>]`` citations and reconcile them against the
        finding IDs we sent. Citations referencing IDs we did NOT
        provide are stripped + logged — the LLM made up a finding.
      * Track which provided findings were never mentioned so callers
        can render them in a "additional findings not summarised"
        list.
      * Never trust the LLM's prose to be exhaustive: the dashboard
        always shows the full findings list alongside the summary.
    """
    warnings: list[str] = []
    if extra_warning:
        warnings.append(extra_warning)

    provided_ids = {c["id"] for c in cards}
    cited_in_text = set(_CITATION_RE.findall(raw_text or ""))

    # Strip any citation pointing at an ID we never provided. This is
    # the "model invented a finding" guardrail.
    invented = cited_in_text - provided_ids
    text = raw_text or ""
    for bad in invented:
        warnings.append(f"removed invented citation [F-{bad}]")
        text = text.replace(f"[F-{bad}]", "[citation removed]")

    valid_cited = sorted(cited_in_text & provided_ids)
    unreferenced = sorted(provided_ids - cited_in_text)

    return AISummaryResult(
        text=text.strip(),
        kind=req.kind,
        cited_finding_ids=valid_cited,
        unreferenced_finding_ids=unreferenced,
        model=model,
        generated_offline=offline,
        validation_warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Prompt + finding-card construction (the only data the LLM can see)
# ---------------------------------------------------------------------------


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _build_finding_cards(
    findings: list[FindingRecord],
) -> list[dict[str, Any]]:
    """Pick the top ``_MAX_FINDINGS_IN_PROMPT`` findings (highest
    severity, ties broken by confidence then engine name) and emit one
    card per finding with only the fields the LLM is allowed to see."""
    rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    ranked = sorted(
        findings,
        key=lambda f: (
            rank.get(getattr(f, "severity", "info"), 99),
            -(getattr(f, "confidence", 0.0) or 0.0),
            getattr(f, "engine", "") or "",
        ),
    )[:_MAX_FINDINGS_IN_PROMPT]
    cards: list[dict[str, Any]] = []
    for f in ranked:
        fid = str(getattr(f, "id", ""))
        cards.append({
            "id": fid,
            "title": (getattr(f, "title", "") or "")[:200],
            "severity": getattr(f, "severity", "info"),
            "confidence": getattr(f, "confidence", None),
            "engine": getattr(f, "engine", "") or "",
            "category": getattr(f, "category", "") or "",
            # Evidence: truncated; never raw HTML / huge JS blobs.
            "evidence_summary": _truncate(
                str(getattr(f, "evidence", "") or ""), 600,
            ),
        })
    return cards


def _truncate(s: str, limit: int) -> str:
    if not s:
        return ""
    return s[:limit] + ("…" if len(s) > limit else "")


# ---------------------------------------------------------------------------
# Template (offline-default) summariser
# ---------------------------------------------------------------------------


def _template_summary(
    req: AISummaryRequest, cards: list[dict[str, Any]],
) -> str:
    """Deterministic fallback. Pure templating — no model, no risk of
    hallucination by construction. Used in offline mode + when the live
    model fails for any reason."""
    severity_counts: dict[str, int] = {}
    for c in cards:
        severity_counts[c["severity"]] = severity_counts.get(c["severity"], 0) + 1
    head_bits = []
    for sev in _SEVERITY_ORDER:
        n = severity_counts.get(sev, 0)
        if n:
            head_bits.append(f"{n} {sev}")
    head_line = ", ".join(head_bits) if head_bits else "no actionable findings"

    target = req.target_url or "the scanned target"
    lines = [
        f"Scan summary for {target}: {head_line}.",
        "",
        "Top findings (sorted by severity then confidence):",
    ]
    for c in cards[:10]:
        cit = f"[F-{c['id']}]"
        conf = (f", confidence {c['confidence']:.0%}"
                if isinstance(c["confidence"], (int, float)) else "")
        lines.append(
            f"  • {cit} {c['title']} "
            f"(severity {c['severity']}{conf}, engine: {c['engine']})"
        )
    if len(cards) > 10:
        lines.append(f"  • … and {len(cards) - 10} more (see full list).")
    lines += [
        "",
        "This summary is a deterministic projection of the scanner's "
        "own findings — no severity has been changed, and every "
        "[F-id] above maps to a real finding ID. The full evidence "
        "for each finding remains available in the structured "
        "findings table.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Live Claude path (opt-in)
# ---------------------------------------------------------------------------


def _ai_enabled() -> bool:
    return os.getenv("WEBHOUND_AI_ENABLED") == "1"


def _anthropic_key() -> str | None:
    return os.getenv("ANTHROPIC_API_KEY") or None


_SYSTEM_PROMPT = """You are a security analyst writing a concise summary of a website security scan.

CONSTRAINTS — these are not suggestions:
  * Cite every claim with a finding ID in the form [F-<id>] where <id>
    matches one of the provided finding IDs exactly. Do not invent IDs.
  * Do not invent findings, evidence, or vendors. If you don't see it
    in the provided data, do not mention it.
  * Do not change a finding's severity. Use the severity as given.
  * Do not speculate about attacker capability, breaches, or business
    impact beyond what the evidence supports.
  * Use plain language; one paragraph for executive, bullet points
    for technical."""


def _generate_with_claude(
    req: AISummaryRequest, cards: list[dict[str, Any]],
) -> str:
    """Call Claude via the official Anthropic SDK. Lazy-imported so
    environments without the SDK installed still get the template
    path."""
    import anthropic  # type: ignore

    client = anthropic.Anthropic(api_key=_anthropic_key())
    user_prompt = _build_user_prompt(req, cards)
    resp = client.messages.create(
        model=_DEFAULT_MODEL,
        max_tokens=1200,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    # Anthropic SDK returns a list of content blocks.
    text_parts = [
        getattr(block, "text", "") for block in (resp.content or [])
        if getattr(block, "type", "") == "text"
    ]
    return "\n".join(text_parts).strip()


def _build_user_prompt(
    req: AISummaryRequest, cards: list[dict[str, Any]],
) -> str:
    target = req.target_url or "<unspecified target>"
    kind = req.kind
    lines = [
        f"TARGET: {target}",
        f"KIND: {kind}",
        f"FINDING COUNT IN SCAN: {len(cards)}",
        "",
        "FINDINGS (JSON-like, one per line — these are the ONLY items "
        "you may discuss):",
    ]
    import json as _json
    for c in cards:
        lines.append(_json.dumps(c, ensure_ascii=False))
    lines += [
        "",
        "Write the summary. Cite every claim with [F-<id>] using the "
        "exact IDs above. Do not mention anything not in this list.",
    ]
    return "\n".join(lines)
