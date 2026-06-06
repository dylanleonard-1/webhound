# WebHound — scanner/webhound/core/trust_policy.py
# Phase-7 trust policy: every finding gets an explicit finding_type
# and confidence_label so scoring, reporting, and the dashboard stop
# guessing from severity alone.
#
# The five finding types (Task 2):
#   confirmed_risk   — direct evidence of actual risk
#   likely_risk      — strong evidence, not total proof
#   heuristic_signal — pattern-only suspicion
#   hardening        — best-practice improvement, not active risk
#   inventory        — useful discovery, not a risk at all
#
# The five confidence labels (Task 3):
#   confirmed / high / medium / low / heuristic
#
# Key principle: finding TYPE and CONFIDENCE are orthogonal to
# SEVERITY. "Missing Permissions-Policy" is *confirmed* missing — but
# it's hardening, and hardening barely moves the risk score.
#
# Classification is duck-typed over Finding and GroupedFinding (both
# expose title/severity/category/confidence/tags/scanner_engine/
# metadata) and is annotation-only: nothing here changes severity,
# confidence, or evidence.

from __future__ import annotations

import re
from typing import Any, Iterable

from webhound.models.severity import Severity

FINDING_TYPES = (
    "confirmed_risk", "likely_risk", "heuristic_signal",
    "hardening", "inventory",
)
CONFIDENCE_LABELS = ("confirmed", "high", "medium", "low", "heuristic")

# ---------------------------------------------------------------------------
# Hardening detection — best-practice gaps, not active risk.
# ---------------------------------------------------------------------------

# Title patterns that mark a finding as a hardening recommendation
# regardless of engine. Matched case-insensitively.
_HARDENING_TITLE_RE = re.compile(
    r"("
    r"missing\s+(content.security.policy|csp\b)"
    r"|missing\s+(coop|coep|corp)\b"
    r"|cross.origin.(opener|embedder|resource).policy"
    r"|permissions.policy"
    r"|referrer.policy"
    r"|x.content.type.options"
    r"|x.frame.options"
    r"|strict.transport.security|hsts"
    r"|server\s+header"
    r"|x.powered.by"
    r"|missing\s+(spf|dmarc|caa|dnssec)"
    r"|(spf|dmarc|caa|dnssec)\s+(record\s+)?(missing|not\s+(set|found|configured))"
    r"|subresource\s+integrity|sri\b"
    r")",
    re.IGNORECASE,
)

# Tags that explicitly assign a type (engines can opt in directly).
_TYPE_TAGS = {
    "inventory": "inventory",
    "hardening": "hardening",
    "advisory": "hardening",
    "best_practice": "hardening",
    "heuristic": "heuristic_signal",
    "weak_signal": "heuristic_signal",
}

_INVENTORY_TITLE_RE = re.compile(
    r"("
    r"\bobserved\b|\bdetected\b|\binventory\b|\bmapped\b"
    r"|technology|api\s+surface|third.party\s+service"
    r")",
    re.IGNORECASE,
)


def _tags(f: Any) -> set[str]:
    return {t.lower() for t in (getattr(f, "tags", None) or [])}


def confidence_label(f: Any) -> str:
    """Map a finding's confidence (plus explicit tags) to one of the
    five labels. Tags win over the numeric value — an engine that
    knows its detection is pattern-only can say so even at 0.8."""
    tags = _tags(f)
    conf = float(getattr(f, "confidence", 0.0) or 0.0)
    if "heuristic" in tags or "weak_signal" in tags:
        return "heuristic"
    if "confirmed" in tags or conf >= 0.9:
        return "confirmed"
    if conf >= 0.75:
        return "high"
    if conf >= 0.55:
        return "medium"
    if conf >= 0.4:
        return "low"
    return "heuristic"


def classify_finding(f: Any) -> str:
    """Return the finding_type for one finding (annotation not
    applied here — see :func:`apply_trust_policy`)."""
    tags = _tags(f)

    # 1. Explicit engine opt-in always wins.
    for tag, ftype in _TYPE_TAGS.items():
        if tag in tags:
            # advisory/hardening INFO stays hardening; inventory wins
            # over everything else when both present.
            if ftype == "inventory" or "inventory" not in tags:
                return ftype

    title = getattr(f, "title", "") or ""
    severity = getattr(f, "severity", Severity.INFO)
    category = getattr(f, "category", None)
    cat_value = getattr(category, "value", str(category or ""))

    # 2. INFO severity is discovery output by definition.
    if severity == Severity.INFO:
        if _HARDENING_TITLE_RE.search(title):
            return "hardening"
        return "inventory"

    # 3. Hardening: best-practice header/DNS gaps — even when an
    #    engine rated them MEDIUM, the *type* is hardening. (The
    #    severity calibrator separately caps their severity.)
    if cat_value == "security_header" or _HARDENING_TITLE_RE.search(title):
        return "hardening"

    # 4. Pure inventory shapes that carry a non-INFO severity by
    #    accident of engine history.
    if cat_value == "technology" and _INVENTORY_TITLE_RE.search(title):
        return "inventory"

    # 5. Everything else: risk, tiered by confidence.
    label = confidence_label(f)
    if label == "confirmed":
        return "confirmed_risk"
    if label in ("high", "medium"):
        return "likely_risk"
    return "heuristic_signal"


def apply_trust_policy(findings: Iterable[Any]) -> None:
    """Annotate every finding in-place with metadata.finding_type and
    metadata.confidence_label. Existing explicit annotations (set by
    an engine that knows better) are preserved."""
    for f in findings:
        md = getattr(f, "metadata", None)
        if md is None:
            md = {}
            try:
                f.metadata = md
            except Exception:  # noqa: BLE001
                continue
        if not md.get("finding_type"):
            md["finding_type"] = classify_finding(f)
        if not md.get("confidence_label"):
            md["confidence_label"] = confidence_label(f)


def finding_type_of(f: Any) -> str:
    """Read the annotated finding_type, classifying on the fly when
    the annotation pass hasn't run (defensive for old persisted
    results)."""
    md = getattr(f, "metadata", None) or {}
    return md.get("finding_type") or classify_finding(f)


def confidence_label_of(f: Any) -> str:
    md = getattr(f, "metadata", None) or {}
    return md.get("confidence_label") or confidence_label(f)
