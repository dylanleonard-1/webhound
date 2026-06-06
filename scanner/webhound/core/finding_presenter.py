# WebHound — scanner/webhound/core/finding_presenter.py
# Phase-7 customer-facing presentation (Tasks 7-8). Maps the trust
# annotations to calm, accurate language and files every finding into
# one of four report sections.
#
# Principle: WebHound earns trust by being precise, not loud. The
# presenter NEVER rewrites engine-produced descriptions or evidence —
# it adds presentation fields alongside them.

from __future__ import annotations

from typing import Any

from webhound.core.trust_policy import (
    confidence_label_of,
    finding_type_of,
)
from webhound.models.severity import Severity

# Severity → what the customer should do (Task 7 wording).
SEVERITY_ACTIONS: dict[str, str] = {
    "critical": "Fix immediately",
    "high": "Fix soon",
    "medium": "Review and schedule",
    "low": "Hardening improvement",
    "info": "Discovered asset",
    "unknown": "Review",
}

# finding_type → calm framing line shown above the engine description.
TYPE_HEADLINES: dict[str, str] = {
    "confirmed_risk": (
        "WebHound confirmed a risk that should be reviewed and fixed."
    ),
    "likely_risk": (
        "WebHound found a likely risk that should be reviewed."
    ),
    "heuristic_signal": (
        "WebHound noticed a pattern worth reviewing. This is a signal, "
        "not a confirmed issue."
    ),
    "hardening": (
        "This is a hardening recommendation — improving it strengthens "
        "your security posture."
    ),
    "inventory": (
        "This is a discovered asset, recorded for visibility. It is "
        "not a security problem by itself."
    ),
}

TYPE_LABELS: dict[str, str] = {
    "confirmed_risk": "Confirmed risk",
    "likely_risk": "Likely risk",
    "heuristic_signal": "Heuristic signal",
    "hardening": "Hardening recommendation",
    "inventory": "Inventory",
}

CONFIDENCE_LABELS_HUMAN: dict[str, str] = {
    "confirmed": "Confirmed",
    "high": "High confidence",
    "medium": "Medium confidence",
    "low": "Low confidence",
    "heuristic": "Heuristic",
}

# Report sections (Task 8).
SECTION_SECURITY = "security_risks"
SECTION_HARDENING = "hardening_recommendations"
SECTION_INVENTORY = "inventory"
SECTION_WADE = "wade_changes"


def section_of(f: Any) -> str:
    """Which report section a finding belongs to."""
    if (getattr(f, "scanner_engine", "") or "") == "wade":
        return SECTION_WADE
    ftype = finding_type_of(f)
    if ftype == "hardening":
        return SECTION_HARDENING
    if ftype == "inventory":
        return SECTION_INVENTORY
    return SECTION_SECURITY


def present(f: Any) -> dict[str, Any]:
    """Presentation fields for one finding/grouped finding. Additive —
    callers merge this next to the engine's own content."""
    ftype = finding_type_of(f)
    conf = confidence_label_of(f)
    sev = getattr(f, "severity", Severity.INFO)
    sev_value = getattr(sev, "value", str(sev))
    return {
        "section": section_of(f),
        "finding_type": ftype,
        "type_label": TYPE_LABELS.get(ftype, ftype),
        "headline": TYPE_HEADLINES.get(ftype, ""),
        "action": SEVERITY_ACTIONS.get(sev_value, "Review"),
        "confidence_label": conf,
        "confidence_label_human": CONFIDENCE_LABELS_HUMAN.get(conf, conf),
    }


def build_report_sections(grouped_findings: list[Any]) -> dict[str, Any]:
    """Split grouped findings into the four customer-facing sections
    (Task 8). Returns counts + per-section title/severity summaries —
    bounded, JSON-stable, additive to existing report output."""
    sections: dict[str, list[dict[str, Any]]] = {
        SECTION_SECURITY: [],
        SECTION_HARDENING: [],
        SECTION_INVENTORY: [],
        SECTION_WADE: [],
    }
    for gf in grouped_findings or []:
        entry = {
            "title": getattr(gf, "title", ""),
            "severity": getattr(getattr(gf, "severity", None), "value",
                                "unknown"),
            "finding_type": finding_type_of(gf),
            "confidence_label": confidence_label_of(gf),
            "action": SEVERITY_ACTIONS.get(
                getattr(getattr(gf, "severity", None), "value", ""),
                "Review",
            ),
            "affected_url_count": getattr(gf, "affected_url_count", 1),
        }
        sections[section_of(gf)].append(entry)

    def _sorted(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                 "info": 4, "unknown": 5}
        return sorted(items, key=lambda e: order.get(e["severity"], 5))

    return {
        "security_risks": _sorted(sections[SECTION_SECURITY])[:100],
        "hardening_recommendations": _sorted(
            sections[SECTION_HARDENING])[:100],
        "inventory": _sorted(sections[SECTION_INVENTORY])[:200],
        "wade_changes": _sorted(sections[SECTION_WADE])[:100],
        "counts": {
            "security_risks": len(sections[SECTION_SECURITY]),
            "hardening_recommendations": len(sections[SECTION_HARDENING]),
            "inventory": len(sections[SECTION_INVENTORY]),
            "wade_changes": len(sections[SECTION_WADE]),
        },
    }
