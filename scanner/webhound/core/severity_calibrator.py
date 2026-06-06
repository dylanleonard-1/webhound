# WebHound — scanner/webhound/core/severity_calibrator.py
# Phase-7 severity calibration: central, demotion-only clamps that
# keep engines from over-escalating weak findings (Task 4/6).
#
# Design rules:
#   * DEMOTION ONLY. The calibrator never raises severity — engines
#     and the correlation pass own escalation.
#   * Every demotion is recorded in metadata.calibration with the
#     original severity and the rule that fired, so the dashboard can
#     show "engine said HIGH, policy capped at MEDIUM and here's why".
#   * Pattern-only detections cannot be HIGH/CRITICAL: a heuristic
#     CRITICAL is a contradiction — if we can't prove it, we don't
#     panic the customer about it.

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from webhound.core.trust_policy import confidence_label_of, finding_type_of
from webhound.models.severity import Severity

_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
          Severity.HIGH, Severity.CRITICAL]
_RANK = {s: i for i, s in enumerate(_ORDER)}


def _cap(f: Any, ceiling: Severity, rule: str) -> bool:
    """Clamp f.severity to *ceiling* if it's above it. Returns True
    when a demotion happened. Original severity + rule recorded."""
    sev = getattr(f, "severity", Severity.INFO)
    if _RANK.get(sev, 0) <= _RANK[ceiling]:
        return False
    md = getattr(f, "metadata", None)
    if md is None:
        md = {}
        f.metadata = md
    md["calibration"] = {
        "original_severity": sev.value,
        "calibrated_severity": ceiling.value,
        "rule": rule,
    }
    f.severity = ceiling
    rationale = getattr(f, "severity_rationale", None)
    note = f"Calibrated from {sev.value}: {rule}"
    f.severity_rationale = f"{rationale} — {note}" if rationale else note
    return True


# ---------------------------------------------------------------------------
# Rules. Each: (name, predicate, ceiling). First matching rule wins —
# ordered most-specific first.
# ---------------------------------------------------------------------------

_LOW_HEADER_RE = re.compile(
    r"(coop|coep|corp|cross.origin.(opener|embedder|resource)"
    r"|permissions.policy|referrer.policy|x.content.type.options"
    r"|x.frame.options|server\s+header|x.powered.by"
    r"|subresource\s+integrity|sri\b)",
    re.IGNORECASE,
)
_CSP_RE = re.compile(r"(content.security.policy|csp\b)", re.IGNORECASE)


def _title(f: Any) -> str:
    return getattr(f, "title", "") or ""


def _engine(f: Any) -> str:
    return getattr(f, "scanner_engine", "") or ""


def _category(f: Any) -> str:
    cat = getattr(f, "category", None)
    return getattr(cat, "value", str(cat or ""))


def _is_corroborated(f: Any) -> bool:
    md = getattr(f, "metadata", None) or {}
    tags = {t.lower() for t in (getattr(f, "tags", None) or [])}
    return bool(md.get("corroborated_by")) or "corroborated" in tags


def _has_external_confirmation(f: Any) -> bool:
    """Threat-intel enrichment hit (URLhaus / VirusTotal) — the only
    thing that lets a domain-reputation finding stay HIGH+."""
    md = getattr(f, "metadata", None) or {}
    tags = {t.lower() for t in (getattr(f, "tags", None) or [])}
    return bool(
        md.get("enrichment") or md.get("enrichment_hit")
        or md.get("urlhaus") or md.get("virustotal")
        or "enrichment_confirmed" in tags or "confirmed" in tags
    )


@dataclass(frozen=True)
class _Rule:
    name: str
    applies: Callable[[Any], bool]
    ceiling: Severity


_RULES: tuple[_Rule, ...] = (
    # -- Security headers (Task 6) ------------------------------------
    _Rule(
        "low-impact browser header is hardening (cap LOW)",
        lambda f: _category(f) == "security_header"
        and bool(_LOW_HEADER_RE.search(_title(f))),
        Severity.LOW,
    ),
    _Rule(
        "missing/weak CSP is hardening (cap MEDIUM)",
        lambda f: _category(f) == "security_header"
        and bool(_CSP_RE.search(_title(f))),
        Severity.MEDIUM,
    ),
    _Rule(
        "header findings never exceed MEDIUM without corroboration",
        lambda f: _category(f) == "security_header"
        and not _is_corroborated(f),
        Severity.MEDIUM,
    ),
    # -- Obfuscation (Task 6) ------------------------------------------
    _Rule(
        "obfuscation pattern alone caps at MEDIUM "
        "(minified vendor JS is not an incident)",
        lambda f: _engine(f) == "obfuscation_detector"
        and not _is_corroborated(f),
        Severity.MEDIUM,
    ),
    # -- Threat intel / domain reputation (Task 6) ---------------------
    _Rule(
        "domain-reputation heuristic without external confirmation "
        "caps at MEDIUM",
        lambda f: _engine(f) in ("threat_intel", "third_party_domains")
        and not _has_external_confirmation(f)
        and confidence_label_of(f) in ("heuristic", "low", "medium"),
        Severity.MEDIUM,
    ),
    # -- Hardening-typed findings are LOW by definition -----------------
    _Rule(
        "hardening recommendations cap at MEDIUM",
        lambda f: finding_type_of(f) == "hardening",
        Severity.MEDIUM,
    ),
    # -- Global trust floor (Task 4) ------------------------------------
    _Rule(
        "pattern-only (heuristic) findings cap at MEDIUM",
        lambda f: confidence_label_of(f) == "heuristic"
        and not _is_corroborated(f),
        Severity.MEDIUM,
    ),
    _Rule(
        "low-confidence findings cap at HIGH (CRITICAL requires "
        "confirmed or high confidence)",
        lambda f: confidence_label_of(f) == "low"
        and not _is_corroborated(f),
        Severity.HIGH,
    ),
    _Rule(
        "CRITICAL requires confirmed/high confidence",
        lambda f: confidence_label_of(f) == "medium"
        and not _is_corroborated(f),
        Severity.HIGH,
    ),
)


def calibrate_findings(findings: Iterable[Any]) -> int:
    """Apply the clamp rules to every finding in-place. Returns the
    number of demotions performed. Never raises a severity. WADE
    findings are skipped — the anomaly pipeline owns their scoring."""
    demoted = 0
    for f in findings:
        if _engine(f) == "wade":
            continue
        for rule in _RULES:
            try:
                if rule.applies(f) and _cap(f, rule.ceiling, rule.name):
                    demoted += 1
                    break  # first matching demotion wins
            except Exception:  # noqa: BLE001
                continue
    return demoted
