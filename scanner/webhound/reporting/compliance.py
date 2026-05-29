# WebHound — scanner/webhound/reporting/compliance.py
# Phase-3 D/E/F: structured compliance rollup that all reporters
# (JSON, markdown, CSV, SARIF, PDF) consume so the same numbers
# appear in every export.
#
# The old per-framework rollup counted "findings touching this
# framework" — which inflated the apparent compliance posture because:
#   * one high-confidence finding + 19 advisory findings looked like
#     "20 hits against SOC 2";
#   * heuristic / advisory findings were lumped in with confirmed
#     violations;
#   * controls and findings shared a single number, so the user
#     couldn't tell whether "5 hits against PCI" meant 5 distinct
#     controls or 5 findings against the same control.
#
# The new rollup explicitly separates four orthogonal axes:
#
#   * controls_impacted        — distinct control IDs that any active
#                                finding touched (lower number = more
#                                concentrated risk)
#   * findings_mapped          — count of active findings that carry
#                                at least one ref into this framework
#   * advisory_controls        — controls touched only by INFO /
#                                advisory-tagged / quality_label=
#                                'informational' / 'advisory' findings
#   * confirmed_violations     — controls touched by ≥1 finding with
#                                severity ≥ HIGH AND quality_label
#                                in {confirmed, likely} — the
#                                dashboard renders THIS number in
#                                bold red, NOT the per-framework
#                                total
#
# The rollup is purely declarative — no severity is changed, no
# remediation is added, no finding is invented. It only re-shapes
# what's already in the scanner output.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webhound.models.finding import FrameworkAlignment
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult
from webhound.models.severity import Severity


# Frameworks we report on. (display label, FrameworkAlignment attr name).
_FRAMEWORKS: tuple[tuple[str, str], ...] = (
    ("OWASP Top 10",     "owasp_top10"),
    ("CWE",              "cwe_ids"),
    ("NIST 800-53",      "nist_controls"),
    ("PCI DSS 4.0",      "pci_dss"),
    ("ISO 27001",        "iso_27001"),
    ("SOC 2",            "soc2"),
    ("HIPAA",            "hipaa"),
)


@dataclass
class FrameworkRollup:
    """One framework's rollup row, ready for JSON or table rendering."""

    label: str
    field_name: str
    controls_impacted: int = 0
    findings_mapped: int = 0
    advisory_controls: int = 0
    confirmed_violations: int = 0
    # Cached control IDs for dashboards that want a click-through view.
    controls_impacted_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "field": self.field_name,
            "controls_impacted": self.controls_impacted,
            "findings_mapped": self.findings_mapped,
            "advisory_controls": self.advisory_controls,
            "confirmed_violations": self.confirmed_violations,
            "controls_impacted_ids": list(self.controls_impacted_ids),
        }


@dataclass
class ComplianceRollup:
    """Aggregate compliance posture across all configured frameworks."""

    frameworks: list[FrameworkRollup] = field(default_factory=list)
    # Total distinct controls touched across every framework (sum of
    # controls_impacted, minus inter-framework duplicates is *not* done
    # here — each framework has its own ID namespace).
    total_controls_impacted: int = 0
    total_confirmed_violations: int = 0
    known_exploited_finding_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "frameworks": [fr.to_dict() for fr in self.frameworks],
            "total_controls_impacted": self.total_controls_impacted,
            "total_confirmed_violations": self.total_confirmed_violations,
            "known_exploited_finding_count":
                self.known_exploited_finding_count,
        }


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def build_compliance_rollup(result: ScanResult) -> ComplianceRollup:
    """Construct a :class:`ComplianceRollup` from a completed
    :class:`ScanResult`. Operates on ``result.grouped_findings`` when
    present (canonical post-grouping view) so the same finding doesn't
    inflate counts via per-URL duplication. Falls back to
    ``result.active_findings`` for callers using the raw scan output."""
    items = result.grouped_findings or result.active_findings
    rollup = ComplianceRollup()

    for label, attr in _FRAMEWORKS:
        rollup.frameworks.append(_one_framework(label, attr, items))

    rollup.total_controls_impacted = sum(
        fr.controls_impacted for fr in rollup.frameworks
    )
    rollup.total_confirmed_violations = sum(
        fr.confirmed_violations for fr in rollup.frameworks
    )
    rollup.known_exploited_finding_count = sum(
        1 for it in items
        if getattr(it, "framework", None)
        and getattr(it.framework, "exploitability", None)
        and it.framework.exploitability.value == "known_exploited"
    )
    return rollup


def _one_framework(
    label: str, attr: str, items: list,
) -> FrameworkRollup:
    """Build a single framework's rollup row.

    Iterates findings once. For each finding's framework refs in the
    target attribute (e.g. ``soc2``), records:
      * the control IDs it impacts (set-deduped → controls_impacted)
      * whether the finding's severity / quality classifies as a
        confirmed violation, an advisory, or neither
    """
    controls_impacted: set[str] = set()
    confirmed_controls: set[str] = set()
    advisory_only_controls: dict[str, bool] = {}
    findings_with_any_ref = 0

    for item in items:
        fa: FrameworkAlignment | None = getattr(item, "framework", None)
        if fa is None:
            continue
        refs = getattr(fa, attr, None) or []
        if not refs:
            continue
        findings_with_any_ref += 1
        is_confirmed = _is_confirmed_violation(item)
        is_advisory = _is_advisory(item)
        for ref in refs:
            controls_impacted.add(ref)
            if is_confirmed:
                confirmed_controls.add(ref)
                # If a control already had advisory hits, the confirmed
                # hit promotes it out of the advisory bucket.
                advisory_only_controls[ref] = False
            elif is_advisory:
                # Only set 'advisory-only=True' if no confirmed hit has
                # been recorded yet — the False stays False once set.
                advisory_only_controls.setdefault(ref, True)
            else:
                # Heuristic / likely finding — neither advisory-only
                # nor confirmed-violation. Mark not-advisory.
                advisory_only_controls[ref] = False

    advisory_controls = sum(
        1 for ref in controls_impacted
        if advisory_only_controls.get(ref) is True
    )
    return FrameworkRollup(
        label=label,
        field_name=attr,
        controls_impacted=len(controls_impacted),
        findings_mapped=findings_with_any_ref,
        advisory_controls=advisory_controls,
        confirmed_violations=len(confirmed_controls),
        controls_impacted_ids=sorted(controls_impacted),
    )


def _is_confirmed_violation(item: Any) -> bool:
    """A control is a "confirmed violation" iff at least one finding
    touching it has severity ≥ HIGH AND quality_label in {confirmed,
    likely}. This is the only number that should drive risk-themed
    UI; everything else is hardening guidance."""
    sev = getattr(item, "severity", None)
    if sev is None:
        return False
    if sev.rank < Severity.HIGH.rank:
        return False
    quality = _quality_label(item)
    return quality in ("confirmed", "likely")


def _is_advisory(item: Any) -> bool:
    """A control hit is 'advisory' when the finding is INFO or
    explicitly tagged advisory / informational."""
    sev = getattr(item, "severity", None)
    if sev is not None and sev == Severity.INFO:
        return True
    quality = _quality_label(item)
    return quality in ("informational", "advisory")


def _quality_label(item: Any) -> str:
    """Read the quality_label off an item if it has one; falls back to
    deriving from tags + confidence for items that haven't implemented
    the property (e.g. older GroupedFinding shapes)."""
    label = getattr(item, "quality_label", None)
    if label:
        return label
    tags = {t.lower() for t in getattr(item, "tags", None) or []}
    if "advisory" in tags:
        return "advisory"
    if "informational" in tags:
        return "informational"
    if "confirmed" in tags:
        return "confirmed"
    if "likely" in tags:
        return "likely"
    if "heuristic" in tags or "weak_signal" in tags:
        return "heuristic"
    conf = getattr(item, "confidence", 1.0) or 1.0
    if conf >= 0.9:
        return "confirmed"
    if conf >= 0.7:
        return "likely"
    if conf < 0.55:
        return "heuristic"
    return "heuristic"
