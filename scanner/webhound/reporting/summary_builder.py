# WebHound — scanner/webhound/reporting/summary_builder.py
# Human-readable plain-text scan summary builder (executive-summary style).

from __future__ import annotations

from webhound.core.performance import ScanTelemetry
from webhound.models.finding import FindingCategory
from webhound.models.grouped_finding import GroupedFinding
from webhound.models.scan_result import ScanResult
from webhound.models.severity import Severity

# Categories that represent active compromise evidence or recon results — these
# are shown in Top Findings as alerts, not in Recommended Actions as policy fixes.
_ALERT_CATEGORIES: frozenset[FindingCategory] = frozenset({
    FindingCategory.COMPROMISE,
    FindingCategory.RECON,
})
from webhound.reporting.cli_formatter import (
    bold_divider,
    fmt_duration,
    fmt_risk,
    fmt_risk_description,
    fmt_url,
    thin_divider,
)

_WIDTH = 60
_TOP_N = 10
_MAX_ACTIONS = 5


class SummaryBuilder:
    """Builds a human-readable plain-text summary of a completed ScanResult.

    Output is formatted for terminal display and designed to be readable as
    an executive summary without requiring access to the full JSON report.

    Usage::

        builder = SummaryBuilder()
        print(builder.build(result))
    """

    def build(self, result: ScanResult) -> str:
        """Return a multi-line plain-text scan summary."""
        lines: list[str] = []

        self._header(result, lines)
        self._findings_breakdown(result, lines)
        self._security_stories(result, lines)
        self._top_findings(result, lines)
        self._recommended_actions(result, lines)
        self._engine_diagnostics(result, lines)
        self._wade_section(result, lines)
        self._performance_section(result, lines)
        self._errors_section(result, lines)

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _header(self, result: ScanResult, lines: list[str]) -> None:
        lines.append(bold_divider(_WIDTH))
        lines.append("WebHound Scan Report")
        lines.append(bold_divider(_WIDTH))
        lines.append(f"Target:      {fmt_url(result.target.base_url, _WIDTH - 13)}")
        lines.append(f"Status:      {result.status.value}")

        risk_score = result.metadata.get("risk_score", "—")
        risk_level = result.metadata.get("risk_level", "unknown")
        lines.append(f"Risk Score:  {fmt_risk(risk_score, risk_level)}")

        desc = fmt_risk_description(str(risk_level))
        if desc:
            lines.append(f"             {desc}")

        if result.duration_seconds is not None:
            lines.append(f"Duration:    {fmt_duration(result.duration_seconds)}")

        lines.append(f"Pages:       {result.urls_crawled} crawled")

        grouped_count = len(result.grouped_findings)
        if grouped_count:
            lines.append(f"Issues:      {grouped_count} unique findings grouped")

        lines.append("")

    def _findings_breakdown(self, result: ScanResult, lines: list[str]) -> None:
        bd = result.severity_breakdown
        lines.append(f"Findings: {bd.total} total ({bd.actionable} actionable)")
        lines.append(f"  CRITICAL  {bd.critical}")
        lines.append(f"  HIGH      {bd.high}")
        lines.append(f"  MEDIUM    {bd.medium}")
        lines.append(f"  LOW       {bd.low}")
        lines.append(f"  INFO      {bd.info}")

        # Phase-7 trust view: risk vs hardening vs inventory. Only
        # rendered when the trust pipeline annotated this result —
        # old persisted results keep the classic summary unchanged.
        sections = result.metadata.get("report_sections") or {}
        counts = sections.get("counts") or {}
        if counts:
            lines.append("")
            lines.append("By type:")
            lines.append(
                f"  Security risks            "
                f"{counts.get('security_risks', 0)}"
            )
            lines.append(
                f"  Hardening recommendations "
                f"{counts.get('hardening_recommendations', 0)}"
            )
            lines.append(
                f"  Inventory / discovered    "
                f"{counts.get('inventory', 0)}"
            )
            if counts.get("wade_changes"):
                lines.append(
                    f"  WADE changes              "
                    f"{counts.get('wade_changes', 0)}"
                )

    def _security_stories(self, result: ScanResult, lines: list[str]) -> None:
        """Phase-8: the 2-3 correlated stories a human analyst would lead
        with. Only rendered when the correlation pass produced stories."""
        stories = result.metadata.get("security_stories") or []
        if not stories:
            return
        lines.append("")
        lines.append("Security Stories:")
        for s in stories[:5]:
            conf = str(s.get("confidence", "")).title()
            tag = " [inventory]" if s.get("is_inventory") else ""
            lines.append(f"  • {s.get('title', '')}  "
                         f"(confidence: {conf}){tag}")
            areas = s.get("affected_areas") or []
            if areas:
                lines.append(
                    f"      Affected: {', '.join(str(a) for a in areas[:3])}"
                )

    def _top_findings(self, result: ScanResult, lines: list[str]) -> None:
        if result.grouped_findings:
            ordered = sorted(
                result.grouped_findings,
                key=lambda g: g.severity.rank,
                reverse=True,
            )
            lines.append("")
            lines.append("Top Findings:")
            for g in ordered[:_TOP_N]:
                label = g.severity.value.upper()
                url_note = f" ({g.affected_url_count} pages)" if g.affected_url_count > 1 else ""
                lines.append(f"  [{label}]  {g.title}{url_note}")
                if g.affected_urls:
                    lines.append(f"           Location: {fmt_url(g.affected_urls[0], _WIDTH - 20)}")
        elif result.active_findings:
            ordered_raw = sorted(
                result.active_findings,
                key=lambda f: f.severity.rank,
                reverse=True,
            )
            lines.append("")
            lines.append("Top Findings:")
            for f in ordered_raw[:_TOP_N]:
                label = f.severity.value.upper()
                lines.append(f"  [{label}]  {f.title}")
                if f.evidence:
                    lines.append(
                        f"           Location: {fmt_url(f.evidence[0].location, _WIDTH - 20)}"
                    )

    def _recommended_actions(self, result: ScanResult, lines: list[str]) -> None:
        actionable = [
            g for g in result.grouped_findings
            if g.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
            and g.remediation
            and g.category not in _ALERT_CATEGORIES
        ]
        if not actionable:
            return

        ordered = sorted(actionable, key=lambda g: g.severity.rank, reverse=True)
        lines.append("")
        lines.append("Recommended Actions:")
        for i, g in enumerate(ordered[:_MAX_ACTIONS], start=1):
            label = g.severity.value.upper()
            page_note = f"  ({g.affected_url_count} pages)" if g.affected_url_count > 1 else ""
            rem = g.remediation or ""
            lines.append(f"  {i}. [{label}] {g.title}{page_note}")
            if rem:
                lines.append(f"       → {rem}")

    def _engine_diagnostics(self, result: ScanResult, lines: list[str]) -> None:
        if result.engine_diagnostics:
            lines.append("")
            lines.append(f"Engine Diagnostics ({len(result.engine_diagnostics)}):")
            lines.append(
                f"  {'Engine':<26} {'Category':<12} {'Status':<10} {'Findings':>8} {'ms':>8}"
            )
            lines.append(
                f"  {'-'*26} {'-'*12} {'-'*10} {'-'*8} {'-'*8}"
            )
            for d in sorted(result.engine_diagnostics, key=lambda x: x.name):
                badge = d.status.value.upper()
                lines.append(
                    f"  {d.name:<26} {d.category:<12} {badge:<10}"
                    f" {d.findings_count:>8} {d.duration_ms:>8.1f}"
                )
        elif result.engines_run:
            lines.append("")
            engines_str = ", ".join(result.engines_run)
            lines.append(f"Engines ({len(result.engines_run)}):  {engines_str}")

    def _wade_section(self, result: ScanResult, lines: list[str]) -> None:
        wade_generated = result.metadata.get("wade_baseline_generated", False)
        wade_compared = result.metadata.get("wade_compared_to_previous", False)
        wade_count = result.metadata.get("wade_anomaly_count", 0)
        wade_findings = sorted(
            [f for f in result.active_findings if f.scanner_engine == "wade"],
            key=lambda f: (f.anomaly_score or 0.0),
            reverse=True,
        )
        if wade_generated or wade_findings:
            lines.append("")
            lines.append("WADE Anomaly Detection:")
            lines.append(f"  Baseline generated:   {'yes' if wade_generated else 'no'}")
            lines.append(f"  Compared to baseline: {'yes' if wade_compared else 'no'}")
            if wade_compared:
                lines.append(f"  Anomalies detected:   {wade_count}")
                for f in wade_findings[:5]:
                    score_str = (
                        f" (score {f.anomaly_score:.2f})"
                        if f.anomaly_score is not None
                        else ""
                    )
                    lines.append(f"  [{f.severity.value.upper()}]{score_str}  {f.title}")
            else:
                lines.append("  (no previous baseline — diff skipped)")

    def _performance_section(self, result: ScanResult, lines: list[str]) -> None:
        tel = ScanTelemetry.from_result(result)
        lines.append("")
        lines.append("Performance:")

        dur_str = fmt_duration(tel.total_duration_seconds) if tel.total_duration_seconds else "—"
        pps_str = f"{tel.pages_per_second:.1f} pages/sec" if tel.pages_per_second > 0 else "—"
        lines.append(f"  Duration:  {dur_str}  ({pps_str})")

        lines.append(
            f"  Requests:  {tel.total_requests} total"
            f"  ({tel.successful_requests} success"
            f"  {tel.failed_requests} failed"
            f"  {tel.retried_requests} retried)"
        )

        slowest = tel.slowest_engines(1)
        if slowest:
            sname, sms = slowest[0]
            lines.append(f"  Slowest engine:  {sname}  ({sms:.0f} ms)")

    def _errors_section(self, result: ScanResult, lines: list[str]) -> None:
        lines.append("")
        error_count = len(result.errors)
        if error_count:
            lines.append(f"Errors: {error_count}")
            for e in result.errors[:5]:
                lines.append(f"  [{e.engine}] {e.message}")
        else:
            lines.append("Errors: 0")
        lines.append(thin_divider(_WIDTH))
