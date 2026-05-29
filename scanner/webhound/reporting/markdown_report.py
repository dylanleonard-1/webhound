# WebHound — scanner/webhound/reporting/markdown_report.py
# Markdown report builder: human-readable scan summary suitable for
# documentation, PR comments, and wiki pages.
#
# Sections:
#   1. Header (target, risk, timing, scan ID)
#   2. Severity breakdown table
#   3. Grouped findings table (top 20, with overflow note)
#   4. Recommended actions (top 5 actionable grouped findings)
#   5. Engine diagnostics table
#   6. WADE anomaly detection (when baseline was compared)
#   7. Performance summary (when telemetry available)
#   8. Errors (when present)

from __future__ import annotations

from typing import Any

from webhound.core.performance import ScanTelemetry
from webhound.models.finding import FindingCategory
from webhound.models.scan_result import ScanResult
from webhound.models.severity import Severity

_MAX_FINDINGS_TABLE = 20
_MAX_ACTIONS = 5
_ALERT_CATEGORIES: frozenset[FindingCategory] = frozenset({
    FindingCategory.COMPROMISE,
    FindingCategory.RECON,
})


def _esc(text: str) -> str:
    """Escape pipe characters inside Markdown table cells."""
    return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", "")


def _pct(value: float) -> str:
    return f"{value * 100:.0f}%"


class MarkdownReport:
    """Serialises a completed ScanResult into a Markdown document string.

    Usage::

        md = MarkdownReport()
        text = md.build(result)
        Path("report.md").write_text(text, encoding="utf-8")
    """

    def build(
        self,
        result: ScanResult,
        *,
        profile_name: str | None = None,
        baseline_id: str | None = None,
    ) -> str:
        lines: list[str] = []
        self._header(result, profile_name, lines)
        self._severity_breakdown(result, lines)
        self._findings_table(result, lines)
        self._recommended_actions(result, lines)
        self._engine_diagnostics(result, lines)
        self._wade_section(result, lines)
        self._performance_section(result, lines)
        self._errors_section(result, lines)
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _header(
        self,
        result: ScanResult,
        profile_name: str | None,
        lines: list[str],
    ) -> None:
        risk_score = result.metadata.get("risk_score", "—")
        risk_level = result.metadata.get("risk_level", "unknown").upper()
        duration = result.duration_seconds

        lines.append("# WebHound Scan Report")
        lines.append("")
        lines.append(f"**Target:** {result.target.base_url}  ")
        lines.append(f"**Status:** {result.status.value}  ")
        lines.append(f"**Risk Score:** {risk_score} / 100 ({risk_level})  ")
        if profile_name:
            lines.append(f"**Profile:** {profile_name}  ")
        if duration is not None:
            lines.append(f"**Duration:** {duration:.1f}s  ")
        lines.append(f"**Pages Crawled:** {result.urls_crawled}  ")
        lines.append(f"**Scan ID:** `{result.id}`  ")
        lines.append("")
        lines.append("---")

    def _severity_breakdown(self, result: ScanResult, lines: list[str]) -> None:
        bd = result.severity_breakdown
        lines.append("")
        lines.append("## Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|------:|")
        lines.append(f"| 🔴 CRITICAL | {bd.critical} |")
        lines.append(f"| 🟠 HIGH | {bd.high} |")
        lines.append(f"| 🟡 MEDIUM | {bd.medium} |")
        lines.append(f"| 🔵 LOW | {bd.low} |")
        lines.append(f"| ⚪ INFO | {bd.info} |")
        lines.append(f"| **Total** | **{bd.total}** |")
        lines.append("")
        lines.append("---")

    def _findings_table(self, result: ScanResult, lines: list[str]) -> None:
        lines.append("")
        lines.append("## Findings")
        lines.append("")

        if result.grouped_findings:
            ordered = sorted(
                result.grouped_findings,
                key=lambda g: g.severity.rank,
                reverse=True,
            )
            lines.append(
                "| Title | Severity | CVSS | Category | Engine | URL | Confidence |"
            )
            lines.append(
                "|-------|----------|------|----------|--------|-----|------------|"
            )
            for gf in ordered[:_MAX_FINDINGS_TABLE]:
                url = gf.affected_urls[0] if gf.affected_urls else "—"
                count_note = (
                    f" *(+{gf.affected_url_count - 1} more)*"
                    if gf.affected_url_count > 1
                    else ""
                )
                cvss = (
                    f"{gf.framework.cvss_score:.1f}"
                    if gf.framework.cvss_score is not None else "—"
                )
                lines.append(
                    f"| {_esc(gf.title)} "
                    f"| {gf.severity.value.upper()} "
                    f"| {cvss} "
                    f"| {gf.category.value} "
                    f"| {gf.scanner_engine} "
                    f"| {_esc(url)}{count_note} "
                    f"| {gf.confidence:.2f} |"
                )
            if len(ordered) > _MAX_FINDINGS_TABLE:
                lines.append(
                    f"\n*{len(ordered) - _MAX_FINDINGS_TABLE} additional findings "
                    f"omitted — see JSON report for full list.*"
                )
        elif result.active_findings:
            ordered_raw = sorted(
                result.active_findings,
                key=lambda f: f.severity.rank,
                reverse=True,
            )
            lines.append(
                "| Title | Severity | CVSS | Category | Engine | URL | Confidence |"
            )
            lines.append(
                "|-------|----------|------|----------|--------|-----|------------|"
            )
            for f in ordered_raw[:_MAX_FINDINGS_TABLE]:
                url = f.evidence[0].location if f.evidence else "—"
                cvss = (
                    f"{f.framework.cvss_score:.1f}"
                    if f.framework.cvss_score is not None else "—"
                )
                lines.append(
                    f"| {_esc(f.title)} "
                    f"| {f.severity.value.upper()} "
                    f"| {cvss} "
                    f"| {f.category.value} "
                    f"| {f.scanner_engine} "
                    f"| {_esc(url)} "
                    f"| {f.confidence:.2f} |"
                )
        else:
            lines.append("*No findings recorded.*")

        lines.append("")
        self._compliance_summary(result, lines)
        lines.append("")
        lines.append("---")

    def _compliance_summary(self, result: ScanResult, lines: list[str]) -> None:
        """Structured compliance rollup — separates controls impacted
        from findings mapped from confirmed violations. Same numbers
        as the JSON / CSV / SARIF exports, sourced from
        reporting/compliance.py so every consumer sees one truth."""
        if not result.grouped_findings and not result.active_findings:
            return
        from webhound.reporting.compliance import build_compliance_rollup
        rollup = build_compliance_rollup(result)
        # Only render rows whose controls_impacted > 0 — otherwise the
        # framework didn't fire at all and an empty row is just noise.
        active_rows = [fr for fr in rollup.frameworks
                        if fr.controls_impacted > 0]
        if not active_rows:
            return
        lines.append("")
        lines.append("### Compliance &amp; Standards Coverage")
        lines.append("")
        lines.append("| Framework | Controls impacted | Findings mapped "
                      "| Confirmed violations | Advisory only |")
        lines.append("|-----------|-------------------|-----------------"
                      "|----------------------|---------------|")
        for fr in active_rows:
            lines.append(
                f"| {fr.label} | {fr.controls_impacted} "
                f"| {fr.findings_mapped} "
                f"| {fr.confirmed_violations} "
                f"| {fr.advisory_controls} |"
            )
        lines.append("")
        lines.append(
            f"**{rollup.total_controls_impacted}** distinct control(s) "
            f"impacted across all frameworks; "
            f"**{rollup.total_confirmed_violations}** confirmed "
            "violation(s) (high-severity findings with confirmed/likely "
            "quality)."
        )
        if rollup.known_exploited_finding_count > 0:
            lines.append("")
            lines.append(
                f"**{rollup.known_exploited_finding_count}** finding(s) "
                "flagged as `KNOWN_EXPLOITED` — working exploits exist "
                "in the wild."
            )

    def _recommended_actions(self, result: ScanResult, lines: list[str]) -> None:
        actionable = [
            gf for gf in result.grouped_findings
            if gf.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
            and gf.remediation
            and gf.category not in _ALERT_CATEGORIES
        ]
        if not actionable:
            return

        ordered = sorted(actionable, key=lambda g: g.severity.rank, reverse=True)
        lines.append("")
        lines.append("## Recommended Actions")
        lines.append("")
        for i, gf in enumerate(ordered[:_MAX_ACTIONS], start=1):
            label = gf.severity.value.upper()
            page_note = f" ({gf.affected_url_count} pages)" if gf.affected_url_count > 1 else ""
            lines.append(f"{i}. **[{label}] {_esc(gf.title)}**{page_note}")
            if gf.remediation:
                lines.append(f"   > {_esc(gf.remediation)}")
            lines.append("")
        lines.append("---")

    def _engine_diagnostics(self, result: ScanResult, lines: list[str]) -> None:
        if not result.engine_diagnostics:
            return
        lines.append("")
        lines.append("## Engine Diagnostics")
        lines.append("")
        lines.append("| Engine | Category | Status | Findings | Duration (ms) |")
        lines.append("|--------|----------|--------|----------|---------------|")
        for d in sorted(result.engine_diagnostics, key=lambda x: x.name):
            lines.append(
                f"| {d.name} "
                f"| {d.category} "
                f"| {d.status.value.upper()} "
                f"| {d.findings_count} "
                f"| {d.duration_ms:.1f} |"
            )
        lines.append("")
        lines.append("---")

    def _wade_section(self, result: ScanResult, lines: list[str]) -> None:
        generated = result.metadata.get("wade_baseline_generated", False)
        compared = result.metadata.get("wade_compared_to_previous", False)
        anomaly_count = result.metadata.get("wade_anomaly_count", 0)

        if not generated:
            return

        wade_findings = sorted(
            [f for f in result.active_findings if f.scanner_engine == "wade"],
            key=lambda f: (f.anomaly_score or 0.0),
            reverse=True,
        )

        lines.append("")
        lines.append("## WADE Anomaly Detection")
        lines.append("")
        lines.append(f"- **Baseline generated:** {'yes' if generated else 'no'}")
        lines.append(f"- **Compared to previous baseline:** {'yes' if compared else 'no'}")
        if compared:
            lines.append(f"- **Anomalies detected:** {anomaly_count}")
            if wade_findings:
                lines.append("")
                lines.append("| Severity | Score | Title |")
                lines.append("|----------|------:|-------|")
                for f in wade_findings[:5]:
                    score = f"{f.anomaly_score:.2f}" if f.anomaly_score is not None else "—"
                    lines.append(
                        f"| {f.severity.value.upper()} | {score} | {_esc(f.title)} |"
                    )
        lines.append("")
        lines.append("---")

    def _performance_section(self, result: ScanResult, lines: list[str]) -> None:
        tel = ScanTelemetry.from_result(result)
        if not tel.total_duration_seconds and not tel.total_requests:
            return

        lines.append("")
        lines.append("## Performance")
        lines.append("")
        lines.append(f"- **Total Duration:** {tel.total_duration_seconds:.2f}s")
        if tel.crawl_duration_seconds is not None:
            lines.append(f"- **Crawl Duration:** {tel.crawl_duration_seconds:.2f}s")
        if tel.pages_per_second > 0:
            lines.append(f"- **Throughput:** {tel.pages_per_second:.2f} pages/sec")
        lines.append(
            f"- **Requests:** {tel.total_requests} total"
            f" ({tel.successful_requests} success,"
            f" {tel.failed_requests} failed,"
            f" {tel.retried_requests} retried)"
        )
        slowest = tel.slowest_engines(3)
        if slowest:
            lines.append("")
            lines.append("**Slowest Engines:**")
            lines.append("")
            lines.append("| Engine | Duration (ms) | Findings |")
            lines.append("|--------|--------------|----------|")
            for name, ms in slowest:
                fcount = tel.findings_per_engine.get(name, 0)
                lines.append(f"| {name} | {ms:.1f} | {fcount} |")
        lines.append("")
        lines.append("---")

    def _errors_section(self, result: ScanResult, lines: list[str]) -> None:
        if not result.errors:
            return
        lines.append("")
        lines.append("## Errors")
        lines.append("")
        for e in result.errors[:10]:
            url_note = f" (`{e.url}`)" if e.url else ""
            lines.append(f"- **[{e.engine}]** {_esc(e.message)}{url_note}")
        if len(result.errors) > 10:
            lines.append(
                f"\n*{len(result.errors) - 10} additional errors omitted.*"
            )
