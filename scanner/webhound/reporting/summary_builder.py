# WebHound — scanner/webhound/reporting/summary_builder.py
# Human-readable plain-text scan summary builder.

from __future__ import annotations

from webhound.models.scan_result import ScanResult

_WIDTH = 44


class SummaryBuilder:
    """Builds a human-readable plain-text summary of a completed ScanResult.

    Usage::

        builder = SummaryBuilder()
        print(builder.build(result))
    """

    def build(self, result: ScanResult) -> str:
        """Return a multi-line plain-text scan summary."""
        lines: list[str] = []

        lines.append("WebHound Scan Report")
        lines.append("=" * _WIDTH)
        lines.append(f"Target:      {result.target.base_url}")
        lines.append(f"Status:      {result.status.value}")

        risk_score = result.metadata.get("risk_score", "—")
        risk_level = result.metadata.get("risk_level", "unknown")
        lines.append(f"Risk Score:  {risk_score} / 100  ({risk_level} risk)")

        if result.duration_seconds is not None:
            lines.append(f"Duration:    {result.duration_seconds:.1f}s")

        lines.append(f"Pages:       {result.urls_crawled} crawled")
        lines.append("")

        bd = result.severity_breakdown
        lines.append(f"Findings: {bd.total} total ({bd.actionable} actionable)")
        lines.append(f"  CRITICAL  {bd.critical}")
        lines.append(f"  HIGH      {bd.high}")
        lines.append(f"  MEDIUM    {bd.medium}")
        lines.append(f"  LOW       {bd.low}")
        lines.append(f"  INFO      {bd.info}")

        active = result.active_findings
        if active:
            lines.append("")
            ordered = sorted(active, key=lambda f: f.severity.rank, reverse=True)
            lines.append("Top Findings:")
            for f in ordered[:10]:
                label = f.severity.value.upper()
                lines.append(f"  [{label}]  {f.title}")
                if f.evidence:
                    lines.append(f"           Location: {f.evidence[0].location}")

        if result.engine_diagnostics:
            lines.append("")
            lines.append(f"Engine Diagnostics ({len(result.engine_diagnostics)}):")
            lines.append(f"  {'Engine':<26} {'Category':<12} {'Status':<10} {'Findings':>8} {'ms':>8}")
            lines.append(f"  {'-'*26} {'-'*12} {'-'*10} {'-'*8} {'-'*8}")
            for d in sorted(result.engine_diagnostics, key=lambda x: x.name):
                badge = d.status.value.upper()
                lines.append(
                    f"  {d.name:<26} {d.category:<12} {badge:<10} {d.findings_count:>8} {d.duration_ms:>8.1f}"
                )
        elif result.engines_run:
            lines.append("")
            engines_str = ", ".join(result.engines_run)
            lines.append(f"Engines ({len(result.engines_run)}):  {engines_str}")

        lines.append("")
        error_count = len(result.errors)
        if error_count:
            lines.append(f"Errors: {error_count}")
            for e in result.errors[:5]:
                lines.append(f"  [{e.engine}] {e.message}")
        else:
            lines.append("Errors: 0")

        return "\n".join(lines)
