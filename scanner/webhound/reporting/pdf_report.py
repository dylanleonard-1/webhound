# WebHound — scanner/webhound/reporting/pdf_report.py
# Branded PDF report — WebHound's dark theme rendered through reportlab.
#
# Sections:
#   1. Cover — logo, scanned URL, risk score, scan timestamp
#   2. Executive summary — severity breakdown + finding counts
#   3. Findings table — top 20 findings with CVSS, severity, engine
#   4. Compliance coverage — per-framework counts (PCI / ISO / SOC / HIPAA)
#   5. Top 5 actionable items — title + one-line remediation excerpt
#
# Output is a bytes object containing a self-contained PDF.

from __future__ import annotations

import io
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

from webhound.models.scan_result import ScanResult
from webhound.models.severity import Severity

# ---------------------------------------------------------------------------
# Theme colors — match the WebHound dark dashboard
# ---------------------------------------------------------------------------

BG_DARK       = colors.HexColor("#0D1220")
BG_CARD       = colors.HexColor("#141A2A")
BORDER        = colors.HexColor("#252B3D")
WHITE         = colors.HexColor("#FFFFFF")
TEXT_PRIMARY  = colors.HexColor("#E5E7EB")
TEXT_MUTED    = colors.HexColor("#9CA3AF")
TEXT_FAINT    = colors.HexColor("#6B7280")
ACCENT_GREEN  = colors.HexColor("#8BFF3E")
ACCENT_BLUE   = colors.HexColor("#4F9CF9")

SEV_COLORS = {
    "critical": colors.HexColor("#EF4444"),
    "high":     colors.HexColor("#F97316"),
    "medium":   colors.HexColor("#EAB308"),
    "low":      colors.HexColor("#8BFF3E"),
    "info":     colors.HexColor("#4F9CF9"),
}

_LOGO_PATH = Path(__file__).parent / "_logo.png"


# ---------------------------------------------------------------------------
# Stylesheet
# ---------------------------------------------------------------------------


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=28, leading=34, textColor=WHITE, alignment=TA_LEFT,
            spaceAfter=4,
        ),
        "subtitle": ParagraphStyle(
            "subtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=11, leading=15, textColor=TEXT_MUTED, spaceAfter=2,
        ),
        "section": ParagraphStyle(
            "section", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=14, leading=18, textColor=WHITE,
            spaceBefore=18, spaceAfter=8,
        ),
        "section_sub": ParagraphStyle(
            "section_sub", parent=base["Normal"], fontName="Helvetica",
            fontSize=9, leading=12, textColor=TEXT_FAINT, spaceAfter=10,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"], fontName="Helvetica",
            fontSize=10, leading=14, textColor=TEXT_PRIMARY, spaceAfter=6,
        ),
        "muted": ParagraphStyle(
            "muted", parent=base["Normal"], fontName="Helvetica",
            fontSize=9, leading=12, textColor=TEXT_MUTED,
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["Normal"], fontName="Courier",
            fontSize=9, leading=13, textColor=TEXT_PRIMARY,
        ),
        "risk_label": ParagraphStyle(
            "risk_label", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=8, leading=10, textColor=TEXT_FAINT,
        ),
        "risk_score": ParagraphStyle(
            "risk_score", parent=base["Normal"], fontName="Courier-Bold",
            fontSize=42, leading=46, textColor=ACCENT_GREEN,
        ),
    }


# ---------------------------------------------------------------------------
# Background painter
# ---------------------------------------------------------------------------


def _paint_background(canv, doc) -> None:
    """Fill the page with the dark theme color before any content draws."""
    canv.saveState()
    canv.setFillColor(BG_DARK)
    canv.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
    # Subtle accent line at the top of every page
    canv.setStrokeColor(ACCENT_GREEN)
    canv.setLineWidth(2)
    canv.line(0.5 * inch, doc.pagesize[1] - 0.4 * inch,
              doc.pagesize[0] - 0.5 * inch, doc.pagesize[1] - 0.4 * inch)
    # Footer
    canv.setFillColor(TEXT_FAINT)
    canv.setFont("Helvetica", 8)
    canv.drawString(0.5 * inch, 0.35 * inch,
                    f"WebHound Security Report · Page {doc.page}")
    canv.drawRightString(doc.pagesize[0] - 0.5 * inch, 0.35 * inch,
                         "webhoundsecurity.com")
    canv.restoreState()


# ---------------------------------------------------------------------------
# PDF builder
# ---------------------------------------------------------------------------


class PdfReport:
    """Render a completed :class:`ScanResult` as a branded PDF document."""

    NAME = "pdf"

    def build(self, result: ScanResult) -> bytes:
        buf = io.BytesIO()
        doc = BaseDocTemplate(
            buf, pagesize=LETTER,
            leftMargin=0.5 * inch, rightMargin=0.5 * inch,
            topMargin=0.65 * inch, bottomMargin=0.55 * inch,
            title=f"WebHound Security Report — {result.target.hostname}",
            author="WebHound",
        )
        frame = Frame(
            doc.leftMargin, doc.bottomMargin,
            doc.width, doc.height, id="body",
        )
        doc.addPageTemplates([
            PageTemplate(id="dark", frames=[frame], onPage=_paint_background),
        ])

        s = _styles()
        story = []
        story.extend(self._cover(result, s))
        story.append(Spacer(1, 0.25 * inch))
        story.extend(self._severity_breakdown(result, s))
        story.append(Spacer(1, 0.15 * inch))
        story.extend(self._compliance_section(result, s))
        story.append(PageBreak())
        story.extend(self._findings_section(result, s))
        story.append(Spacer(1, 0.2 * inch))
        story.extend(self._top_actionable(result, s))

        doc.build(story)
        return buf.getvalue()

    # ------------------------------------------------------------------
    # Cover
    # ------------------------------------------------------------------

    def _cover(self, result, s) -> list:
        elems = []
        # Logo + title row
        header_cells = [[]]
        if _LOGO_PATH.exists():
            img = Image(str(_LOGO_PATH), width=70, height=70)
            header_cells[0].append(img)
        title_block = [
            Paragraph("WebHound Security Report", s["title"]),
            Paragraph(
                f"<font color='#9CA3AF'>{_html_safe(result.target.base_url)}</font>",
                s["subtitle"],
            ),
            Paragraph(
                f"Scan completed "
                f"<font color='#E5E7EB'>"
                f"{result.completed_at.strftime('%B %d, %Y at %H:%M UTC') if result.completed_at else '—'}"
                f"</font> · "
                f"{result.urls_crawled} page{'s' if result.urls_crawled != 1 else ''} crawled · "
                f"{(result.duration_seconds or 0):.1f}s",
                s["muted"],
            ),
        ]
        header_cells[0].append(title_block)
        header = Table(
            header_cells, colWidths=[0.95 * inch, doc_width() - 0.95 * inch],
        )
        header.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 0),
        ]))
        elems.append(header)
        elems.append(Spacer(1, 0.25 * inch))

        # Risk score hero card
        risk_score = _resolve_risk_score(result)
        risk_level = _resolve_risk_level(result, risk_score).upper()
        risk_color = SEV_COLORS.get(risk_level.lower(), ACCENT_GREEN)
        risk_text = ParagraphStyle(
            "risk_score_dyn", parent=s["risk_score"], textColor=risk_color,
        )
        risk_card = Table(
            [[
                [
                    Paragraph("OVERALL RISK SCORE", s["risk_label"]),
                    Spacer(1, 6),
                    Paragraph(f"{risk_score:.1f}", risk_text),
                    Paragraph(
                        f"<font color='{'#' + risk_color.hexval()[2:]}'>"
                        f"<b>{risk_level}</b></font>",
                        s["body"],
                    ),
                ],
                [
                    Paragraph("FINDINGS", s["risk_label"]),
                    Spacer(1, 6),
                    Paragraph(
                        f"<font color='#FFFFFF'>"
                        f"{result.severity_breakdown.total}"
                        f"</font>",
                        ParagraphStyle(
                            "findings_count", parent=s["risk_score"],
                            textColor=WHITE,
                        ),
                    ),
                    Paragraph(
                        f"<font color='#F97316'>"
                        f"{result.severity_breakdown.actionable} actionable"
                        f"</font>",
                        s["muted"],
                    ),
                ],
                [
                    Paragraph("SEVERITY", s["risk_label"]),
                    Spacer(1, 6),
                    _severity_legend(result, s),
                ],
            ]],
            colWidths=[doc_width() / 3.0] * 3,
        )
        risk_card.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.75, BORDER),
            ("LINEAFTER", (0, 0), (-2, -1), 0.75, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 18),
            ("RIGHTPADDING", (0, 0), (-1, -1), 18),
            ("TOPPADDING", (0, 0), (-1, -1), 16),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 16),
        ]))
        elems.append(risk_card)
        return elems

    # ------------------------------------------------------------------
    # Severity breakdown bar
    # ------------------------------------------------------------------

    def _severity_breakdown(self, result, s) -> list:
        bd = result.severity_breakdown
        elems = [
            Paragraph("Severity Breakdown", s["section"]),
            Paragraph(
                "Distribution of findings by severity. Critical and high "
                "findings should be addressed first.",
                s["section_sub"],
            ),
        ]
        rows = [
            ("CRITICAL", bd.critical, SEV_COLORS["critical"]),
            ("HIGH",     bd.high,     SEV_COLORS["high"]),
            ("MEDIUM",   bd.medium,   SEV_COLORS["medium"]),
            ("LOW",      bd.low,      SEV_COLORS["low"]),
            ("INFO",     bd.info,     SEV_COLORS["info"]),
        ]
        total = max(bd.total, 1)
        data = [["Severity", "Count", "Distribution"]]
        for label, count, color in rows:
            pct = count / total
            bar_w = max(2, int(pct * 220))
            bar = Table(
                [[" " * max(1, bar_w // 4)]],
                colWidths=[bar_w], rowHeights=[10],
            )
            bar.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ("TOPPADDING", (0, 0), (-1, -1), 0),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
            ]))
            data.append([
                Paragraph(
                    f"<font color='{'#' + color.hexval()[2:]}'><b>{label}</b></font>",
                    s["body"],
                ),
                Paragraph(
                    f"<font color='#FFFFFF'><b>{count}</b></font> "
                    f"<font color='#6B7280'>({pct * 100:.0f}%)</font>",
                    s["body"],
                ),
                bar,
            ])
        table = Table(
            data,
            colWidths=[1.2 * inch, 1.4 * inch, doc_width() - 2.6 * inch],
        )
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BG_CARD),
            ("TEXTCOLOR", (0, 0), (-1, 0), TEXT_FAINT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("ALIGN", (0, 0), (-1, 0), "LEFT"),
            ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
            ("LINEBELOW", (0, 0), (-1, 0), 0.5, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("TOPPADDING", (0, 0), (-1, -1), 9),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_DARK, BG_CARD]),
        ]))
        elems.append(table)
        return elems

    # ------------------------------------------------------------------
    # Compliance summary
    # ------------------------------------------------------------------

    def _compliance_section(self, result, s) -> list:
        if not result.grouped_findings:
            return []
        frameworks = [
            ("PCI DSS 4.0",  "pci_dss"),
            ("ISO 27001",    "iso_27001"),
            ("SOC 2",        "soc2"),
            ("HIPAA",        "hipaa"),
            ("OWASP Top 10", "owasp_top10"),
            ("NIST 800-53",  "nist_controls"),
        ]
        rows: list[list] = [["Framework", "Findings", "Unique Refs", "Top Examples"]]
        any_rows = False
        for label, attr in frameworks:
            total = 0
            refs: set[str] = set()
            for gf in result.grouped_findings:
                values = getattr(gf.framework, attr, None) or []
                if values:
                    total += 1
                    refs.update(values)
            if total == 0:
                continue
            any_rows = True
            examples = ", ".join(sorted(refs)[:3])
            if len(refs) > 3:
                examples += f" (+{len(refs) - 3})"
            rows.append([
                Paragraph(f"<font color='#FFFFFF'><b>{label}</b></font>", s["body"]),
                Paragraph(f"<font color='#F97316'><b>{total}</b></font>", s["body"]),
                Paragraph(str(len(refs)), s["body"]),
                Paragraph(_html_safe(examples) or "—", s["mono"]),
            ])
        if not any_rows:
            return []
        elems = [
            Paragraph("Compliance &amp; Standards Coverage", s["section"]),
            Paragraph(
                "Each row counts the findings that map to that framework. "
                "Cross-reference with auditor checklists for evidence gathering.",
                s["section_sub"],
            ),
        ]
        # Known-exploited callout
        known_exp = sum(
            1 for gf in result.grouped_findings
            if gf.framework.exploitability
            and gf.framework.exploitability.value == "known_exploited"
        )
        table = Table(
            rows,
            colWidths=[1.5 * inch, 0.9 * inch, 1.0 * inch, doc_width() - 3.4 * inch],
        )
        table.setStyle(_table_style(header=True))
        elems.append(table)
        if known_exp > 0:
            elems.append(Spacer(1, 0.1 * inch))
            elems.append(Paragraph(
                f"<font color='#EF4444'><b>{known_exp} finding(s) flagged "
                "as KNOWN EXPLOITED</b></font> — working exploits exist in "
                "the wild for these issues. Prioritise above all other items.",
                s["body"],
            ))
        return elems

    # ------------------------------------------------------------------
    # Findings table
    # ------------------------------------------------------------------

    def _findings_section(self, result, s) -> list:
        elems = [
            Paragraph("Findings", s["section"]),
            Paragraph(
                "Top 20 findings by severity. Full list available in the "
                "JSON / CSV / SARIF exports.",
                s["section_sub"],
            ),
        ]
        if not result.grouped_findings and not result.active_findings:
            elems.append(Paragraph("No findings recorded.", s["muted"]))
            return elems

        ordered = sorted(
            result.grouped_findings or result.active_findings,
            key=lambda x: x.severity.rank,
            reverse=True,
        )[:20]
        data = [["Severity", "CVSS", "Title", "Engine"]]
        for f in ordered:
            sev = f.severity.value.lower()
            color = SEV_COLORS.get(sev, TEXT_PRIMARY)
            cvss = (f"{f.framework.cvss_score:.1f}"
                    if f.framework.cvss_score is not None else "—")
            exploit_badge = ""
            if (f.framework.exploitability
                and f.framework.exploitability.value == "known_exploited"):
                exploit_badge = (
                    " <font color='#EF4444' size='7'><b>EXPLOITED</b></font>"
                )
            data.append([
                Paragraph(
                    f"<font color='{'#' + color.hexval()[2:]}'><b>"
                    f"{f.severity.value.upper()}</b></font>",
                    s["body"],
                ),
                Paragraph(
                    f"<font color='#FFFFFF'>{cvss}</font>",
                    s["mono"],
                ),
                Paragraph(_html_safe(f.title) + exploit_badge, s["body"]),
                Paragraph(
                    f"<font color='#9CA3AF'>{_html_safe(f.scanner_engine)}</font>",
                    s["mono"],
                ),
            ])
        table = Table(
            data,
            colWidths=[
                1.0 * inch, 0.55 * inch,
                doc_width() - 2.85 * inch, 1.3 * inch,
            ],
        )
        table.setStyle(_table_style(header=True))
        elems.append(table)
        return elems

    # ------------------------------------------------------------------
    # Top actionable items (with remediation)
    # ------------------------------------------------------------------

    def _top_actionable(self, result, s) -> list:
        actionable = [
            gf for gf in result.grouped_findings
            if gf.severity in (Severity.CRITICAL, Severity.HIGH)
            and gf.remediation
        ]
        if not actionable:
            return []
        ordered = sorted(actionable, key=lambda g: g.severity.rank, reverse=True)[:5]
        elems = [
            Paragraph("Top Actionable Items", s["section"]),
            Paragraph(
                "Critical and high-severity findings with specific "
                "remediation guidance. Address these first.",
                s["section_sub"],
            ),
        ]
        for i, gf in enumerate(ordered, 1):
            color = SEV_COLORS.get(gf.severity.value.lower(), TEXT_PRIMARY)
            cvss = (f" · CVSS {gf.framework.cvss_score:.1f}"
                    if gf.framework.cvss_score is not None else "")
            content = [
                Paragraph(
                    f"<font color='{'#' + color.hexval()[2:]}'><b>"
                    f"#{i} {gf.severity.value.upper()}</b></font> "
                    f"<font color='#6B7280'>{_html_safe(gf.scanner_engine)}"
                    f"{cvss}</font>",
                    s["muted"],
                ),
                Paragraph(_html_safe(gf.title), s["body"]),
                Paragraph(
                    f"<font color='#9CA3AF'><b>Fix:</b> "
                    f"{_html_safe(_truncate(gf.remediation or '', 320))}"
                    "</font>",
                    s["muted"],
                ),
            ]
            wrapper = Table(
                [[content]],
                colWidths=[doc_width()],
            )
            wrapper.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), BG_CARD),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
                ("LINEBEFORE", (0, 0), (0, -1), 3, color),
                ("LEFTPADDING", (0, 0), (-1, -1), 14),
                ("RIGHTPADDING", (0, 0), (-1, -1), 14),
                ("TOPPADDING", (0, 0), (-1, -1), 11),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elems.append(KeepTogether(wrapper))
            elems.append(Spacer(1, 0.1 * inch))
        return elems


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def doc_width() -> float:
    """Usable horizontal space inside the page margins (LETTER, 0.5" each)."""
    return LETTER[0] - 1.0 * inch


def _table_style(header: bool = False) -> TableStyle:
    base = [
        ("BACKGROUND", (0, 1), (-1, -1), BG_CARD),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_DARK, BG_CARD]),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]
    if header:
        base += [
            ("BACKGROUND", (0, 0), (-1, 0), BORDER),
            ("TEXTCOLOR", (0, 0), (-1, 0), TEXT_PRIMARY),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
        ]
    return TableStyle(base)


def _severity_legend(result, s) -> list:
    bd = result.severity_breakdown
    items = [
        ("C", bd.critical, "critical"),
        ("H", bd.high,     "high"),
        ("M", bd.medium,   "medium"),
        ("L", bd.low,      "low"),
        ("I", bd.info,     "info"),
    ]
    line = " &nbsp; ".join(
        f"<font color='{'#' + SEV_COLORS[k].hexval()[2:]}'><b>{label}</b></font>"
        f"<font color='#FFFFFF'> {cnt}</font>"
        for label, cnt, k in items
    )
    return [Paragraph(line, s["body"])]


def _resolve_risk_score(result) -> float:
    """Return the 0-10 risk score, falling back to overall_risk_score."""
    score = getattr(result, "overall_risk_score", None)
    if score is None:
        return 0.0
    return float(score)


def _resolve_risk_level(result, score: float) -> str:
    """Map 0-10 score to a human-readable risk level."""
    if score >= 8.0:
        return "critical"
    if score >= 5.0:
        return "high"
    if score >= 2.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _html_safe(text: str) -> str:
    """Escape characters that confuse reportlab's mini-XML paragraph parser."""
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _truncate(text: str, n: int) -> str:
    if not text:
        return ""
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"
