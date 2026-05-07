# WebHound — scanner/webhound/core/finding_grouper.py
# Aggregates raw Finding objects into GroupedFinding objects for cleaner
# reporting and fair risk scoring.
#
# Grouping strategy:
#   Standard engines: group by (title, engine, category, remediation) — one
#     entry per distinct issue regardless of how many pages it appears on.
#   Per-URL engines: group by (title, engine, category, remediation, url) so
#     compromise/sensitive-path/WADE findings are never silently merged.

from __future__ import annotations

from collections import defaultdict

from webhound.models.finding import Finding
from webhound.models.grouped_finding import GroupedFinding

# Engines whose findings must stay separate per URL — never collapsed site-wide.
_PER_URL_ENGINES: frozenset[str] = frozenset({
    "sensitive_paths",       # each path is its own distinct finding
    "injected_js",           # per-page compromise signal
    "hidden_iframes",        # per-page compromise signal
    "seo_spam",              # per-page compromise signal
    "suspicious_redirects",  # per-page compromise signal
    "wade",                  # per-anomaly detection; context matters
})

_MAX_SAMPLE_URLS = 10


def _group_key(f: Finding) -> tuple:
    base = (f.title, f.scanner_engine, f.category.value, f.remediation or "")
    if f.scanner_engine in _PER_URL_ENGINES:
        loc = f.evidence[0].location if f.evidence else ""
        return base + (loc,)
    return base


class FindingGrouper:
    """Collapse repeated raw findings into one :class:`GroupedFinding` per distinct issue."""

    def group(self, findings: list[Finding]) -> list[GroupedFinding]:
        """Return one :class:`GroupedFinding` per distinct issue.

        For standard engines, findings that share (title, engine, category,
        remediation) are merged.  For per-URL engines they are only merged if
        they also share the same evidence URL — preventing important per-page
        details from being hidden.
        """
        buckets: dict[tuple, list[Finding]] = defaultdict(list)
        for f in findings:
            buckets[_group_key(f)].append(f)

        grouped = [self._merge(group) for group in buckets.values()]
        return sorted(grouped, key=lambda g: g.severity.rank, reverse=True)

    # ------------------------------------------------------------------

    def _merge(self, findings: list[Finding]) -> GroupedFinding:
        first = findings[0]

        seen_urls: list[str] = []
        seen_set: set[str] = set()
        for f in findings:
            loc = f.evidence[0].location if f.evidence else ""
            if loc and loc not in seen_set:
                seen_set.add(loc)
                seen_urls.append(loc)

        confidence = max(f.confidence for f in findings)
        scores = [f.anomaly_score for f in findings if f.anomaly_score is not None]

        return GroupedFinding(
            title=first.title,
            severity=first.severity,
            category=first.category,
            scanner_engine=first.scanner_engine,
            description=first.description,
            remediation=first.remediation,
            affected_url_count=len(seen_set) if seen_set else 1,
            affected_urls=sorted(seen_urls)[:_MAX_SAMPLE_URLS],
            evidence_count=len(findings),
            confidence=confidence,
            framework=first.framework,
            anomaly_score=max(scores) if scores else None,
            finding_ids=[str(f.id) for f in findings],
        )
