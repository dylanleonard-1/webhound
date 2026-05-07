# WebHound — scanner/webhound/wade/anomaly_scorer.py
# Combines diff signals with context-page weight to produce a per-anomaly score
# in [0.0, 1.0].  Higher scores indicate more suspicious changes.

from __future__ import annotations

from dataclasses import dataclass

from webhound.wade.context_engine import ContextEngine, PageContext
from webhound.wade.diff_engine import DiffItem, DiffType


# Base scores for each diff type before context weighting
BASE_SCORES: dict[DiffType, float] = {
    DiffType.NEW_SCRIPT_SOURCE:     0.75,
    DiffType.CHANGED_INLINE_SCRIPT: 0.75,
    DiffType.NEW_EXTERNAL_DOMAIN:   0.50,
    DiffType.HEADER_REGRESSION:     0.45,
    DiffType.COOKIE_REGRESSION:     0.55,
    DiffType.NEW_FORM:              0.40,
    DiffType.FORM_FIELD_CHANGE:     0.40,
    DiffType.STATUS_CODE_CHANGE:    0.20,
}


@dataclass
class ScoredAnomaly:
    """A diff item enriched with anomaly score and context information."""

    diff_item: DiffItem
    raw_score: float       # base score before context weighting
    context_weight: float  # multiplier from page context
    anomaly_score: float   # raw_score × context_weight, clamped to [0, 1]
    context_type: str


class AnomalyScorer:
    """Score diff items using per-type base rates and context-page weights."""

    def __init__(self) -> None:
        self._ctx = ContextEngine()

    def score(self, diff_items: list[DiffItem]) -> list[ScoredAnomaly]:
        """Return a :class:`ScoredAnomaly` for each diff item."""
        result: list[ScoredAnomaly] = []
        for item in diff_items:
            ctx = self._ctx.classify(item.url)
            raw = BASE_SCORES.get(item.diff_type, 0.3)
            weighted = min(1.0, raw * ctx.weight)
            result.append(ScoredAnomaly(
                diff_item=item,
                raw_score=raw,
                context_weight=ctx.weight,
                anomaly_score=round(weighted, 4),
                context_type=ctx.context_type,
            ))
        return result

    def aggregate_page_score(
        self, anomalies: list[ScoredAnomaly]
    ) -> dict[str, float]:
        """Return the highest anomaly score per URL."""
        scores: dict[str, float] = {}
        for a in anomalies:
            url = a.diff_item.url
            scores[url] = max(scores.get(url, 0.0), a.anomaly_score)
        return scores
