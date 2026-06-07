# WebHound — scanner/webhound/industry/industry_classifier.py
# Phase-19 Task 2: infer the business industry from safe, passive signals.
#
# No network calls, no JavaScript execution. We reason only over what a scan
# already surfaced: domain text, the page title, the meta description,
# homepage text, schema.org @types, and the set of detected vendors. When a
# user explicitly selected a category we trust it; otherwise we score each
# industry by keyword / schema / vendor evidence and pick the leader — but
# only if it clears a confidence floor. When nothing converges we honestly
# return UNKNOWN rather than guess.

from __future__ import annotations

import re

from webhound.industry.models import (
    Confidence,
    Industry,
    IndustryClassification,
    IndustrySignals,
    industry_from_value,
)
from webhound.industry.vendor_catalog import lookup as vendor_lookup

# ---------------------------------------------------------------------------
# Keyword signals (Task 2). Weighted: strong, identifying words score higher
# than generic ones that several industries share ("contact", "about").
# ---------------------------------------------------------------------------

# (regex, weight). Word boundaries keep "barber" from matching "bar".
_KEYWORDS: dict[Industry, list[tuple[str, float]]] = {
    Industry.RESTAURANT: [
        (r"\bmenu\b", 2.0), (r"\breservations?\b", 2.5),
        (r"\border online\b", 3.0), (r"\bonline ordering\b", 3.0),
        (r"\bcatering\b", 2.0), (r"\bdelivery\b", 1.5),
        (r"\btakeout\b", 2.0), (r"\bdine[- ]in\b", 2.0),
        (r"\brestaurant\b", 2.5), (r"\bcafe\b|\bcafé\b", 1.5),
        (r"\bgift cards?\b", 1.0), (r"\bhours?\b", 0.5),
    ],
    Industry.DENTAL_HEALTHCARE: [
        (r"\bdental\b", 3.0), (r"\bdentist\b", 3.0),
        (r"\bpatients?\b", 2.0), (r"\bappointments?\b", 2.0),
        (r"\binsurance\b", 1.5), (r"\bnew patient\b", 3.0),
        (r"\bteeth\b|\btooth\b", 1.5), (r"\borthodont", 2.5),
        (r"\bhygiene\b", 1.0), (r"\bcrowns?\b|\bfillings?\b", 1.5),
        (r"\bclinic\b", 1.0), (r"\bdoctor\b|\bdr\.", 0.5),
    ],
    Industry.LAW_FIRM: [
        (r"\battorneys?\b", 3.0), (r"\blawyers?\b", 3.0),
        (r"\bconsultation\b", 1.5), (r"\bpractice areas?\b", 3.0),
        (r"\bcase evaluation\b", 3.0), (r"\blaw firm\b", 3.0),
        (r"\blegal\b", 1.5), (r"\blitigation\b", 2.0),
        (r"\bcounsel\b", 1.5), (r"\bclients?\b", 0.5),
        (r"\bcase\b", 1.0), (r"\bplaintiff\b|\bdefendant\b", 2.0),
    ],
    Industry.LOCAL_ECOMMERCE: [
        (r"\bcart\b", 2.5), (r"\bcheckout\b", 3.0),
        (r"\bproducts?\b", 1.5), (r"\bcollections?\b", 1.5),
        (r"\bshop\b", 2.0), (r"\bshipping\b", 2.0),
        (r"\badd to cart\b", 3.0), (r"\bstore\b", 1.0),
        (r"\border status\b", 2.0), (r"\bsale\b", 0.5),
        (r"\bfree shipping\b", 2.0),
    ],
    Industry.HOME_SERVICES: [
        (r"\bquote\b", 2.0), (r"\bestimate\b", 2.5),
        (r"\brepairs?\b", 1.5), (r"\bhvac\b", 3.0),
        (r"\bplumbing\b", 3.0), (r"\broofing\b", 3.0),
        (r"\belectrical\b", 2.5), (r"\bcontractor\b", 2.5),
        (r"\bservice area\b", 2.0), (r"\binstallation\b", 1.5),
        (r"\bemergency service\b", 2.0), (r"\blicensed & insured\b", 2.0),
    ],
    Industry.NONPROFIT_CHURCH: [
        (r"\bdonate\b|\bdonations?\b", 2.5), (r"\bnonprofit\b|\bnon-profit\b", 3.0),
        (r"\bchurch\b", 3.0), (r"\bministry\b|\bministries\b", 2.5),
        (r"\bvolunteers?\b", 2.0), (r"\bcongregation\b", 2.5),
        (r"\bworship\b", 2.5), (r"\bsermons?\b", 2.5),
        (r"\bgiving\b", 1.5), (r"\bmission\b", 1.0),
        (r"\bfundrais", 2.0), (r"\b501\(c\)\b", 3.0),
    ],
    Industry.PROFESSIONAL_SERVICES: [
        (r"\bconsulting\b", 2.5), (r"\baccounting\b", 2.5),
        (r"\bbookkeeping\b", 2.5), (r"\bagency\b", 1.5),
        (r"\bservices\b", 0.5), (r"\bconsultants?\b", 2.0),
        (r"\badvisory\b", 2.0), (r"\bfreelance\b", 1.5),
        (r"\bportfolio\b", 1.0), (r"\bschedule a call\b", 1.5),
    ],
}

_COMPILED: dict[Industry, list[tuple[re.Pattern[str], float]]] = {
    ind: [(re.compile(p, re.IGNORECASE), w) for p, w in pairs]
    for ind, pairs in _KEYWORDS.items()
}

# schema.org @type → industry (a strong, structured signal worth a big boost).
_SCHEMA_TYPES: dict[str, Industry] = {
    "restaurant": Industry.RESTAURANT,
    "bakery": Industry.RESTAURANT,
    "cafeorcoffeeshop": Industry.RESTAURANT,
    "barorpub": Industry.RESTAURANT,
    "foodestablishment": Industry.RESTAURANT,
    "dentist": Industry.DENTAL_HEALTHCARE,
    "medicalclinic": Industry.DENTAL_HEALTHCARE,
    "medicalbusiness": Industry.DENTAL_HEALTHCARE,
    "physician": Industry.DENTAL_HEALTHCARE,
    "hospital": Industry.DENTAL_HEALTHCARE,
    "dentaloffice": Industry.DENTAL_HEALTHCARE,
    "attorney": Industry.LAW_FIRM,
    "legalservice": Industry.LAW_FIRM,
    "lawfirm": Industry.LAW_FIRM,
    "store": Industry.LOCAL_ECOMMERCE,
    "onlinestore": Industry.LOCAL_ECOMMERCE,
    "clothingstore": Industry.LOCAL_ECOMMERCE,
    "product": Industry.LOCAL_ECOMMERCE,
    "offer": Industry.LOCAL_ECOMMERCE,
    "homeandconstructionbusiness": Industry.HOME_SERVICES,
    "plumber": Industry.HOME_SERVICES,
    "hvacbusiness": Industry.HOME_SERVICES,
    "electrician": Industry.HOME_SERVICES,
    "roofingcontractor": Industry.HOME_SERVICES,
    "generalcontractor": Industry.HOME_SERVICES,
    "ngo": Industry.NONPROFIT_CHURCH,
    "church": Industry.NONPROFIT_CHURCH,
    "placeofworship": Industry.NONPROFIT_CHURCH,
    "professionalservice": Industry.PROFESSIONAL_SERVICES,
    "accountingservice": Industry.PROFESSIONAL_SERVICES,
    "financialservice": Industry.PROFESSIONAL_SERVICES,
}

_SCHEMA_WEIGHT = 4.0      # one strong structured hit
_VENDOR_WEIGHT = 3.0      # a recognised industry vendor is strong evidence

# Confidence thresholds on the leading industry's absolute score and its
# margin over the runner-up.
_HIGH_SCORE = 6.0
_MEDIUM_SCORE = 3.0
_LOW_SCORE = 1.5
_DOMINANCE_MARGIN = 2.0   # leader must beat runner-up by this for HIGH


class IndustryClassifier:
    """Infer a business industry from passive scan signals."""

    def classify(self, signals: IndustrySignals) -> IndustryClassification:
        # 1. User-selected category wins outright when recognised.
        if signals.user_category:
            picked = industry_from_value(signals.user_category)
            if picked != Industry.UNKNOWN:
                return IndustryClassification(
                    industry=picked,
                    confidence=Confidence.HIGH,
                    score=float(_HIGH_SCORE),
                    signals=[f"user-selected category: {signals.user_category}"],
                    scores_by_industry={picked.value: float(_HIGH_SCORE)},
                    source="user_selected",
                )

        text = signals.combined_text()
        scores: dict[Industry, float] = {ind: 0.0 for ind in _COMPILED}
        evidence: dict[Industry, list[str]] = {ind: [] for ind in _COMPILED}

        # 2. Keyword evidence.
        for ind, patterns in _COMPILED.items():
            for rx, weight in patterns:
                if rx.search(text):
                    scores[ind] += weight
                    evidence[ind].append(f"keyword '{rx.pattern}'")

        # 3. schema.org evidence.
        for raw in signals.schema_types or []:
            key = str(raw).strip().lower().lstrip("@")
            ind = _SCHEMA_TYPES.get(key)
            if ind is not None:
                scores[ind] += _SCHEMA_WEIGHT
                evidence[ind].append(f"schema.org type '{raw}'")

        # 4. Vendor evidence — a recognised industry vendor points at its
        #    industries (split the weight when a vendor spans several).
        for host in signals.detected_vendors or []:
            vendor = vendor_lookup(host)
            if vendor is None:
                continue
            share = _VENDOR_WEIGHT / max(1, len(vendor.industries))
            for ind in vendor.industries:
                if ind in scores:
                    scores[ind] += share
                    evidence[ind].append(f"vendor {vendor.name}")

        # 5. Pick the leader and assign confidence.
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        leader, top = ranked[0]
        runner_up = ranked[1][1] if len(ranked) > 1 else 0.0

        if top < _LOW_SCORE:
            return IndustryClassification(
                industry=Industry.UNKNOWN,
                confidence=Confidence.LOW,
                score=round(top, 2),
                signals=["no clear industry signals"],
                scores_by_industry={k.value: v for k, v in scores.items() if v},
                source="default",
            )

        if top >= _HIGH_SCORE and (top - runner_up) >= _DOMINANCE_MARGIN:
            confidence = Confidence.HIGH
        elif top >= _MEDIUM_SCORE:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW

        return IndustryClassification(
            industry=leader,
            confidence=confidence,
            score=round(top, 2),
            signals=evidence[leader][:8],
            scores_by_industry={k.value: round(v, 2)
                                for k, v in scores.items() if v},
            source="inferred",
        )


def classify_industry(signals: IndustrySignals) -> IndustryClassification:
    """Module-level convenience wrapper."""
    return IndustryClassifier().classify(signals)
