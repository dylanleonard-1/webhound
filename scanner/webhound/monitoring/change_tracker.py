# WebHound — scanner/webhound/monitoring/change_tracker.py
# Phase-11 Task 1/2: accumulate a site's change history across scans.
#
# The WADE timeline (metadata.wade_timeline) is per-scan; this folds each
# scan's changes into a persistent ChangeHistory so first/last-seen and
# frequency genuinely accumulate over time — the cross-scan tracking the
# per-scan timeline couldn't do on its own. Pure; the caller owns load
# /save of the ChangeHistory.

from __future__ import annotations

from typing import Any

from webhound.monitoring.change_history import (
    AlertTier,
    ChangeCategory,
    ChangeEvent,
    ChangeHistory,
    RiskDirection,
    TrackedAsset,
)

# WADE diff_type → (TrackedAsset, ChangeCategory, is_additive).
_DIFF_MAP: dict[str, tuple[TrackedAsset, ChangeCategory, bool]] = {
    "new_script_source":        (TrackedAsset.SCRIPT, ChangeCategory.SECURITY, True),
    "removed_script_source":    (TrackedAsset.SCRIPT, ChangeCategory.CONTENT, False),
    "changed_inline_script":    (TrackedAsset.SCRIPT, ChangeCategory.SECURITY, True),
    "new_external_domain":      (TrackedAsset.THIRD_PARTY, ChangeCategory.VENDOR, True),
    "removed_external_domain":  (TrackedAsset.THIRD_PARTY, ChangeCategory.VENDOR, False),
    "new_third_party_domain":   (TrackedAsset.THIRD_PARTY, ChangeCategory.VENDOR, True),
    "removed_third_party_domain": (TrackedAsset.THIRD_PARTY, ChangeCategory.VENDOR, False),
    "new_api_endpoint":         (TrackedAsset.API, ChangeCategory.TECHNOLOGY, True),
    "removed_api_endpoint":     (TrackedAsset.API, ChangeCategory.CONTENT, False),
    "new_form":                 (TrackedAsset.FORM, ChangeCategory.AUTHENTICATION, True),
    "form_field_change":        (TrackedAsset.FORM, ChangeCategory.AUTHENTICATION, True),
    "header_added":             (TrackedAsset.HEADER, ChangeCategory.SECURITY, True),
    "header_regression":        (TrackedAsset.HEADER, ChangeCategory.SECURITY, False),
    "cookie_behavior_change":   (TrackedAsset.COOKIE, ChangeCategory.SECURITY, True),
    "cookie_regression":        (TrackedAsset.COOKIE, ChangeCategory.SECURITY, False),
    "new_iframe":               (TrackedAsset.IFRAME, ChangeCategory.SECURITY, True),
    "redirect_change":          (TrackedAsset.REDIRECT, ChangeCategory.INFRASTRUCTURE, True),
    "technology_change":        (TrackedAsset.TECHNOLOGY, ChangeCategory.TECHNOLOGY, True),
    "status_code_change":       (TrackedAsset.PAGE, ChangeCategory.INFRASTRUCTURE, True),
    "dom_structure_change":     (TrackedAsset.PAGE, ChangeCategory.CONTENT, True),
}

# WADE change_type → ChangeCategory override (intent beats mechanics).
_CHANGE_TYPE_CATEGORY: dict[str, ChangeCategory] = {
    "new_payment_provider": ChangeCategory.PAYMENT,
    "new_auth_provider": ChangeCategory.AUTHENTICATION,
    "new_analytics_tool": ChangeCategory.VENDOR,
    "new_marketing_tool": ChangeCategory.VENDOR,
    "new_third_party_service": ChangeCategory.VENDOR,
    "suspicious_script_change": ChangeCategory.POSSIBLE_COMPROMISE,
    "suspicious_iframe": ChangeCategory.POSSIBLE_COMPROMISE,
    "suspicious_redirect": ChangeCategory.POSSIBLE_COMPROMISE,
    "possible_compromise": ChangeCategory.POSSIBLE_COMPROMISE,
    "confirmed_malicious_indicator": ChangeCategory.POSSIBLE_COMPROMISE,
}

# WADE band → AlertTier (Task 3 base mapping; alert_manager can escalate).
_BAND_TIER: dict[str, AlertTier] = {
    "very_low": AlertTier.INFORMATIONAL,
    "low": AlertTier.NOTICE,
    "medium": AlertTier.REVIEW,
    "high": AlertTier.WARNING,
    "critical": AlertTier.CRITICAL,
}


def _classify_record(rec: dict[str, Any]) -> tuple[str, str, str]:
    """Return (asset, category, direction) for one WADE timeline record."""
    diff_type = rec.get("diff_type", "")
    asset, category, additive = _DIFF_MAP.get(
        diff_type, (TrackedAsset.OTHER, ChangeCategory.CONTENT, True))
    # Intent override from the WADE change_type.
    ct = rec.get("change_type", "")
    if ct in _CHANGE_TYPE_CATEGORY:
        category = _CHANGE_TYPE_CATEGORY[ct]
    # Direction: security regressions / new risky things increase risk;
    # removals of risky things or added protections decrease it.
    if category == ChangeCategory.POSSIBLE_COMPROMISE:
        direction = RiskDirection.INCREASED
    elif diff_type in ("header_added",):
        direction = RiskDirection.DECREASED          # protection added
    elif diff_type in ("header_regression", "cookie_regression"):
        direction = RiskDirection.INCREASED          # protection lost
    elif additive and category in (ChangeCategory.SECURITY,
                                   ChangeCategory.AUTHENTICATION):
        direction = RiskDirection.INCREASED
    elif not additive:
        direction = RiskDirection.DECREASED
    else:
        direction = RiskDirection.UNCHANGED
    return asset.value, category.value, direction.value


def track_scan(
    history: ChangeHistory,
    *,
    wade_timeline: dict[str, Any] | None,
    scan_timestamp: str,
    target: str = "",
) -> ChangeHistory:
    """Fold one scan's WADE timeline into the persistent history.

    Existing change keys accumulate (last_seen + occurrences); new keys
    are added. Returns the same (mutated) history for chaining."""
    if target and not history.target:
        history.target = target
    history.scan_count += 1
    history.last_scan_at = scan_timestamp

    for rec in (wade_timeline or {}).get("records", []) or []:
        key = rec.get("change_key")
        if not key:
            continue
        asset, category, direction = _classify_record(rec)
        band = rec.get("band", "low")
        tier = _BAND_TIER.get(band, AlertTier.NOTICE)

        existing = history.records.get(key)
        if existing is not None:
            existing.last_seen = scan_timestamp
            existing.occurrences += 1
            existing.tier = tier.value
            existing.direction = direction
            existing.category = category
        else:
            history.records[key] = ChangeEvent(
                change_key=key,
                asset=asset,
                category=category,
                tier=tier.value,
                direction=direction,
                title=_title_for(rec, asset),
                detail=str(rec.get("value") or ""),
                url=rec.get("url"),
                confidence="confirmed" if rec.get("diff_type", "").startswith(
                    ("new_", "removed_", "header_", "cookie_")) else "medium",
                first_seen=scan_timestamp,
                last_seen=scan_timestamp,
                occurrences=1,
            )
    return history


def _title_for(rec: dict[str, Any], asset: str) -> str:
    diff_type = (rec.get("diff_type") or "").replace("_", " ")
    value = rec.get("value")
    base = diff_type.capitalize() if diff_type else f"{asset} change"
    if value:
        snippet = str(value)
        if len(snippet) > 60:
            snippet = snippet[:57] + "…"
        return f"{base}: {snippet}"
    return base
