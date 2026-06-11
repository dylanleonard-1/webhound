# WebHound — apps/api/services/scanner_access_diagnosis.py
# Phase 3.4 scanner-access — assemble the LAYERED, honest scanner-access diagnosis
# for the dashboard: is the site verified? is Cloudflare connected? is Cloudflare
# actually the blocker? what's the Cloudflare scanner-access status, and what's the
# real next action (which may be a DIFFERENT provider, e.g. Vercel)?
#
# The pure `assemble_diagnosis` is the testable core; `diagnose_scanner_access`
# gathers the facts from the DB and calls it. Customer-safe (no tokens / zone ids
# beyond what's already surfaced).

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.website import Website
from apps.api.services import cloudflare as cf
from apps.api.services import cloudflare_scanner_state as state
from apps.api.services import cloudflare_scopes as cf_scopes
from apps.api.services import scanner_block_detection as det
from apps.api.services import trusted_access as ta_service
from apps.api.services.access_validation import _latest_scan_metadata
from apps.api.services.verification import is_ownership_verified

SCANNER_ACCESS_META_KEY = "scanner_access"


def assemble_diagnosis(
    detection: dict, *, verified: bool, cloudflare_connected: bool,
    has_rule: bool, rule_validated: bool, has_rule_edit_permission: bool,
    rule_setup_failed: bool = False, rule_meta: dict | None = None,
    evidence: list | None = None,
) -> dict:
    """Pure assembly of the layered diagnosis from plain facts."""
    s = state.derive_status(
        detection, cloudflare_connected=cloudflare_connected, has_rule=has_rule,
        rule_validated=rule_validated, has_rule_edit_permission=has_rule_edit_permission,
        rule_setup_failed=rule_setup_failed)
    return {
        "verified": verified,
        "cloudflare_connected": cloudflare_connected,
        "cloudflare_scanner_access": s["status"],
        # `blocker` = the provider actually blocking the scan (what to act on next);
        # `diagnosis` = the layer nuance: cloudflare | vercel | both | unknown.
        "blocker": detection.get("active_blocker_provider") or detection.get("diagnosis"),
        "diagnosis": detection.get("diagnosis"),
        "confidence": detection.get("confidence"),
        "next_action": s["next_action"],
        "message": s["message"],
        "rule": rule_meta or None,
        # Non-secret detection signals (for the support ticket).
        "evidence": [str(e)[:200] for e in (evidence or [])][:10],
    }


def _customer_safe_rule(meta: dict | None) -> dict | None:
    """Expose only non-sensitive rule facts (no token; zone id already known to the
    owner)."""
    if not meta:
        return None
    return {
        "rule_type": meta.get("rule_type"),
        "created_by_webhound": meta.get("created_by_webhound"),
        "created_at": meta.get("created_at"),
        "last_validated_at": meta.get("last_validated_at"),
        "degraded": meta.get("degraded", False),
    }


async def diagnose_scanner_access(db: AsyncSession, website: Website) -> dict:
    """Gather facts and return the layered scanner-access diagnosis for `website`."""
    conn = await cf.get_connection(db, website.id)
    cloudflare_connected = bool(conn and conn.connection_status == "connected")

    metadata, _pages = await _latest_scan_metadata(db, website)
    bp = metadata.get("browser_pass") if isinstance(metadata, dict) else None
    ya = bp.get("yield_assessment") if isinstance(bp, dict) else None
    detection = det.classify_scan_blocker(ya, cloudflare_connected=cloudflare_connected)

    sa_meta = ((conn.connection_metadata or {}).get(SCANNER_ACCESS_META_KEY)
               if conn else None)
    has_rule = bool(sa_meta and sa_meta.get("rule_ids"))
    rule_validated = bool(sa_meta and sa_meta.get("last_validated_at"))
    rule_setup_failed = bool(sa_meta and sa_meta.get("failed"))

    profile = await ta_service.get_trusted_access(db, website)
    granted = (profile.permissions_granted if profile else None) or []
    has_perm = cf_scopes.has_rule_edit_permission(granted)

    ev = ya.get("evidence") if isinstance(ya, dict) else None
    return assemble_diagnosis(
        detection, verified=is_ownership_verified(website),
        cloudflare_connected=cloudflare_connected, has_rule=has_rule,
        rule_validated=rule_validated, has_rule_edit_permission=has_perm,
        rule_setup_failed=rule_setup_failed, rule_meta=_customer_safe_rule(sa_meta),
        evidence=ev if isinstance(ev, list) else None)
