# WebHound — apps/api/services/wade_correlation.py
# Phase-4 WADE expansion: cross-scan *behavioural* correlation.
#
# Distinct from the per-scan `compute_delta` (which compares N-1 → N)
# and from the per-page `wade.diff_engine.DiffEngine` (which compares a
# single page against a baseline snapshot). This module operates on
# the *history* of scans for one website and looks for patterns no
# single delta can see:
#
#   * sustained tech-stack churn (≥3 distinct tech changes in N scans)
#   * recurring TLS instability (≥2 TLS-config changes in N scans)
#   * unexplained third-party explosion (current scan's domain count
#     is ≥3x the median of the prior N-1 scans)
#   * persistent header regressions (the same security header has
#     been missing or wrong across the last N scans)
#   * admin/login surface flapping (a login form appears and disappears
#     across scans — common in misconfigured staging→prod promotion)
#
# Each finding describes *what changed*, *why it matters*, and
# *evidence* (the scan_job_ids it draws from). Per Phase-4 §3D —
# explainability is mandatory.

from __future__ import annotations

import statistics
import uuid
from dataclasses import dataclass, field

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from apps.api.models.enums import DriftSeverity, ScanStatus
from apps.api.models.scan_job import ScanJob
from apps.api.models.scan_result import ScanResultRecord
from apps.api.services.scan_delta import ScanFingerprint


DEFAULT_WINDOW = 5


@dataclass
class BehaviouralAnomaly:
    """One cross-scan behavioural anomaly. Each anomaly explains itself:
    which pattern fired, the affected scan_job_ids that contributed,
    and a one-paragraph rationale suitable for the UI."""

    pattern: str                # short identifier (used as dedup key)
    title: str
    description: str
    severity: DriftSeverity
    evidence_scan_job_ids: list[str] = field(default_factory=list)
    metric_values: dict[str, float] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Behavioural rules. Each rule takes the list of fingerprints
# *chronological order, oldest first*, and returns an anomaly or None.
# Conservative thresholds — only fire on patterns that aren't likely
# explained by ordinary site evolution.
# ---------------------------------------------------------------------------


def _rule_tech_stack_churn(
    fingerprints: list[ScanFingerprint],
) -> BehaviouralAnomaly | None:
    if len(fingerprints) < 3:
        return None
    # Count distinct tech changes across the window — tech that appeared
    # in one scan and disappeared in the next, or vice-versa.
    changes = 0
    seen_changes: set[str] = set()
    for prev, cur in zip(fingerprints, fingerprints[1:]):
        delta_set = (cur.technologies ^ prev.technologies)
        changes += len(delta_set)
        seen_changes |= delta_set
    if changes < 3:
        return None
    return BehaviouralAnomaly(
        pattern="tech_stack_churn",
        title=f"Repeated tech-stack changes across last {len(fingerprints)} scans",
        description=(
            f"The detected technology fingerprint changed {changes} times "
            f"across {len(fingerprints)} scans (≥3 distinct technologies "
            f"have appeared or disappeared). Sustained churn at this rate "
            f"typically indicates either a major migration in progress, "
            f"frequent vendor swaps, or scanner false-positives caused "
            f"by intermittent rendering. Worth confirming via an asset "
            f"inventory."
        ),
        severity=DriftSeverity.MEDIUM,
        evidence_scan_job_ids=[str(fp.scan_job_id) for fp in fingerprints],
        metric_values={"distinct_tech_changes": float(changes)},
    )


def _rule_tls_instability(
    fingerprints: list[ScanFingerprint],
) -> BehaviouralAnomaly | None:
    if len(fingerprints) < 3:
        return None
    changes = 0
    for prev, cur in zip(fingerprints, fingerprints[1:]):
        if cur.tls_summary.get("min_tls_version") != prev.tls_summary.get(
            "min_tls_version"
        ):
            changes += 1
        if cur.tls_summary.get("cipher_suite") != prev.tls_summary.get(
            "cipher_suite"
        ):
            changes += 1
    if changes < 2:
        return None
    return BehaviouralAnomaly(
        pattern="tls_instability",
        title=(
            f"Recurring TLS configuration changes ({changes} flips "
            f"in last {len(fingerprints)} scans)"
        ),
        description=(
            f"Transport security parameters (min TLS version and/or "
            f"cipher suite) changed {changes} times across the last "
            f"{len(fingerprints)} scans. TLS configuration should be "
            f"stable. Recurring changes typically point at a "
            f"misconfigured load-balancer rotation, an unstable A/B "
            f"between origin servers, or staging configuration leaking "
            f"into production."
        ),
        severity=DriftSeverity.HIGH,
        evidence_scan_job_ids=[str(fp.scan_job_id) for fp in fingerprints],
        metric_values={"tls_change_count": float(changes)},
    )


def _rule_third_party_explosion(
    fingerprints: list[ScanFingerprint],
) -> BehaviouralAnomaly | None:
    if len(fingerprints) < 3:
        return None
    domain_counts = [len(fp.external_domains) for fp in fingerprints]
    *history, latest = domain_counts
    if latest < 5:
        return None
    # Need a stable baseline — at least 2 prior scans.
    median_prev = statistics.median(history)
    # Avoid divide-by-zero; if median was 0, ANY appearance triggers a
    # softer LOW signal — but only if there are at least a handful of
    # new domains, otherwise this is a noisy first-scan effect.
    if median_prev == 0:
        return None
    if latest < median_prev * 3:
        return None
    return BehaviouralAnomaly(
        pattern="third_party_explosion",
        title=(
            f"Third-party host count tripled in latest scan "
            f"({int(median_prev)} → {latest})"
        ),
        description=(
            f"The latest scan referenced {latest} external hosts, but "
            f"the median across the previous {len(history)} scans was "
            f"{int(median_prev)}. A ≥3× jump in third-party surface in "
            f"one scan window is usually a tag-manager misconfig (the "
            f"GTM container loaded a campaign that itself pulls in many "
            f"vendors), a CDN-vendor swap, or a CMS template insertion. "
            f"Investigate vendor inventory + recent template changes."
        ),
        severity=DriftSeverity.HIGH,
        evidence_scan_job_ids=[str(fp.scan_job_id) for fp in fingerprints],
        metric_values={
            "median_previous": float(median_prev),
            "current": float(latest),
            "ratio": float(latest) / float(median_prev),
        },
    )


def _rule_persistent_header_regression(
    fingerprints: list[ScanFingerprint],
) -> BehaviouralAnomaly | None:
    """A security-relevant header that USED to be set has been absent
    or weakened across the last 2+ scans."""
    if len(fingerprints) < 3:
        return None
    # Headers that were present in the oldest scan.
    oldest = fingerprints[0]
    monitored = {"Content-Security-Policy", "Strict-Transport-Security",
                  "X-Frame-Options", "Referrer-Policy"}
    regressed: list[str] = []
    for hdr in monitored:
        was_set = bool(oldest.security_headers.get(hdr))
        if not was_set:
            continue
        # Has it been missing in the last 2 scans?
        last_two = fingerprints[-2:]
        if all(not bool(fp.security_headers.get(hdr)) for fp in last_two):
            regressed.append(hdr)
    if not regressed:
        return None
    return BehaviouralAnomaly(
        pattern="persistent_header_regression",
        title=(
            f"{len(regressed)} security header(s) absent across "
            f"last 2 scans"
        ),
        description=(
            "The following security header(s) were present in the "
            f"earliest scan in the window and have been missing across "
            f"the last 2: {', '.join(regressed)}. This is a sustained "
            f"regression, not transient — likely a config-management "
            f"change that didn't roll out the header alongside other "
            f"updates. Audit the deployment that started the gap."
        ),
        severity=DriftSeverity.HIGH,
        evidence_scan_job_ids=[str(fp.scan_job_id) for fp in fingerprints],
        metric_values={"regressed_count": float(len(regressed))},
    )


def _rule_login_form_flapping(
    fingerprints: list[ScanFingerprint],
) -> BehaviouralAnomaly | None:
    """A login/admin form keeps appearing and disappearing across
    scans — almost always means staging config leaking into prod or
    incomplete promotion of an environment toggle."""
    if len(fingerprints) < 4:
        return None
    def _has_login(fp: ScanFingerprint) -> bool:
        return any(
            ("login" in f.lower() or "admin" in f.lower()
             or "auth" in f.lower())
            for f in fp.forms
        )
    presence = [_has_login(fp) for fp in fingerprints]
    flips = sum(
        1 for a, b in zip(presence, presence[1:]) if a != b
    )
    if flips < 2:
        return None
    return BehaviouralAnomaly(
        pattern="login_form_flapping",
        title=f"Login/admin form appearance flapped {flips} times",
        description=(
            f"Across the last {len(fingerprints)} scans, a login or admin "
            f"form appeared and disappeared {flips} times. Stable sites "
            f"have stable authentication surfaces. Flapping usually "
            f"means staging config is intermittently leaking into prod, "
            f"or an environment-toggled feature is mis-rolling-out."
        ),
        severity=DriftSeverity.MEDIUM,
        evidence_scan_job_ids=[str(fp.scan_job_id) for fp in fingerprints],
        metric_values={"flip_count": float(flips)},
    )


_BEHAVIOURAL_RULES = (
    _rule_tech_stack_churn,
    _rule_tls_instability,
    _rule_third_party_explosion,
    _rule_persistent_header_regression,
    _rule_login_form_flapping,
)


# ---------------------------------------------------------------------------
# Public entry point — loads the recent fingerprint history for a
# website and runs every rule against it.
# ---------------------------------------------------------------------------


def analyse_history(
    fingerprints: list[ScanFingerprint],
) -> list[BehaviouralAnomaly]:
    """Pure-function — run every behavioural rule over the given
    chronological fingerprint history (oldest first). Returns a
    de-duplicated list of anomalies."""
    out: list[BehaviouralAnomaly] = []
    for rule in _BEHAVIOURAL_RULES:
        try:
            anomaly = rule(fingerprints)
        except Exception:  # noqa: BLE001
            continue
        if anomaly is not None:
            out.append(anomaly)
    return out


async def analyse_website(
    db: AsyncSession,
    website_id: uuid.UUID,
    *,
    window: int = DEFAULT_WINDOW,
) -> list[BehaviouralAnomaly]:
    """Load the most recent ``window`` completed scans for the website,
    build their fingerprints, and run :func:`analyse_history`. Returns
    ``[]`` if too few scans exist to draw conclusions."""
    rows = (await db.execute(
        sa.select(ScanJob, ScanResultRecord)
        .join(ScanResultRecord,
              ScanResultRecord.scan_job_id == ScanJob.id)
        .where(
            ScanJob.website_id == website_id,
            ScanJob.status == ScanStatus.COMPLETED,
        )
        .order_by(ScanJob.completed_at.desc().nulls_last(),
                   ScanJob.created_at.desc())
        .limit(window),
    )).all()
    if not rows:
        return []
    # rows came back newest-first; we want chronological oldest-first.
    rows = list(reversed(rows))
    fps = [
        ScanFingerprint.from_scan_result(result, scan_job=job)
        for job, result in rows
    ]
    return analyse_history(fps)
