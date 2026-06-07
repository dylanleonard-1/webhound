# WebHound — scanner/webhound/threat_intel/supply_chain.py
# Phase-13 Task 4/6: supply-chain change detection. Diffs a previous vs
# current vendor/script/CDN inventory and classifies each change by how
# dangerous it is — the standout being a KNOWN vendor replaced by an
# UNKNOWN one ("Stripe replaced by an unrecognised provider").
#
# Pure: operates on host/script lists the caller extracts from two scans
# (or the WADE baseline). Reputation comes from DomainReputationEngine.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from webhound.threat_intel.domain_reputation import (
    DomainReputationEngine,
    ReputationClass,
)


class SupplyChainChangeType(str, Enum):
    NEW_KNOWN_VENDOR = "new_known_vendor"
    NEW_UNKNOWN_VENDOR = "new_unknown_vendor"
    NEW_MALICIOUS_VENDOR = "new_malicious_vendor"
    VENDOR_REMOVED = "vendor_removed"
    KNOWN_REPLACED_BY_UNKNOWN = "known_replaced_by_unknown"
    KNOWN_REPLACED_BY_MALICIOUS = "known_replaced_by_malicious"
    NEW_CDN = "new_cdn"


class SupplyChainSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SupplyChainChange:
    change_type: SupplyChainChangeType
    severity: SupplyChainSeverity
    host: str
    replaced_host: str | None = None
    category: str = "unknown"
    detail: str = ""
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_type": self.change_type.value,
            "severity": self.severity.value,
            "host": self.host,
            "replaced_host": self.replaced_host,
            "category": self.category,
            "detail": self.detail,
            "confidence": self.confidence,
        }


def _registrable(host: str) -> str:
    from webhound.browser.network_capture import _registrable as _r
    return _r(host)


def _reg_set(hosts: Iterable[str]) -> dict[str, str]:
    """registrable-domain → first host seen (so cdn.x.com and x.com group)."""
    out: dict[str, str] = {}
    for h in hosts:
        h = (h or "").lower()
        if not h:
            continue
        reg = _registrable(h)
        out.setdefault(reg, h)
    return out


class SupplyChainEngine:
    def __init__(
        self, *, domain_engine: DomainReputationEngine | None = None,
    ) -> None:
        self._domain = domain_engine or DomainReputationEngine()

    def diff(
        self,
        *,
        previous_hosts: Iterable[str],
        current_hosts: Iterable[str],
    ) -> list[SupplyChainChange]:
        """Compare two third-party host inventories. Detects new/removed
        vendors and — the key signal — a known vendor in a category being
        replaced by an unknown/malicious one in the same category."""
        prev = _reg_set(previous_hosts)
        cur = _reg_set(current_hosts)
        prev_regs = set(prev)
        cur_regs = set(cur)

        added = cur_regs - prev_regs
        removed = prev_regs - cur_regs

        changes: list[SupplyChainChange] = []

        # Reputation + category lookups (cached inside the engine).
        def rep(host: str):
            return self._domain.assess(host)

        # Index removed vendors by category to detect replacements.
        removed_by_cat: dict[str, list[str]] = {}
        for reg in removed:
            r = rep(prev[reg])
            removed_by_cat.setdefault(r.vendor_category, []).append(prev[reg])

        consumed_removals: set[str] = set()

        for reg in sorted(added):
            host = cur[reg]
            r = rep(host)
            cat = r.vendor_category

            # Replacement: a same-category KNOWN vendor disappeared and an
            # unknown/malicious one appeared. This is the dangerous case.
            replacement_for = None
            if cat != "unknown" and removed_by_cat.get(cat):
                for old in removed_by_cat[cat]:
                    old_rep = rep(old)
                    if old_rep.reputation in (ReputationClass.TRUSTED,
                                              ReputationClass.KNOWN_VENDOR):
                        replacement_for = old
                        break

            if r.reputation == ReputationClass.MALICIOUS:
                if replacement_for:
                    consumed_removals.add(replacement_for)
                    changes.append(SupplyChainChange(
                        SupplyChainChangeType.KNOWN_REPLACED_BY_MALICIOUS,
                        SupplyChainSeverity.CRITICAL, host=host,
                        replaced_host=replacement_for, category=cat,
                        confidence="high",
                        detail=(f"{cat} vendor {replacement_for} replaced by "
                                f"malicious host {host}")))
                else:
                    changes.append(SupplyChainChange(
                        SupplyChainChangeType.NEW_MALICIOUS_VENDOR,
                        SupplyChainSeverity.CRITICAL, host=host, category=cat,
                        confidence="high",
                        detail=f"new malicious third-party host {host}"))
                continue

            if replacement_for and r.reputation in (
                    ReputationClass.UNKNOWN, ReputationClass.SUSPICIOUS,
                    ReputationClass.NORMAL):
                consumed_removals.add(replacement_for)
                sev = (SupplyChainSeverity.HIGH
                       if r.reputation == ReputationClass.SUSPICIOUS
                       else SupplyChainSeverity.MEDIUM)
                changes.append(SupplyChainChange(
                    SupplyChainChangeType.KNOWN_REPLACED_BY_UNKNOWN,
                    sev, host=host, replaced_host=replacement_for,
                    category=cat, confidence="medium",
                    detail=(f"known {cat} vendor {replacement_for} replaced by "
                            f"unrecognised host {host}")))
                continue

            # Plain additions.
            if r.reputation in (ReputationClass.TRUSTED,
                                ReputationClass.KNOWN_VENDOR):
                ctype = (SupplyChainChangeType.NEW_CDN
                         if cat == "cdn"
                         else SupplyChainChangeType.NEW_KNOWN_VENDOR)
                changes.append(SupplyChainChange(
                    ctype, SupplyChainSeverity.INFO, host=host, category=cat,
                    confidence="high",
                    detail=f"new known {cat or 'vendor'} {host}"))
            else:
                changes.append(SupplyChainChange(
                    SupplyChainChangeType.NEW_UNKNOWN_VENDOR,
                    SupplyChainSeverity.LOW, host=host, category=cat,
                    confidence="medium",
                    detail=f"new unrecognised third-party host {host}"))

        # Removals not consumed by a replacement → informational.
        for reg in sorted(removed):
            host = prev[reg]
            if host in consumed_removals:
                continue
            r = rep(host)
            changes.append(SupplyChainChange(
                SupplyChainChangeType.VENDOR_REMOVED,
                SupplyChainSeverity.INFO, host=host,
                category=r.vendor_category, confidence="high",
                detail=f"third-party host {host} no longer present"))

        return changes
