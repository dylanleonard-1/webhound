# WebHound — scanner/webhound/portfolio/client_groups.py
# Phase-17 Task 4: client groups — the agency/MSP abstraction for
# organizing sites into clients, franchise/office/store locations, and
# business units, each with its own rollup + scores.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webhound.portfolio.portfolio_score import compute_portfolio_scores
from webhound.portfolio.risk_rollup import build_risk_rollup
from webhound.portfolio.site_registry import SiteRecord, SiteRegistry


class GroupType(str, Enum):
    AGENCY_CLIENT = "agency_client"
    FRANCHISE_LOCATION = "franchise_location"
    OFFICE_LOCATION = "office_location"
    STORE_LOCATION = "store_location"
    BUSINESS_UNIT = "business_unit"


@dataclass
class ClientGroup:
    group_id: str
    name: str
    group_type: str = GroupType.AGENCY_CLIENT.value
    parent_group: str | None = None     # for nested business units

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "name": self.name,
            "group_type": self.group_type,
            "parent_group": self.parent_group,
        }


@dataclass
class GroupRollup:
    group: ClientGroup
    site_count: int
    scores: dict[str, Any]
    rollup: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.group.to_dict(),
            "site_count": self.site_count,
            "scores": self.scores,
            "rollup": self.rollup,
        }


class ClientGroupManager:
    """Manages client groups + computes per-group portfolio views."""

    def __init__(self, registry: SiteRegistry) -> None:
        self._registry = registry
        self._groups: dict[str, ClientGroup] = {}

    def add_group(self, group: ClientGroup) -> None:
        self._groups[group.group_id] = group

    def get_group(self, group_id: str) -> ClientGroup | None:
        return self._groups.get(group_id)

    @property
    def group_count(self) -> int:
        return len(self._groups)

    def groups_of_type(self, group_type: str) -> list[ClientGroup]:
        return [g for g in self._groups.values()
                if g.group_type == group_type]

    def sites_in_group(self, group_id: str) -> list[SiteRecord]:
        return self._registry.by_group(group_id)

    def rollup_group(self, group_id: str) -> GroupRollup | None:
        group = self._groups.get(group_id)
        if group is None:
            return None
        sites = self.sites_in_group(group_id)
        return GroupRollup(
            group=group, site_count=len(sites),
            scores=compute_portfolio_scores(sites).to_dict(),
            rollup=build_risk_rollup(sites).to_dict())

    def rollup_all(self) -> list[GroupRollup]:
        out = []
        for gid in self._groups:
            r = self.rollup_group(gid)
            if r is not None:
                out.append(r)
        # Highest-risk groups first.
        out.sort(key=lambda gr: gr.scores.get("portfolio_risk_score", 0),
                 reverse=True)
        return out
