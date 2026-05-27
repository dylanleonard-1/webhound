# WebHound — apps/api/internal/rbac.py
# RBAC dependencies for the internal /control command center.
#
# require_admin(min_role) returns a FastAPI dependency that resolves the
# authenticated user and enforces a minimum internal role. Roles are ranked in
# ROLE_RANK, so SUPER_ADMIN satisfies every check. Customer accounts have role
# "none" and are rejected from all internal routes.

from __future__ import annotations

from typing import Annotated, Callable

from fastapi import Depends, HTTPException

from apps.api.models.enums import ROLE_RANK, AdminRole
from apps.api.models.user import User
from apps.api.security import get_current_user

_CurrentUser = Annotated[User, Depends(get_current_user)]


def role_of(user: User) -> AdminRole:
    try:
        return AdminRole(user.admin_role)
    except ValueError:
        return AdminRole.NONE


def require_admin(min_role: AdminRole = AdminRole.READ_ONLY) -> Callable:
    """Dependency: require an authenticated staff user with >= min_role."""

    async def _dep(current_user: _CurrentUser) -> User:
        if ROLE_RANK.get(role_of(current_user), 0) < ROLE_RANK[min_role]:
            # 403 (not 404): the caller is authenticated but lacks the role.
            # The frontend /control route group handles hiding/redirecting.
            raise HTTPException(status_code=403, detail="Insufficient privileges")
        return current_user

    return _dep
