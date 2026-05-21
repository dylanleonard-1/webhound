#!/usr/bin/env python3
"""Promote a WebHound user to admin (or revoke admin).

Usage:
    python3 scripts/promote_admin.py --email user@example.com
    python3 scripts/promote_admin.py --email user@example.com --revoke

Requires DATABASE_URL in environment or .env file.
The database must be reachable (run with the stack up, or set DATABASE_URL directly).
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_env = Path(".env")
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


async def _promote(email: str, *, revoke: bool) -> None:
    import sqlalchemy as sa
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    import apps.api.models  # noqa: F401
    from apps.api.models.user import User

    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("ERROR: DATABASE_URL is not set.", file=sys.stderr)
        sys.exit(1)

    engine = create_async_engine(db_url, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async with factory() as session:
        user = await session.scalar(sa.select(User).where(User.email == email))
        if user is None:
            print(f"ERROR: No user found with email '{email}'.", file=sys.stderr)
            await engine.dispose()
            sys.exit(1)

        target = not revoke
        if user.is_admin == target:
            state = "admin" if target else "non-admin"
            print(f"No change: '{email}' is already {state}.")
            await engine.dispose()
            return

        user.is_admin = target
        await session.commit()
        action = "revoked from" if revoke else "granted to"
        print(f"Admin {action}: {email}  (id={user.id})")

    await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Promote or revoke WebHound admin")
    parser.add_argument("--email", required=True, help="User email address")
    parser.add_argument(
        "--revoke", action="store_true", help="Remove admin privileges instead of granting"
    )
    args = parser.parse_args()
    asyncio.run(_promote(args.email, revoke=args.revoke))


if __name__ == "__main__":
    main()
