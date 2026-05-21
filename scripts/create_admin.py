#!/usr/bin/env python3
"""
WebHound — create an admin user in the database.

Usage:
    python3 scripts/create_admin.py
    python3 scripts/create_admin.py --email admin@example.com --password s3cr3t

Requires DATABASE_URL in environment or .env file.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path

# Ensure repo root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load .env if present
_env = Path(".env")
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


async def _create(email: str, password: str) -> None:
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    import apps.api.models  # noqa: F401
    from apps.api.database import Base
    from apps.api.models.user import User
    from apps.api.security import hash_password

    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        print("ERROR: DATABASE_URL is not set.", file=sys.stderr)
        sys.exit(1)

    engine = create_async_engine(db_url, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        from sqlalchemy import select
        existing = await session.scalar(select(User).where(User.email == email))
        if existing:
            print(f"User '{email}' already exists (id={existing.id}).")
            await engine.dispose()
            return

        user = User(
            email=email,
            hashed_password=hash_password(password),
            is_active=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        print(f"Created user: {email}  (id={user.id})")

    await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a WebHound admin user")
    parser.add_argument("--email", help="User email address")
    parser.add_argument("--password", help="Password (prompted if omitted)")
    args = parser.parse_args()

    email = args.email or input("Email: ").strip()
    if not email:
        print("Email is required.", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)

    if len(password) < 8:
        print("Password must be at least 8 characters.", file=sys.stderr)
        sys.exit(1)

    asyncio.run(_create(email, password))


if __name__ == "__main__":
    main()
