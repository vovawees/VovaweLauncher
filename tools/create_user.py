#!/usr/bin/env python3
"""CLI-утилита для быстрого создания пользователя/админа без Telegram-бота."""
import argparse
import asyncio
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings
from app.core.security import hash_password, new_account_uuid, now_ts
from app.db import Database


async def main() -> None:
    parser = argparse.ArgumentParser(description="Create user in VovaweLauncher DB")
    parser.add_argument("--username", "-u", required=True, help="Player nickname (3-16 chars)")
    parser.add_argument("--password", "-p", required=True, help="Password")
    parser.add_argument("--role", "-r", default="admin", choices=["player", "admin", "tester"])
    parser.add_argument("--tg-id", type=int, default=100000001, help="Telegram ID (optional)")
    parser.add_argument("--tg-username", default="DevUser", help="Telegram @username")
    args = parser.parse_args()

    settings = get_settings()
    db = Database(Path(settings.db_path))
    await db.connect()

    existing = await db.fetch_one("SELECT id FROM users WHERE username_lower = ?", (args.username.lower(),))
    if existing:
        print(f"Error: Username '{args.username}' is already taken.")
        await db.close()
        return

    ts = now_ts()
    pw_hash = await hash_password(args.password)
    uuid = new_account_uuid()

    uid = await db.execute_write(
        """
        INSERT INTO users (
            account_uuid, tg_id, tg_username, username, username_lower,
            password_hash, role, last_login_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (uuid, args.tg_id, args.tg_username, args.username, args.username.lower(), pw_hash, args.role, ts, ts, ts),
    )
    await db.close()
    print(f"User created successfully!")
    print(f"  ID:           {uid}")
    print(f"  Username:     {args.username}")
    print(f"  UUID:         {uuid}")
    print(f"  Role:         {args.role}")
    print(f"  Telegram ID:  {args.tg_id} (@{args.tg_username})")


if __name__ == "__main__":
    asyncio.run(main())
