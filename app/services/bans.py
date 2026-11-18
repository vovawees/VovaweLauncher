from typing import Any
from app.core.security import now_ts
from app.db import Database


async def find_active_ban(
    db: Database,
    *,
    user_id: int | None = None,
    tg_id: int | None = None,
    hwid_hash: str | None = None,
    ip: str | None = None,
) -> dict[str, Any] | None:
    ts = now_ts()

    if user_id is not None:
        u = await db.fetch_one(
            "SELECT is_banned, ban_reason, ban_expires_at FROM users WHERE id = ?",
            (user_id,),
        )
        if u and u["is_banned"]:
            if u["ban_expires_at"] is None or u["ban_expires_at"] > ts:
                return {
                    "target_type": "user",
                    "reason": u["ban_reason"] or "Нарушение правил сервера",
                    "expires_at": u["ban_expires_at"],
                }

    checks: list[tuple[str, str]] = []
    if user_id is not None:
        checks.append(("user", str(user_id)))
    if tg_id is not None:
        checks.append(("tg_id", str(tg_id)))
    if hwid_hash:
        checks.append(("hwid", hwid_hash))
    if ip:
        checks.append(("ip", ip))

    for t_type, t_val in checks:
        row = await db.fetch_one(
            """
            SELECT target_type, reason, expires_at
            FROM bans
            WHERE target_type = ? AND target_value = ? AND active = 1
              AND (expires_at IS NULL OR expires_at > ?)
            ORDER BY id DESC LIMIT 1
            """,
            (t_type, t_val, ts),
        )
        if row:
            return row

    return None
