from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from app.api.deps import AuthContext, get_client_ip, get_current_auth, get_db, get_logs, rate_limit
from app.config import Settings, get_settings
from app.core.responses import ApiError, ok_response
from app.core.security import is_valid_nick, now_ts
from app.db import Database
from app.services.logger import LogService

router = APIRouter(prefix="/api/v1/profile", tags=["Profile"])


class ChangeNickRequest(BaseModel):
    new_username: str = Field(min_length=3, max_length=16)


@router.get("/me")
async def get_me(
    auth: AuthContext = Depends(get_current_auth),
    db: Database = Depends(get_db),
    settings: Settings = Depends(get_settings),
):
    u = auth.user
    ts = now_ts()
    cd_sec = settings.nick_cooldown_days * 86400
    last_changed = u["nick_changed_at"]
    remaining = max(0, (last_changed + cd_sec) - ts) if last_changed else 0

    history = await db.fetch_all(
        "SELECT old_username, new_username, changed_at FROM nick_history WHERE user_id = ? ORDER BY id DESC LIMIT 5",
        (u["id"],),
    )

    return ok_response({
        "id": u["id"],
        "account_uuid": u["account_uuid"],
        "username": u["username"],
        "role": u["role"],
        "tg_username": u["tg_username"],
        "nick_change_available": remaining == 0,
        "nick_cooldown_remaining_sec": remaining,
        "nick_changed_at": last_changed,
        "created_at": u["created_at"],
        "login_count": u["login_count"],
        "nick_history": history,
    })


@router.post("/nick", dependencies=[Depends(rate_limit("change_nick", 10, 60))])
async def change_nick(
    body: ChangeNickRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Database = Depends(get_db),
    logs: LogService = Depends(get_logs),
    ip: str = Depends(get_client_ip),
    settings: Settings = Depends(get_settings),
):
    u = auth.user
    new_nick = body.new_username.strip()

    if not is_valid_nick(new_nick):
        raise ApiError(400, "INVALID_NICK", "Ник должен содержать 3–16 символов (A-Z, 0-9, _)")

    if new_nick == u["username"]:
        return ok_response({"username": u["username"]}, message="Никнейм не изменился")

    ts = now_ts()
    cd_sec = settings.nick_cooldown_days * 86400
    if u["nick_changed_at"]:
        remaining = (u["nick_changed_at"] + cd_sec) - ts
        if remaining > 0 and u["role"] != "admin":
            raise ApiError(
                429,
                "NICK_COOLDOWN",
                "Смена никнейма доступна не чаще 1 раза в 7 дней",
                {"remaining_sec": remaining},
            )

    # Разрешаем смену регистра своего же ника, но запрещаем занимать чужой
    taken = await db.fetch_one(
        "SELECT id FROM users WHERE username_lower = ? AND id != ?",
        (new_nick.lower(), u["id"]),
    )
    if taken:
        raise ApiError(409, "NICK_TAKEN", "Этот никнейм уже занят другим игроком")

    old_nick = u["username"]
    await db.execute_write(
        "UPDATE users SET username = ?, username_lower = ?, nick_changed_at = ?, updated_at = ? WHERE id = ?",
        (new_nick, new_nick.lower(), ts, ts, u["id"]),
    )
    await db.execute_write(
        "INSERT INTO nick_history (user_id, old_username, new_username, ip, changed_at) VALUES (?, ?, ?, ?, ?)",
        (u["id"], old_nick, new_nick, ip, ts),
    )
    await logs.audit(
        "profile",
        "nick_changed",
        user_id=u["id"],
        ip=ip,
        details={"old_username": old_nick, "new_username": new_nick},
    )

    return ok_response(
        {
            "username": new_nick,
            "old_username": old_nick,
            "next_change_at": ts + cd_sec,
            "nick_cooldown_remaining_sec": cd_sec,
        },
        message=f"Никнейм изменён на {new_nick}",
    )
