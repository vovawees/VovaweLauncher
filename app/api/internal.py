import json
from typing import Any
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from app.api.deps import get_cache, get_db, get_logs, require_internal_key
from app.config import Settings, get_settings
from app.core.responses import ApiError, ok_response
from app.core.security import now_ts, sha256_hex
from app.db import Database
from app.services.bans import find_active_ban
from app.services.cache import RuntimeCache
from app.services.logger import LogService

router = APIRouter(
    prefix="/api/v1/internal",
    tags=["Internal (MC Mod & Admin)"],
    dependencies=[Depends(require_internal_key)],
)


class McVerifyJoinRequest(BaseModel):
    game_ticket: str = Field(min_length=8, max_length=128)
    username: str = Field(min_length=3, max_length=16)
    ip: str = Field(min_length=3, max_length=64)
    mc_server_id: str = Field(default="main", max_length=32)
    client_mod_hash: str | None = Field(default=None, max_length=128)
    client_launcher_hash: str | None = Field(default=None, max_length=128)
    extra: dict[str, Any] = Field(default_factory=dict)


class McEventRequest(BaseModel):
    event_type: str = Field(min_length=2, max_length=64)
    severity: str = Field(default="info", pattern="^(info|warn|critical)$")
    username: str | None = None
    account_uuid: str | None = None
    ip: str | None = None
    passed: bool = True
    notify_admins: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class BanRequest(BaseModel):
    target_type: str = Field(pattern="^(user|tg_id|hwid|ip)$")
    target_value: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=2, max_length=256)
    duration_sec: int | None = None
    issued_by: str = Field(default="mc_security_mod", max_length=64)


@router.post("/mc/verify-join")
async def verify_mc_join(
    body: McVerifyJoinRequest,
    db: Database = Depends(get_db),
    logs: LogService = Depends(get_logs),
):
    """Вызывается будущим модом безопасности на Forge 1.20.1 при входе игрока на сервер."""
    ts = now_ts()
    ticket_hash = sha256_hex(body.game_ticket)
    ticket = await db.fetch_one("SELECT * FROM game_tickets WHERE ticket_hash = ?", (ticket_hash,))

    if not ticket:
        await logs.audit(
            "mc",
            "join_rejected_no_ticket",
            severity="warn",
            ip=body.ip,
            details={"username": body.username},
        )
        return ok_response({"allowed": False, "reason": "Недействительный тикет входа"})

    if ticket["status"] != "issued" or ticket["expires_at"] <= ts:
        return ok_response({"allowed": False, "reason": "Тикет уже использован или истёк"})

    user = await db.fetch_one("SELECT * FROM users WHERE id = ?", (ticket["user_id"],))
    if not user or user["username_lower"] != body.username.lower():
        await logs.audit(
            "mc",
            "join_rejected_nick_mismatch",
            severity="critical",
            user_id=ticket["user_id"],
            ip=body.ip,
            details={"expected": user["username"] if user else None, "got": body.username},
        )
        return ok_response({"allowed": False, "reason": "Ник не совпадает с авторизованным в лаунчере"})

    ban = await find_active_ban(
        db,
        user_id=user["id"],
        tg_id=user["tg_id"],
        hwid_hash=ticket.get("hwid_hash"),
        ip=body.ip,
    )
    if ban:
        return ok_response({"allowed": False, "reason": f"Бан: {ban['reason']}"})

    await db.execute_write(
        "UPDATE game_tickets SET status = 'used', used_at = ?, mc_server_id = ? WHERE ticket_hash = ?",
        (ts, body.mc_server_id, ticket_hash),
    )

    await logs.audit(
        "mc",
        "join_verified",
        user_id=user["id"],
        ip=body.ip,
        hwid_hash=ticket.get("hwid_hash"),
        details={"server": body.mc_server_id, "mod_hash": body.client_mod_hash},
    )

    return ok_response({
        "allowed": True,
        "account_id": user["id"],
        "account_uuid": user["account_uuid"],
        "username": user["username"],
        "role": user["role"],
        "hwid_hash": ticket.get("hwid_hash"),
    })


@router.post("/mc/event")
async def ingest_mc_event(
    body: McEventRequest,
    request: Request,
    db: Database = Depends(get_db),
    logs: LogService = Depends(get_logs),
    settings: Settings = Depends(get_settings),
):
    ts = now_ts()
    user_id: int | None = None
    if body.account_uuid:
        u = await db.fetch_one("SELECT id FROM users WHERE account_uuid = ?", (body.account_uuid,))
        if u:
            user_id = u["id"]
    elif body.username:
        u = await db.fetch_one("SELECT id FROM users WHERE username_lower = ?", (body.username.lower(),))
        if u:
            user_id = u["id"]

    await db.execute_write(
        """
        INSERT INTO security_reports (
            source, plugin_id, user_id, event_type, severity, passed, details_json, ip, created_at
        )
        VALUES ('mc_mod', 'forge_security', ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,
            body.event_type,
            body.severity,
            1 if body.passed else 0,
            json.dumps(body.details, ensure_ascii=False),
            body.ip,
            ts,
        ),
    )
    await logs.audit(
        "mc",
        body.event_type,
        severity=body.severity,
        user_id=user_id,
        ip=body.ip,
        details=body.details,
    )

    if body.notify_admins and getattr(request.app.state, "bot", None):
        bot = request.app.state.bot
        msg = (
            f"🚨 <b>MC Security Alert [{body.severity.upper()}]</b>\n"
            f"Событие: <code>{body.event_type}</code>\n"
            f"Игрок: <code>{body.username or body.account_uuid or 'unknown'}</code>\n"
            f"IP: <code>{body.ip or '-'}</code>\n"
            f"Детали: <code>{json.dumps(body.details, ensure_ascii=False)[:500]}</code>"
        )
        for admin_id in settings.admin_tg_ids:
            try:
                await bot.send_message(admin_id, msg)
            except Exception:
                pass

    return ok_response({"recorded": True})


@router.get("/mc/player/{identifier}")
async def lookup_player(identifier: str, db: Database = Depends(get_db)):
    """Поиск игрока по account_uuid, текущему нику или старому нику (для миграции лута при смене ника)."""
    user = await db.fetch_one(
        """
        SELECT id, account_uuid, tg_id, tg_username, username, role, is_banned,
               ban_reason, nick_changed_at, last_login_at, last_ip, created_at
        FROM users
        WHERE account_uuid = ? OR username_lower = ?
        """,
        (identifier, identifier.lower()),
    )
    if not user:
        hist = await db.fetch_one(
            "SELECT user_id FROM nick_history WHERE old_username = ? COLLATE NOCASE ORDER BY id DESC LIMIT 1",
            (identifier,),
        )
        if hist:
            user = await db.fetch_one(
                """
                SELECT id, account_uuid, tg_id, tg_username, username, role, is_banned,
                       ban_reason, nick_changed_at, last_login_at, last_ip, created_at
                FROM users WHERE id = ?
                """,
                (hist["user_id"],),
            )

    if not user:
        raise ApiError(404, "PLAYER_NOT_FOUND", "Игрок не найден")

    nicks = await db.fetch_all(
        "SELECT old_username, new_username, changed_at FROM nick_history WHERE user_id = ? ORDER BY id DESC LIMIT 10",
        (user["id"],),
    )
    return ok_response({"player": user, "nick_history": nicks})


@router.post("/mc/ban")
async def ban_target(
    body: BanRequest,
    db: Database = Depends(get_db),
    logs: LogService = Depends(get_logs),
):
    ts = now_ts()
    expires_at = (ts + body.duration_sec) if body.duration_sec else None

    await db.execute_write(
        """
        INSERT INTO bans (target_type, target_value, reason, issued_by, expires_at, active, created_at)
        VALUES (?, ?, ?, ?, ?, 1, ?)
        """,
        (body.target_type, body.target_value, body.reason, body.issued_by, expires_at, ts),
    )
    if body.target_type == "user" and body.target_value.isdigit():
        uid = int(body.target_value)
        await db.execute_write(
            "UPDATE users SET is_banned = 1, ban_reason = ?, ban_expires_at = ?, updated_at = ? WHERE id = ?",
            (body.reason, expires_at, ts, uid),
        )
        await db.execute_write(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (ts, uid),
        )

    await logs.audit(
        "security",
        "ban_issued",
        severity="critical",
        details={
            "target_type": body.target_type,
            "target_value": body.target_value,
            "reason": body.reason,
            "issued_by": body.issued_by,
        },
    )
    return ok_response({"banned": True})


@router.post("/manifest/reload")
async def reload_manifest(
    cache: RuntimeCache = Depends(get_cache),
    settings: Settings = Depends(get_settings),
):
    cache.load_manifest(settings.manifest_path)
    return ok_response({
        "manifest_hash": cache.manifest_sha256,
        "files_count": len(cache.manifest.get("files", [])),
    })
