from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from app.api.deps import AuthContext, get_client_ip, get_current_auth, get_db, get_logs, rate_limit
from app.config import Settings, get_settings
from app.core.responses import ok_response, ApiError
from app.core.security import (
    hash_password,
    is_valid_nick,
    new_account_uuid,
    new_token,
    now_ts,
    sha256_hex,
    verify_password,
)
from app.db import Database
from app.services.bans import find_active_ban
from app.services.logger import LogService

router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


class DeviceTelemetry(BaseModel):
    hwid_hash: str | None = Field(default=None, max_length=128)
    os_name: str | None = Field(default=None, max_length=32)
    os_version: str | None = Field(default=None, max_length=64)
    arch: str | None = Field(default=None, max_length=16)
    cpu_info: str | None = Field(default=None, max_length=128)
    gpu_name: str | None = Field(default=None, max_length=128)
    gfx_backend: str | None = Field(default=None, max_length=16)
    ram_total_mb: int | None = None
    launcher_version: str | None = Field(default=None, max_length=32)
    launcher_hash: str | None = Field(default=None, max_length=128)


class TgInitRequest(BaseModel):
    purpose: str = Field(default="register", pattern="^(register|reset_pw)$")


class RegisterRequest(BaseModel):
    reg_token: str = Field(min_length=10, max_length=80)
    username: str = Field(min_length=3, max_length=16)
    password: str = Field(min_length=6, max_length=72)
    device: DeviceTelemetry | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=16)
    password: str = Field(min_length=1, max_length=72)
    device: DeviceTelemetry | None = None


class ResetPasswordRequest(BaseModel):
    reset_token: str = Field(min_length=10, max_length=80)
    new_password: str = Field(min_length=6, max_length=72)


async def _upsert_device(db: Database, user_id: int, device: DeviceTelemetry | None, ts: int) -> None:
    if not device or not device.hwid_hash:
        return
    await db.execute_write(
        """
        INSERT INTO devices (
            hwid_hash, first_user_id, last_user_id, os_name, os_version,
            cpu_info, gpu_name, gfx_backend, ram_total_mb, first_seen_at, last_seen_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hwid_hash) DO UPDATE SET
            last_user_id = excluded.last_user_id,
            os_name = COALESCE(excluded.os_name, devices.os_name),
            os_version = COALESCE(excluded.os_version, devices.os_version),
            cpu_info = COALESCE(excluded.cpu_info, devices.cpu_info),
            gpu_name = COALESCE(excluded.gpu_name, devices.gpu_name),
            gfx_backend = COALESCE(excluded.gfx_backend, devices.gfx_backend),
            ram_total_mb = COALESCE(excluded.ram_total_mb, devices.ram_total_mb),
            last_seen_at = excluded.last_seen_at
        """,
        (
            device.hwid_hash,
            user_id,
            user_id,
            device.os_name,
            device.os_version,
            device.cpu_info,
            device.gpu_name,
            device.gfx_backend,
            device.ram_total_mb,
            ts,
            ts,
        ),
    )
    await db.execute_write(
        """
        INSERT INTO user_devices (user_id, hwid_hash, first_seen_at, last_seen_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(user_id, hwid_hash) DO UPDATE SET last_seen_at = excluded.last_seen_at
        """,
        (user_id, device.hwid_hash, ts, ts),
    )


async def _issue_session(
    db: Database,
    user_id: int,
    device: DeviceTelemetry | None,
    ip: str,
    ttl_days: int,
    ts: int,
) -> tuple[str, int]:
    raw_token = new_token("dm_", 32)
    expires_at = ts + ttl_days * 86400
    await db.execute_write(
        """
        INSERT INTO sessions (
            token_hash, user_id, hwid_hash, os_name, os_version, arch,
            gpu_backend, launcher_version, launcher_hash, ip,
            created_at, last_seen_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            sha256_hex(raw_token),
            user_id,
            device.hwid_hash if device else None,
            device.os_name if device else None,
            device.os_version if device else None,
            device.arch if device else None,
            device.gfx_backend if device else None,
            device.launcher_version if device else None,
            device.launcher_hash if device else None,
            ip,
            ts,
            ts,
            expires_at,
        ),
    )
    return raw_token, expires_at


@router.post("/tg/init", dependencies=[Depends(rate_limit("tg_init", 12, 60))])
async def tg_init(
    body: TgInitRequest,
    db: Database = Depends(get_db),
    logs: LogService = Depends(get_logs),
    ip: str = Depends(get_client_ip),
    settings: Settings = Depends(get_settings),
):
    ts = now_ts()
    prefix = "reg_" if body.purpose == "register" else "rst_"
    token = new_token(prefix, 18)
    expires_at = ts + settings.tg_token_ttl_sec

    await db.execute_write(
        """
        INSERT INTO tg_bind_tokens (token, purpose, status, created_ip, expires_at, created_at)
        VALUES (?, ?, 'pending', ?, ?, ?)
        """,
        (token, body.purpose, ip, expires_at, ts),
    )
    await logs.audit("auth", "tg_init", ip=ip, details={"purpose": body.purpose})

    bot_url = f"https://t.me/{settings.telegram_bot_username}?start={token}"
    return ok_response({
        "token": token,
        "purpose": body.purpose,
        "bot_url": bot_url,
        "expires_in": settings.tg_token_ttl_sec,
    })


@router.get("/tg/poll", dependencies=[Depends(rate_limit("tg_poll", 90, 60))])
async def tg_poll(token: str, db: Database = Depends(get_db)):
    row = await db.fetch_one("SELECT * FROM tg_bind_tokens WHERE token = ?", (token,))
    if not row:
        raise ApiError(404, "TG_TOKEN_NOT_FOUND", "Токен привязки не найден")

    ts = now_ts()
    if row["expires_at"] <= ts and row["status"] == "pending":
        return ok_response({"status": "expired", "verified": False})

    return ok_response({
        "status": row["status"],
        "verified": row["status"] == "verified",
        "purpose": row["purpose"],
        "tg_username": row["tg_username"],
        "tg_first_name": row["tg_first_name"],
    })


@router.post("/register", dependencies=[Depends(rate_limit("register", 10, 300))])
async def register(
    body: RegisterRequest,
    db: Database = Depends(get_db),
    logs: LogService = Depends(get_logs),
    ip: str = Depends(get_client_ip),
    settings: Settings = Depends(get_settings),
):
    ts = now_ts()
    if not is_valid_nick(body.username):
        raise ApiError(400, "INVALID_NICK", "Ник должен содержать 3–16 символов (A-Z, 0-9, _)")

    bind = await db.fetch_one("SELECT * FROM tg_bind_tokens WHERE token = ?", (body.reg_token,))
    if not bind or bind["purpose"] != "register":
        raise ApiError(400, "INVALID_REG_TOKEN", "Неверный токен регистрации")
    if bind["status"] != "verified" or bind["tg_id"] is None:
        raise ApiError(400, "TG_NOT_VERIFIED", "Сначала подтвердите привязку в Telegram-боте")
    if bind["expires_at"] <= ts:
        raise ApiError(400, "TG_TOKEN_EXPIRED", "Время жизни токена истекло, запросите новый")

    ban = await find_active_ban(
        db,
        tg_id=bind["tg_id"],
        hwid_hash=body.device.hwid_hash if body.device else None,
        ip=ip,
    )
    if ban:
        raise ApiError(403, "BANNED", f"Регистрация запрещена: {ban['reason']}", ban)

    existing_tg = await db.fetch_one("SELECT id FROM users WHERE tg_id = ?", (bind["tg_id"],))
    if existing_tg:
        raise ApiError(409, "TG_ALREADY_BOUND", "Этот Telegram уже привязан к другому аккаунту")

    existing_nick = await db.fetch_one(
        "SELECT id FROM users WHERE username_lower = ?",
        (body.username.lower(),),
    )
    if existing_nick:
        raise ApiError(409, "NICK_TAKEN", "Этот никнейм уже занят")

    pw_hash = await hash_password(body.password)
    account_uuid = new_account_uuid()

    user_id = await db.execute_write(
        """
        INSERT INTO users (
            account_uuid, tg_id, tg_username, username, username_lower,
            password_hash, last_login_at, last_ip, login_count, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
        """,
        (
            account_uuid,
            bind["tg_id"],
            bind["tg_username"],
            body.username,
            body.username.lower(),
            pw_hash,
            ts,
            ip,
            ts,
            ts,
        ),
    )
    await db.execute_write(
        "UPDATE tg_bind_tokens SET status = 'used', user_id = ? WHERE token = ?",
        (user_id, body.reg_token),
    )
    await _upsert_device(db, user_id, body.device, ts)
    session_token, expires_at = await _issue_session(
        db, user_id, body.device, ip, settings.session_ttl_days, ts
    )

    await logs.audit(
        "auth",
        "register_success",
        user_id=user_id,
        tg_id=bind["tg_id"],
        ip=ip,
        hwid_hash=body.device.hwid_hash if body.device else None,
        details={"username": body.username, "account_uuid": account_uuid},
    )

    return ok_response(
        {
            "session_token": session_token,
            "expires_at": expires_at,
            "user": {
                "id": user_id,
                "account_uuid": account_uuid,
                "username": body.username,
                "tg_username": bind["tg_username"],
                "role": "player",
            },
        },
        message="Аккаунт успешно создан",
        status_code=201,
    )


@router.post("/login", dependencies=[Depends(rate_limit("login", 15, 60))])
async def login(
    body: LoginRequest,
    db: Database = Depends(get_db),
    logs: LogService = Depends(get_logs),
    ip: str = Depends(get_client_ip),
    settings: Settings = Depends(get_settings),
):
    ts = now_ts()
    user = await db.fetch_one(
        "SELECT * FROM users WHERE username_lower = ?",
        (body.username.lower(),),
    )
    if not user or not await verify_password(user["password_hash"], body.password):
        await logs.audit(
            "auth",
            "login_failed",
            severity="warn",
            user_id=user["id"] if user else None,
            ip=ip,
            hwid_hash=body.device.hwid_hash if body.device else None,
            details={"attempted_nick": body.username},
        )
        raise ApiError(401, "INVALID_CREDENTIALS", "Неверный никнейм или пароль")

    ban = await find_active_ban(
        db,
        user_id=user["id"],
        tg_id=user["tg_id"],
        hwid_hash=body.device.hwid_hash if body.device else None,
        ip=ip,
    )
    if ban:
        raise ApiError(403, "BANNED", f"Аккаунт заблокирован: {ban['reason']}", ban)

    await _upsert_device(db, user["id"], body.device, ts)
    await db.execute_write(
        "UPDATE users SET last_login_at = ?, last_ip = ?, login_count = login_count + 1, updated_at = ? WHERE id = ?",
        (ts, ip, ts, user["id"]),
    )
    session_token, expires_at = await _issue_session(
        db, user["id"], body.device, ip, settings.session_ttl_days, ts
    )

    await logs.audit(
        "auth",
        "login_success",
        user_id=user["id"],
        tg_id=user["tg_id"],
        ip=ip,
        hwid_hash=body.device.hwid_hash if body.device else None,
        details={"launcher_version": body.device.launcher_version if body.device else None},
    )

    return ok_response({
        "session_token": session_token,
        "expires_at": expires_at,
        "user": {
            "id": user["id"],
            "account_uuid": user["account_uuid"],
            "username": user["username"],
            "tg_username": user["tg_username"],
            "role": user["role"],
        },
    })


@router.post("/reset-password", dependencies=[Depends(rate_limit("reset_pw", 10, 300))])
async def reset_password(
    body: ResetPasswordRequest,
    db: Database = Depends(get_db),
    logs: LogService = Depends(get_logs),
    ip: str = Depends(get_client_ip),
):
    ts = now_ts()
    bind = await db.fetch_one("SELECT * FROM tg_bind_tokens WHERE token = ?", (body.reset_token,))
    if not bind or bind["purpose"] != "reset_pw":
        raise ApiError(400, "INVALID_RESET_TOKEN", "Неверный токен сброса пароля")
    if bind["status"] != "verified" or not bind["user_id"] or bind["expires_at"] <= ts:
        raise ApiError(400, "RESET_NOT_VERIFIED", "Подтвердите сброс пароля в Telegram-боте")

    pw_hash = await hash_password(body.new_password)
    await db.execute_write(
        "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
        (pw_hash, ts, bind["user_id"]),
    )
    await db.execute_write(
        "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        (ts, bind["user_id"]),
    )
    await db.execute_write("UPDATE tg_bind_tokens SET status = 'used' WHERE token = ?", (body.reset_token,))
    await logs.audit("auth", "password_reset", user_id=bind["user_id"], tg_id=bind["tg_id"], ip=ip)

    return ok_response({}, message="Пароль изменён, старые сессии завершены")


@router.post("/logout")
async def logout(
    auth: AuthContext = Depends(get_current_auth),
    db: Database = Depends(get_db),
    logs: LogService = Depends(get_logs),
    ip: str = Depends(get_client_ip),
):
    ts = now_ts()
    await db.execute_write("UPDATE sessions SET revoked_at = ? WHERE id = ?", (ts, auth.session["id"]))
    await logs.audit("auth", "logout", user_id=auth.user["id"], ip=ip)
    return ok_response({}, message="Выход выполнен")
