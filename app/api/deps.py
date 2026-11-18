from dataclasses import dataclass
from typing import Any
from fastapi import Depends, Header, Request
from app.config import Settings, get_settings
from app.core.responses import ApiError
from app.core.security import InMemoryRateLimiter, now_ts, sha256_hex
from app.db import Database
from app.services.bans import find_active_ban
from app.services.cache import RuntimeCache
from app.services.logger import LogService


@dataclass
class AuthContext:
    user: dict[str, Any]
    session: dict[str, Any]


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_cache(request: Request) -> RuntimeCache:
    return request.app.state.cache


def get_logs(request: Request) -> LogService:
    return request.app.state.logs


def get_limiter(request: Request) -> InMemoryRateLimiter:
    return request.app.state.limiter


def get_client_ip(request: Request, settings: Settings = Depends(get_settings)) -> str:
    if settings.trust_proxy_headers:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
        xri = request.headers.get("x-real-ip")
        if xri:
            return xri.strip()
    return request.client.host if request.client else "0.0.0.0"


def rate_limit(bucket: str, limit: int, window_sec: float):
    async def _checker(
        ip: str = Depends(get_client_ip),
        limiter: InMemoryRateLimiter = Depends(get_limiter),
    ) -> None:
        allowed, retry_after = limiter.allow(f"{bucket}:{ip}", limit, window_sec)
        if not allowed:
            raise ApiError(
                429,
                "RATE_LIMITED",
                f"Слишком много запросов. Повторите через {retry_after} сек.",
                {"retry_after": retry_after},
            )
    return _checker


async def get_current_auth(
    request: Request,
    authorization: str | None = Header(default=None),
    db: Database = Depends(get_db),
    ip: str = Depends(get_client_ip),
) -> AuthContext:
    if not authorization or not authorization.startswith("Bearer "):
        raise ApiError(401, "UNAUTHORIZED", "Требуется Bearer-токен сессии")

    token = authorization[7:].strip()
    if not token:
        raise ApiError(401, "UNAUTHORIZED", "Пустой токен сессии")

    token_hash = sha256_hex(token)
    ts = now_ts()

    session = await db.fetch_one(
        """
        SELECT * FROM sessions
        WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > ?
        """,
        (token_hash, ts),
    )
    if not session:
        raise ApiError(401, "SESSION_INVALID", "Сессия недействительна или истекла")

    user = await db.fetch_one("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    if not user:
        raise ApiError(401, "USER_NOT_FOUND", "Аккаунт не найден")

    ban = await find_active_ban(
        db,
        user_id=user["id"],
        tg_id=user["tg_id"],
        hwid_hash=session.get("hwid_hash"),
        ip=ip,
    )
    if ban:
        raise ApiError(403, "BANNED", f"Доступ заблокирован: {ban['reason']}", ban)

    # Обновляем last_seen не чаще раза в 60 сек, чтобы не нагружать SQLite на каждом пинге
    if ts - session["last_seen_at"] >= 60:
        await db.execute_write(
            "UPDATE sessions SET last_seen_at = ?, ip = ? WHERE id = ?",
            (ts, ip, session["id"]),
        )

    request.state.user_id = user["id"]
    return AuthContext(user=user, session=session)


async def require_internal_key(
    x_internal_key: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> None:
    if not x_internal_key or x_internal_key != settings.internal_api_key:
        raise ApiError(403, "FORBIDDEN_INTERNAL", "Недействительный внутренний ключ сервера")
