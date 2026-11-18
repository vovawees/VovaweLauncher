from fastapi import APIRouter, Depends, Header, Response
from pydantic import BaseModel, Field
from app.api.deps import (
    AuthContext,
    get_cache,
    get_client_ip,
    get_current_auth,
    get_db,
    get_logs,
    rate_limit,
)
from app.config import Settings, get_settings
from app.core.responses import ApiError, ok_response
from app.core.security import new_token, now_ts, offline_mc_uuid, sha256_hex
from app.db import Database
from app.services.cache import RuntimeCache
from app.services.logger import LogService

router = APIRouter(prefix="/api/v1/game", tags=["Game"])


class GameTicketRequest(BaseModel):
    ram_mb: int = Field(default=6144, ge=1024, le=32768)
    os_name: str = Field(default="linux", max_length=32)
    gfx_backend: str = Field(default="vulkan", max_length=16)
    launcher_version: str = Field(default="0.1.0", max_length=32)
    launcher_hash: str | None = Field(default=None, max_length=128)
    modpack_hash: str | None = Field(default=None, max_length=128)
    hwid_hash: str | None = Field(default=None, max_length=128)


@router.get("/status")
async def game_status(
    cache: RuntimeCache = Depends(get_cache),
    settings: Settings = Depends(get_settings),
):
    st = cache.mc_status
    return ok_response({
        "online": st.online,
        "maintenance": settings.mc_maintenance,
        "players_online": st.players_online,
        "players_max": st.players_max,
        "ping_ms": st.ping_ms,
        "mc_version": st.version,
        "motd": st.motd,
        "client_version": cache.manifest.get("client_version", "0.9.6"),
        "launcher_latest_version": settings.launcher_latest_version,
        "updated_at": st.updated_at,
    })


@router.get("/news")
async def game_news(cache: RuntimeCache = Depends(get_cache)):
    return ok_response({"items": cache.news})


@router.get("/manifest")
async def game_manifest(
    os: str | None = None,
    if_none_match: str | None = Header(default=None),
    cache: RuntimeCache = Depends(get_cache),
    settings: Settings = Depends(get_settings),
):
    os_key = (os or "all").lower()
    etag = f'"{cache.manifest_sha256}:{os_key}"'
    if if_none_match == etag:
        return Response(status_code=304, headers={"ETag": etag})

    files = cache.manifest.get("files", [])
    if os_key in ("linux", "win32"):
        files = [f for f in files if f.get("os", "all") in ("all", os_key)]

    payload = {
        "client_version": cache.manifest.get("client_version", "0.9.6"),
        "mc_version": cache.manifest.get("mc_version", "1.20.1"),
        "forge_version": cache.manifest.get("forge_version", "47.3.0"),
        "manifest_hash": cache.manifest_sha256,
        "files_base_url": settings.files_base_url.rstrip("/"),
        "files": files,
    }
    return ok_response(payload, headers={"ETag": etag})


@router.post("/ticket", dependencies=[Depends(rate_limit("ticket", 15, 60))])
async def issue_game_ticket(
    body: GameTicketRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Database = Depends(get_db),
    cache: RuntimeCache = Depends(get_cache),
    logs: LogService = Depends(get_logs),
    ip: str = Depends(get_client_ip),
    settings: Settings = Depends(get_settings),
):
    if settings.mc_maintenance and auth.user["role"] not in ("admin", "tester"):
        raise ApiError(503, "MAINTENANCE", "Сервер на технических работах")

    if settings.strict_launcher_hash:
        expected = (
            settings.launcher_sha256_win32
            if body.os_name.lower() == "win32"
            else settings.launcher_sha256_linux
        )
        if expected and body.launcher_hash != expected:
            await logs.audit(
                "security",
                "ticket_denied_launcher_hash",
                severity="critical",
                user_id=auth.user["id"],
                ip=ip,
                hwid_hash=body.hwid_hash,
                details={"got": body.launcher_hash, "expected": expected},
            )
            raise ApiError(403, "LAUNCHER_TAMPERED", "Обнаружено несовпадение подписи лаунчера")

    ts = now_ts()
    raw_ticket = new_token("dmgt_", 28)
    expires_at = ts + settings.game_ticket_ttl_sec

    await db.execute_write(
        """
        INSERT INTO game_tickets (
            ticket_hash, user_id, session_id, ip, hwid_hash,
            launcher_hash, modpack_hash, ram_mb, status, issued_at, expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'issued', ?, ?)
        """,
        (
            sha256_hex(raw_ticket),
            auth.user["id"],
            auth.session["id"],
            ip,
            body.hwid_hash or auth.session.get("hwid_hash"),
            body.launcher_hash,
            body.modpack_hash or cache.manifest_sha256,
            body.ram_mb,
            ts,
            expires_at,
        ),
    )

    await logs.audit(
        "mc",
        "game_ticket_issued",
        user_id=auth.user["id"],
        ip=ip,
        hwid_hash=body.hwid_hash,
        details={
            "ram_mb": body.ram_mb,
            "os": body.os_name,
            "gfx": body.gfx_backend,
            "launcher_version": body.launcher_version,
        },
    )

    return ok_response({
        "game_ticket": raw_ticket,
        "expires_in": settings.game_ticket_ttl_sec,
        "username": auth.user["username"],
        "account_uuid": auth.user["account_uuid"],
        "offline_uuid": offline_mc_uuid(auth.user["username"]),
        "mc_connect": f"{settings.mc_host}:{settings.mc_port}",
    })
