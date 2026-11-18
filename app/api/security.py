from typing import Any
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from app.api.deps import AuthContext, get_client_ip, get_current_auth, get_db, get_logs, rate_limit
from app.config import Settings, get_settings
from app.core.responses import ApiError, ok_response
from app.core.security import new_token, now_ts
from app.db import Database
from app.services.logger import LogService

router = APIRouter(prefix="/api/v1", tags=["Security & Plugins"])


class ChallengeRequest(BaseModel):
    plugin_id: str = Field(default="core_launcher", max_length=64)


class AttestRequest(BaseModel):
    challenge_id: str = Field(min_length=8, max_length=80)
    source: str = Field(default="launcher", pattern="^(launcher|launcher_plugin|mc_mod)$")
    plugin_id: str = Field(default="core_launcher", max_length=64)
    passed: bool = True
    launcher_hash: str | None = Field(default=None, max_length=128)
    client_mod_hash: str | None = Field(default=None, max_length=128)
    hwid_hash: str | None = Field(default=None, max_length=128)
    details: dict[str, Any] = Field(default_factory=dict)


class TelemetryRequest(BaseModel):
    source: str = Field(default="launcher", max_length=32)
    event_name: str = Field(min_length=2, max_length=64)
    hwid_hash: str | None = Field(default=None, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)


@router.get("/security/launcher-policy")
async def launcher_policy(settings: Settings = Depends(get_settings)):
    return ok_response({
        "latest_version": settings.launcher_latest_version,
        "min_version": settings.launcher_min_version,
        "strict_hash_check": settings.strict_launcher_hash,
        "expected_hashes": {
            "linux": settings.launcher_sha256_linux,
            "win32": settings.launcher_sha256_win32,
        },
        "required_plugins": [],
    })


@router.get("/plugins/registry")
async def plugins_registry():
    """Реестр будущих плагинов лаунчера и клиентских/серверных модулей безопасности."""
    return ok_response({
        "launcher_plugins": [],
        "mc_security_mods": [],
    })


@router.post("/security/challenge", dependencies=[Depends(rate_limit("sec_challenge", 30, 60))])
async def create_challenge(
    body: ChallengeRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Database = Depends(get_db),
    ip: str = Depends(get_client_ip),
    settings: Settings = Depends(get_settings),
):
    ts = now_ts()
    cid = new_token("chg_", 16)
    nonce = new_token("", 24)
    expires_at = ts + settings.challenge_ttl_sec

    await db.execute_write(
        """
        INSERT INTO security_challenges (challenge_id, nonce, user_id, session_id, ip, status, issued_at, expires_at)
        VALUES (?, ?, ?, ?, ?, 'issued', ?, ?)
        """,
        (cid, nonce, auth.user["id"], auth.session["id"], ip, ts, expires_at),
    )

    return ok_response({
        "challenge_id": cid,
        "nonce": nonce,
        "plugin_id": body.plugin_id,
        "expires_in": settings.challenge_ttl_sec,
    })


@router.post("/security/attest", dependencies=[Depends(rate_limit("sec_attest", 30, 60))])
async def submit_attestation(
    body: AttestRequest,
    auth: AuthContext = Depends(get_current_auth),
    db: Database = Depends(get_db),
    logs: LogService = Depends(get_logs),
    ip: str = Depends(get_client_ip),
):
    ts = now_ts()
    chg = await db.fetch_one("SELECT * FROM security_challenges WHERE challenge_id = ?", (body.challenge_id,))
    if not chg or chg["user_id"] != auth.user["id"] or chg["status"] != "issued":
        raise ApiError(400, "INVALID_CHALLENGE", "Челлендж не найден или уже использован")
    if chg["expires_at"] <= ts:
        raise ApiError(400, "CHALLENGE_EXPIRED", "Время челленджа истекло")

    new_status = "verified" if body.passed else "failed"
    await db.execute_write(
        "UPDATE security_challenges SET status = ? WHERE challenge_id = ?",
        (new_status, body.challenge_id),
    )

    severity = "info" if body.passed else "critical"
    import json
    await db.execute_write(
        """
        INSERT INTO security_reports (
            source, plugin_id, user_id, session_id, hwid_hash, event_type,
            severity, passed, launcher_hash, client_mod_hash, details_json, ip, created_at
        )
        VALUES (?, ?, ?, ?, ?, 'attestation', ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            body.source,
            body.plugin_id,
            auth.user["id"],
            auth.session["id"],
            body.hwid_hash or auth.session.get("hwid_hash"),
            severity,
            1 if body.passed else 0,
            body.launcher_hash,
            body.client_mod_hash,
            json.dumps(body.details, ensure_ascii=False),
            ip,
            ts,
        ),
    )

    if not body.passed and (body.hwid_hash or auth.session.get("hwid_hash")):
        hwid = body.hwid_hash or auth.session.get("hwid_hash")
        await db.execute_write(
            "UPDATE devices SET trust_score = MAX(0, trust_score - 25), is_flagged = 1 WHERE hwid_hash = ?",
            (hwid,),
        )

    await logs.audit(
        "security",
        f"attest_{new_status}",
        severity=severity,
        user_id=auth.user["id"],
        ip=ip,
        hwid_hash=body.hwid_hash,
        details={"source": body.source, "plugin_id": body.plugin_id},
    )

    return ok_response({"accepted": True, "status": new_status})


@router.post("/telemetry/event", dependencies=[Depends(rate_limit("telemetry", 60, 60))])
async def ingest_telemetry(
    body: TelemetryRequest,
    auth: AuthContext = Depends(get_current_auth),
    logs: LogService = Depends(get_logs),
    ip: str = Depends(get_client_ip),
):
    await logs.telemetry(
        body.source,
        body.event_name,
        body.payload,
        user_id=auth.user["id"],
        hwid_hash=body.hwid_hash or auth.session.get("hwid_hash"),
        ip=ip,
    )
    return ok_response({"queued": True})
