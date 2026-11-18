import asyncio
from pathlib import Path
from typing import Any
import aiosqlite


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_uuid    TEXT NOT NULL UNIQUE,
    tg_id           INTEGER NOT NULL UNIQUE,
    tg_username     TEXT,
    username        TEXT NOT NULL,
    username_lower  TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'player',
    is_banned       INTEGER NOT NULL DEFAULT 0,
    ban_reason      TEXT,
    ban_expires_at  INTEGER,
    nick_changed_at INTEGER,
    last_login_at   INTEGER,
    last_ip         TEXT,
    login_count     INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tg_bind_tokens (
    token           TEXT PRIMARY KEY,
    purpose         TEXT NOT NULL,               -- 'register' | 'reset_pw'
    user_id         INTEGER,
    tg_id           INTEGER,
    tg_username     TEXT,
    tg_first_name   TEXT,
    status          TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'verified' | 'used'
    created_ip      TEXT,
    verified_at     INTEGER,
    expires_at      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash       TEXT NOT NULL UNIQUE,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hwid_hash        TEXT,
    os_name          TEXT,
    os_version       TEXT,
    arch             TEXT,
    gpu_backend      TEXT,                       -- 'vulkan' | 'opengl'
    launcher_version TEXT,
    launcher_hash    TEXT,
    ip               TEXT,
    created_at       INTEGER NOT NULL,
    last_seen_at     INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    revoked_at       INTEGER
);

CREATE TABLE IF NOT EXISTS nick_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    old_username    TEXT NOT NULL,
    new_username    TEXT NOT NULL,
    ip              TEXT,
    changed_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    hwid_hash       TEXT PRIMARY KEY,
    first_user_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,
    last_user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    os_name         TEXT,
    os_version      TEXT,
    cpu_info        TEXT,
    gpu_name        TEXT,
    gfx_backend     TEXT,
    ram_total_mb    INTEGER,
    trust_score     INTEGER NOT NULL DEFAULT 100,
    is_flagged      INTEGER NOT NULL DEFAULT 0,
    first_seen_at   INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_devices (
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hwid_hash       TEXT NOT NULL REFERENCES devices(hwid_hash) ON DELETE CASCADE,
    first_seen_at   INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    PRIMARY KEY (user_id, hwid_hash)
);

CREATE TABLE IF NOT EXISTS game_tickets (
    ticket_hash     TEXT PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id      INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    ip              TEXT NOT NULL,
    hwid_hash       TEXT,
    launcher_hash   TEXT,
    modpack_hash    TEXT,
    ram_mb          INTEGER,
    status          TEXT NOT NULL DEFAULT 'issued', -- 'issued' | 'used' | 'revoked'
    issued_at       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    used_at         INTEGER,
    mc_server_id    TEXT
);

CREATE TABLE IF NOT EXISTS security_challenges (
    challenge_id    TEXT PRIMARY KEY,
    nonce           TEXT NOT NULL,
    user_id         INTEGER REFERENCES users(id) ON DELETE CASCADE,
    session_id      INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    ip              TEXT,
    status          TEXT NOT NULL DEFAULT 'issued', -- 'issued' | 'verified' | 'failed'
    issued_at       INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS security_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT NOT NULL,               -- 'launcher' | 'launcher_plugin' | 'mc_mod'
    plugin_id       TEXT,
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    session_id      INTEGER REFERENCES sessions(id) ON DELETE SET NULL,
    hwid_hash       TEXT,
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info', -- 'info' | 'warn' | 'critical'
    passed          INTEGER NOT NULL DEFAULT 1,
    launcher_hash   TEXT,
    client_mod_hash TEXT,
    details_json    TEXT NOT NULL,
    ip              TEXT,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_type     TEXT NOT NULL,               -- 'user' | 'tg_id' | 'hwid' | 'ip'
    target_value    TEXT NOT NULL,
    reason          TEXT NOT NULL,
    issued_by       TEXT NOT NULL,
    expires_at      INTEGER,
    active          INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    category        TEXT NOT NULL,               -- 'auth' | 'profile' | 'security' | 'mc' | 'admin' | 'bot'
    action          TEXT NOT NULL,
    severity        TEXT NOT NULL DEFAULT 'info',
    user_id         INTEGER,
    tg_id           INTEGER,
    ip              TEXT,
    hwid_hash       TEXT,
    details_json    TEXT NOT NULL,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS request_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    status_code     INTEGER NOT NULL,
    latency_ms      REAL NOT NULL,
    ip              TEXT,
    user_id         INTEGER,
    user_agent      TEXT,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS telemetry_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER,
    hwid_hash       TEXT,
    source          TEXT NOT NULL,
    event_name      TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    ip              TEXT,
    created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS news (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    badge           TEXT NOT NULL,
    badge_type      TEXT NOT NULL DEFAULT 'default', -- 'default' | 'alert' | 'detroit'
    date_label      TEXT NOT NULL,
    title           TEXT NOT NULL,
    summary         TEXT NOT NULL,
    items_json      TEXT NOT NULL,
    is_published    INTEGER NOT NULL DEFAULT 1,
    author_tg_id    INTEGER,
    created_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_tg_tokens_tg_id ON tg_bind_tokens(tg_id);
CREATE INDEX IF NOT EXISTS idx_tg_tokens_expires ON tg_bind_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_nick_hist_user ON nick_history(user_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_nick_hist_old ON nick_history(old_username COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_tickets_user ON game_tickets(user_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS idx_tickets_expires ON game_tickets(expires_at);
CREATE INDEX IF NOT EXISTS idx_bans_lookup ON bans(target_type, target_value, active);
CREATE INDEX IF NOT EXISTS idx_sec_reports_user ON security_reports(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_cat_time ON audit_logs(category, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_req_logs_time ON request_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_event ON telemetry_events(event_name, created_at DESC);
"""


class Database:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.read_conn: aiosqlite.Connection | None = None
        self.write_conn: aiosqlite.Connection | None = None
        self.write_lock = asyncio.Lock()

    async def connect(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.write_conn = await aiosqlite.connect(self.db_path)
        self.read_conn = await aiosqlite.connect(self.db_path)

        for conn in (self.write_conn, self.read_conn):
            conn.row_factory = aiosqlite.Row
            await conn.execute("PRAGMA journal_mode=WAL;")
            await conn.execute("PRAGMA synchronous=NORMAL;")
            await conn.execute("PRAGMA foreign_keys=ON;")
            await conn.execute("PRAGMA busy_timeout=5000;")
            await conn.execute("PRAGMA temp_store=MEMORY;")
            await conn.execute("PRAGMA cache_size=-64000;")
            await conn.execute("PRAGMA mmap_size=268435456;")

        async with self.write_lock:
            await self.write_conn.executescript(SCHEMA_SQL)
            await self.write_conn.commit()

    async def close(self) -> None:
        if self.read_conn:
            await self.read_conn.close()
        if self.write_conn:
            await self.write_conn.close()

    async def fetch_one(self, query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        assert self.read_conn is not None
        async with self.read_conn.execute(query, params) as cur:
            row = await cur.fetchone()
            return dict(row) if row is not None else None

    async def fetch_all(self, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        assert self.read_conn is not None
        async with self.read_conn.execute(query, params) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]

    async def execute_write(self, query: str, params: tuple[Any, ...] = ()) -> int:
        assert self.write_conn is not None
        async with self.write_lock:
            cur = await self.write_conn.execute(query, params)
            await self.write_conn.commit()
            return cur.lastrowid or 0

    async def executemany_write(self, query: str, rows: list[tuple[Any, ...]]) -> None:
        if not rows:
            return
        assert self.write_conn is not None
        async with self.write_lock:
            await self.write_conn.executemany(query, rows)
            await self.write_conn.commit()
