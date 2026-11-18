import asyncio
import json
import logging
from typing import Any
from app.core.security import now_ts
from app.db import Database

log = logging.getLogger("deadmile96")


class LogService:
    """Асинхронный буферизованный логгер: сбрасывает пачки в SQLite без тормозов для API."""

    def __init__(self, db: Database, flush_interval: float = 1.5) -> None:
        self.db = db
        self.flush_interval = flush_interval
        self._audit_buf: list[tuple[Any, ...]] = []
        self._req_buf: list[tuple[Any, ...]] = []
        self._tel_buf: list[tuple[Any, ...]] = []
        self._lock = asyncio.Lock()

    async def audit(
        self,
        category: str,
        action: str,
        *,
        severity: str = "info",
        user_id: int | None = None,
        tg_id: int | None = None,
        ip: str | None = None,
        hwid_hash: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        row = (
            category,
            action,
            severity,
            user_id,
            tg_id,
            ip,
            hwid_hash,
            json.dumps(details or {}, ensure_ascii=False),
            now_ts(),
        )
        async with self._lock:
            self._audit_buf.append(row)
            should_flush = len(self._audit_buf) >= 100
        if should_flush:
            await self.flush()

    async def request(
        self,
        method: str,
        path: str,
        status_code: int,
        latency_ms: float,
        ip: str | None,
        user_id: int | None,
        user_agent: str | None,
    ) -> None:
        row = (method, path, status_code, round(latency_ms, 2), ip, user_id, user_agent, now_ts())
        async with self._lock:
            self._req_buf.append(row)
            should_flush = len(self._req_buf) >= 200
        if should_flush:
            await self.flush()

    async def telemetry(
        self,
        source: str,
        event_name: str,
        payload: dict[str, Any],
        *,
        user_id: int | None = None,
        hwid_hash: str | None = None,
        ip: str | None = None,
    ) -> None:
        row = (
            user_id,
            hwid_hash,
            source,
            event_name,
            json.dumps(payload, ensure_ascii=False),
            ip,
            now_ts(),
        )
        async with self._lock:
            self._tel_buf.append(row)

    async def flush(self) -> None:
        async with self._lock:
            audits, self._audit_buf = self._audit_buf, []
            reqs, self._req_buf = self._req_buf, []
            tels, self._tel_buf = self._tel_buf, []

        if audits:
            await self.db.executemany_write(
                """
                INSERT INTO audit_logs
                (category, action, severity, user_id, tg_id, ip, hwid_hash, details_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                audits,
            )
        if reqs:
            await self.db.executemany_write(
                """
                INSERT INTO request_logs
                (method, path, status_code, latency_ms, ip, user_id, user_agent, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                reqs,
            )
        if tels:
            await self.db.executemany_write(
                """
                INSERT INTO telemetry_events
                (user_id, hwid_hash, source, event_name, payload_json, ip, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                tels,
            )

    async def run_loop(self) -> None:
        while True:
            await asyncio.sleep(self.flush_interval)
            try:
                await self.flush()
            except Exception as exc:
                log.exception("Failed to flush buffered logs: %s", exc)
