import asyncio
import hashlib
import hmac
import re
import secrets
import time
import uuid
from collections import defaultdict, deque
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

NICK_REGEX = re.compile(r"^[A-Za-z0-9_]{3,16}$")

_ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=2,
)


def now_ts() -> int:
    return int(time.time())


def sha256_hex(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(raw).hexdigest()


def new_token(prefix: str = "", nbytes: int = 24) -> str:
    raw = secrets.token_urlsafe(nbytes)
    return f"{prefix}{raw}" if prefix else raw


def new_account_uuid() -> str:
    return str(uuid.uuid4())


def offline_mc_uuid(username: str) -> str:
    # Стандартный алгоритм OfflinePlayer UUID из Minecraft
    digest = bytearray(hashlib.md5(f"OfflinePlayer:{username}".encode("utf-8")).digest())
    digest[6] = (digest[6] & 0x0F) | 0x30
    digest[8] = (digest[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(digest)))


def is_valid_nick(username: str) -> bool:
    return bool(NICK_REGEX.fullmatch(username))


def hmac_sign(secret: str, payload: str) -> str:
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


async def hash_password(password: str) -> str:
    return await asyncio.to_thread(_ph.hash, password)


async def verify_password(password_hash: str, password: str) -> bool:
    def _verify() -> bool:
        try:
            return _ph.verify(password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    return await asyncio.to_thread(_verify)


class InMemoryRateLimiter:
    """Быстрый sliding-window rate limiter в RAM для защиты API от брутфорса и флуда."""

    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._last_gc = time.monotonic()

    def allow(self, key: str, limit: int, window_sec: float) -> tuple[bool, int]:
        now = time.monotonic()
        q = self._buckets[key]
        cutoff = now - window_sec
        while q and q[0] < cutoff:
            q.popleft()

        if len(q) >= limit:
            retry_after = max(1, int(window_sec - (now - q[0])))
            return False, retry_after

        q.append(now)

        if now - self._last_gc > 300:
            self._gc(now, max_window=600.0)
            self._last_gc = now

        return True, 0

    def _gc(self, now: float, max_window: float) -> None:
        stale = [k for k, q in self._buckets.items() if not q or (now - q[-1]) > max_window]
        for k in stale:
            del self._buckets[k]
