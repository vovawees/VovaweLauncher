import asyncio
import logging
import time
from contextlib import asynccontextmanager
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.staticfiles import StaticFiles

from app.api import auth, game, internal, profile, security
from app.api.deps import get_client_ip
from app.bot.handlers import build_bot_router
from app.config import get_settings
from app.core.responses import (
    ApiError,
    api_error_handler,
    http_error_handler,
    ok_response,
    validation_error_handler,
)
from app.core.security import InMemoryRateLimiter, now_ts
from app.db import Database
from app.services.cache import RuntimeCache, seed_initial_news
from app.services.logger import LogService
from app.services.mc_ping import mc_ping_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("deadmile96")


async def _cleanup_expired_loop(db: Database) -> None:
    while True:
        await asyncio.sleep(3600)
        ts = now_ts()
        try:
            await db.execute_write("DELETE FROM tg_bind_tokens WHERE expires_at < ?", (ts - 86400,))
            await db.execute_write("DELETE FROM game_tickets WHERE expires_at < ?", (ts - 86400,))
            await db.execute_write("DELETE FROM security_challenges WHERE expires_at < ?", (ts - 86400,))
            await db.execute_write("DELETE FROM sessions WHERE expires_at < ?", (ts - 86400,))
        except Exception as exc:
            log.exception("Cleanup error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    db = Database(settings.db_path)
    await db.connect()
    await seed_initial_news(db)

    cache = RuntimeCache()
    cache.load_manifest(settings.manifest_path)
    await cache.reload_news(db)

    logs = LogService(db, flush_interval=settings.log_flush_interval_sec)
    limiter = InMemoryRateLimiter()

    app.state.db = db
    app.state.cache = cache
    app.state.logs = logs
    app.state.limiter = limiter
    app.state.bot = None

    bg_tasks: list[asyncio.Task] = [
        asyncio.create_task(logs.run_loop()),
        asyncio.create_task(
            mc_ping_loop(
                cache,
                settings.mc_host,
                settings.mc_port,
                settings.mc_ping_interval_sec,
                settings.mc_maintenance,
            )
        ),
        asyncio.create_task(_cleanup_expired_loop(db)),
    ]

    dp: Dispatcher | None = None
    bot: Bot | None = None
    bot_task: asyncio.Task | None = None

    if settings.telegram_bot_token:
        bot = Bot(
            token=settings.telegram_bot_token,
            default=DefaultBotProperties(parse_mode=ParseMode.HTML),
        )
        dp = Dispatcher()
        dp.include_router(build_bot_router(db, cache, logs, settings))
        app.state.bot = bot
        bot_task = asyncio.create_task(
            dp.start_polling(bot, handle_signals=False, allowed_updates=dp.resolve_used_update_types())
        )
        log.info("Telegram bot polling started (@%s)", settings.telegram_bot_username)
    else:
        log.warning("TELEGRAM_BOT_TOKEN is empty — Telegram bot is disabled")

    try:
        yield
    finally:
        if dp and bot_task:
            await dp.stop_polling()
            bot_task.cancel()
            try:
                await bot_task
            except asyncio.CancelledError:
                pass
        if bot:
            await bot.session.close()

        for task in bg_tasks:
            task.cancel()
        await asyncio.gather(*bg_tasks, return_exceptions=True)

        await logs.flush()
        await db.close()
        log.info("Dead Mile '96 Server stopped cleanly")


app = FastAPI(
    title="Dead Mile '96 API",
    version="0.1.0",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_exception_handler(ApiError, api_error_handler)
app.add_exception_handler(StarletteHTTPException, http_error_handler)
app.add_exception_handler(RequestValidationError, validation_error_handler)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    latency_ms = (time.perf_counter() - start) * 1000.0

    # Не засоряем таблицу частыми polling-пингами если не нужно — логируем всё, кроме /health
    if request.url.path != "/health":
        logs: LogService = request.app.state.logs
        settings = get_settings()
        ip = get_client_ip(request, settings)
        user_id = getattr(request.state, "user_id", None)
        ua = request.headers.get("user-agent", "")[:128]
        await logs.request(
            request.method,
            request.url.path,
            response.status_code,
            latency_ms,
            ip,
            user_id,
            ua,
        )
    return response


app.include_router(auth.router)
app.include_router(profile.router)
app.include_router(game.router)
app.include_router(security.router)
app.include_router(internal.router)

# Раздача клиентских файлов (моды, конфиги, шейдеры)
_client_dir = get_settings().client_files_dir
_client_dir.mkdir(parents=True, exist_ok=True)
app.mount("/files", StaticFiles(directory=str(_client_dir)), name="files")


@app.get("/health")
async def health():
    return ok_response({"status": "alive"})
