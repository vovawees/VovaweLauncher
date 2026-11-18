from functools import lru_cache
from pathlib import Path
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Dead Mile '96 API"
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = 8000
    trust_proxy_headers: bool = True

    db_path: Path = Path("data/deadmile96.db")
    manifest_path: Path = Path("data/manifest.json")
    client_files_dir: Path = Path("data/client_files")
    files_base_url: str = "https://cdn.deadmile96.ru/files"

    internal_api_key: str = "dev_internal_key_change_me"

    telegram_bot_token: str = ""
    telegram_bot_username: str = "DeadMile96Bot"
    admin_tg_ids: list[int] = Field(default_factory=list)

    mc_host: str = "127.0.0.1"
    MC_PORT_FALLBACK: int = 25565
    mc_port: int = 25565
    mc_ping_interval_sec: float = 10.0
    mc_maintenance: bool = False

    launcher_latest_version: str = "0.1.0"
    launcher_min_version: str = "0.1.0"
    launcher_sha256_linux: str = ""
    launcher_sha256_win32: str = ""
    strict_launcher_hash: bool = False

    session_ttl_days: int = 30
    tg_token_ttl_sec: int = 600
    game_ticket_ttl_sec: int = 120
    challenge_ttl_sec: int = 60
    nick_cooldown_days: int = 7
    log_flush_interval_sec: float = 1.5


@lru_cache
def get_settings() -> Settings:
    return Settings()
