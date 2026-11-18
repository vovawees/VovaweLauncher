import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from app.core.security import now_ts, sha256_hex
from app.db import Database


@dataclass
class McStatus:
    online: bool = False
    players_online: int = 0
    players_max: int = 200
    motd: str = "Dead Mile '96"
    version: str = "1.20.1"
    ping_ms: int = 0
    maintenance: bool = False
    updated_at: int = 0


@dataclass
class RuntimeCache:
    manifest: dict[str, Any] = field(default_factory=lambda: {
        "client_version": "0.9.6",
        "mc_version": "1.20.1",
        "forge_version": "47.3.0",
        "manifest_hash": "empty",
        "files": [],
    })
    manifest_sha256: str = "empty"
    news: list[dict[str, Any]] = field(default_factory=list)
    mc_status: McStatus = field(default_factory=McStatus)

    def load_manifest(self, path: Path) -> None:
        if not path.exists():
            raw = json.dumps(self.manifest).encode("utf-8")
            self.manifest_sha256 = sha256_hex(raw)
            return
        raw_bytes = path.read_bytes()
        data = json.loads(raw_bytes.decode("utf-8"))
        self.manifest = data
        self.manifest_sha256 = sha256_hex(raw_bytes)

    async def reload_news(self, db: Database) -> None:
        rows = await db.fetch_all(
            """
            SELECT id, badge, badge_type, date_label, title, summary, items_json, created_at
            FROM news
            WHERE is_published = 1
            ORDER BY id DESC
            LIMIT 12
            """
        )
        parsed = []
        for r in rows:
            parsed.append({
                "id": r["id"],
                "badge": r["badge"],
                "badge_type": r["badge_type"],
                "date_label": r["date_label"],
                "title": r["title"],
                "summary": r["summary"],
                "items": json.loads(r["items_json"]),
                "created_at": r["created_at"],
            })
        self.news = parsed


async def seed_initial_news(db: Database) -> None:
    existing = await db.fetch_one("SELECT COUNT(*) AS cnt FROM news")
    if existing and existing["cnt"] > 0:
        return

    ts = now_ts()
    initial = [
        (
            "ПАТЧ 0.9.6",
            "default",
            "17.11.96",
            "Реворк баллистики MAC-10 и клин магазинов",
            "Грязные стволы требуют чистки набором из автомагазина, а дробь выбивает двери.",
            json.dumps([
                "Грязные пистолеты-пулемёты (MAC-10, TEC-9) начинают клинить при износе ниже 35%.",
                "Дробовик Mossberg 500 выбивает деревянные двери и отбрасывает бегущих заражённых.",
                "Набор для чистки ствола теперь спавнится в багажниках полицейских Crown Victoria.",
            ], ensure_ascii=False),
            1,
            None,
            ts,
        ),
        (
            "ТРЕВОГА 911",
            "alert",
            "15.11.96",
            "Орды на перекрёстке Crenshaw & Slauson",
            "Автосигнализации патрульных Crown Vic срывают заражённых со всего квартала.",
            json.dumps([
                "Автосигнализации разбитых машин собирают орды в радиусе 180 блоков.",
                "Отключайте аккумулятор перед обыском багажника или работайте глушителем.",
            ], ensure_ascii=False),
            1,
            None,
            ts - 172800,
        ),
        (
            "8 MILE",
            "detroit",
            "12.11.96",
            "Ноябрьские заморозки и запчасти Impala '64",
            "Костры в стальных бочках согревают ночью, но выдают позицию дымом над промзоной.",
            json.dumps([
                "В заморозки согревайтесь у бочек с огнём (дым виден с крыш соседних зданий).",
                "В гаражах у железной дороги увеличен спавн свечей зажигания и дисков для Impala '64.",
            ], ensure_ascii=False),
            1,
            None,
            ts - 432000,
        ),
    ]
    await db.executemany_write(
        """
        INSERT INTO news (badge, badge_type, date_label, title, summary, items_json, is_published, author_tg_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        initial,
    )
