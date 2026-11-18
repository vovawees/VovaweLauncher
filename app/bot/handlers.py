import json
from aiogram import Router
from aiogram.filters import Command, CommandObject, CommandStart
from aiogram.types import Message
from app.config import Settings
from app.core.security import now_ts
from app.db import Database
from app.services.cache import RuntimeCache
from app.services.logger import LogService


def build_bot_router(
    db: Database,
    cache: RuntimeCache,
    logs: LogService,
    settings: Settings,
) -> Router:
    router = Router()

    def is_admin(tg_id: int) -> bool:
        return tg_id in settings.admin_tg_ids

    @router.message(CommandStart())
    async def cmd_start(message: Message, command: CommandObject) -> None:
        if not message.from_user:
            return
        tg_id = message.from_user.id
        tg_user = message.from_user.username
        tg_name = message.from_user.first_name
        token = (command.args or "").strip()
        ts = now_ts()

        if not token:
            user = await db.fetch_one("SELECT username, account_uuid FROM users WHERE tg_id = ?", (tg_id,))
            if user:
                await message.answer(
                    f"🎙 <b>Dead Mile '96</b>\n\n"
                    f"Ваш аккаунт привязан:\n"
                    f"• Ник: <code>{user['username']}</code>\n"
                    f"• UUID: <code>{user['account_uuid']}</code>\n\n"
                    f"Команды: /profile, /status, /reset"
                )
            else:
                await message.answer(
                    "🎙 <b>Dead Mile '96</b>\n\n"
                    "Чтобы зарегистрироваться, откройте лаунчер Dead Mile '96 и нажмите "
                    "<b>«Регистрация через Telegram»</b> — он автоматически откроет нужную ссылку."
                )
            return

        bind = await db.fetch_one("SELECT * FROM tg_bind_tokens WHERE token = ?", (token,))
        if not bind or bind["status"] != "pending" or bind["expires_at"] <= ts:
            await message.answer("❌ Ссылка устарела или уже использована. Запросите новую в лаунчере.")
            return

        existing = await db.fetch_one("SELECT id, username FROM users WHERE tg_id = ?", (tg_id,))

        if bind["purpose"] == "register":
            if existing:
                await message.answer(
                    f"⚠️ Этот Telegram уже привязан к аккаунту <code>{existing['username']}</code>.\n"
                    f"Если забыли пароль — воспользуйтесь сбросом пароля в лаунчере."
                )
                return

            await db.execute_write(
                """
                UPDATE tg_bind_tokens
                SET tg_id = ?, tg_username = ?, tg_first_name = ?, status = 'verified', verified_at = ?
                WHERE token = ?
                """,
                (tg_id, tg_user, tg_name, ts, token),
            )
            await logs.audit("bot", "tg_register_verified", tg_id=tg_id, details={"tg_username": tg_user})
            await message.answer(
                "✅ <b>Telegram подтверждён!</b>\n\n"
                "Вернитесь в лаунчер <b>Dead Mile '96</b>, придумайте уникальный никнейм и пароль."
            )

        elif bind["purpose"] == "reset_pw":
            if not existing:
                await message.answer("❌ К этому Telegram ещё не привязан ни один игровой аккаунт.")
                return

            await db.execute_write(
                """
                UPDATE tg_bind_tokens
                SET user_id = ?, tg_id = ?, tg_username = ?, tg_first_name = ?, status = 'verified', verified_at = ?
                WHERE token = ?
                """,
                (existing["id"], tg_id, tg_user, tg_name, ts, token),
            )
            await logs.audit("bot", "tg_reset_verified", user_id=existing["id"], tg_id=tg_id)
            await message.answer(
                f"🔑 Сброс пароля для <code>{existing['username']}</code> подтверждён.\n"
                f"Вернитесь в лаунчер и введите новый пароль."
            )

    @router.message(Command("profile"))
    async def cmd_profile(message: Message) -> None:
        if not message.from_user:
            return
        u = await db.fetch_one("SELECT * FROM users WHERE tg_id = ?", (message.from_user.id,))
        if not u:
            await message.answer("Аккаунт ещё не зарегистрирован через лаунчер.")
            return
        ts = now_ts()
        cd_sec = settings.nick_cooldown_days * 86400
        rem = max(0, (u["nick_changed_at"] + cd_sec) - ts) if u["nick_changed_at"] else 0
        cd_text = "Доступна сейчас" if rem == 0 else f"Через {rem // 3600} ч."
        await message.answer(
            f"👤 <b>Профиль выжившего</b>\n"
            f"• Ник: <code>{u['username']}</code>\n"
            f"• Роль: <code>{u['role']}</code>\n"
            f"• Смена ника: <b>{cd_text}</b>\n"
            f"• Входов в лаунчер: <b>{u['login_count']}</b>"
        )

    @router.message(Command("status"))
    async def cmd_status(message: Message) -> None:
        st = cache.mc_status
        state_icon = "🟢 Онлайн" if st.online else "🔴 Офлайн"
        await message.answer(
            f"📻 <b>Сводка сервера Dead Mile '96</b>\n"
            f"• Статус: {state_icon}\n"
            f"• Выживших: <b>{st.players_online} / {st.players_max}</b>\n"
            f"• Пинг (локальный): <code>{st.ping_ms} мс</code>"
        )

    @router.message(Command("stats"))
    async def cmd_stats(message: Message) -> None:
        if not message.from_user or not is_admin(message.from_user.id):
            return
        ts = now_ts()
        users_cnt = (await db.fetch_one("SELECT COUNT(*) AS c FROM users"))["c"]
        active_24h = (await db.fetch_one("SELECT COUNT(*) AS c FROM users WHERE last_login_at > ?", (ts - 86400,)))["c"]
        sec_warns = (await db.fetch_one("SELECT COUNT(*) AS c FROM security_reports WHERE passed = 0"))["c"]
        await message.answer(
            f"📊 <b>Статистика VPS</b>\n"
            f"• Всего игроков: <b>{users_cnt}</b>\n"
            f"• Заходили за 24ч: <b>{active_24h}</b>\n"
            f"• Срабатываний анти-тампера: <b>{sec_warns}</b>"
        )

    @router.message(Command("addnews"))
    async def cmd_addnews(message: Message) -> None:
        if not message.from_user or not is_admin(message.from_user.id):
            return
        # Формат: /addnews ПАТЧ 0.9.7|default|18.11.96|Заголовок|Краткое описание|Пункт 1;Пункт 2
        raw = (message.text or "").replace("/addnews", "", 1).strip()
        parts = [p.strip() for p in raw.split("|")]
        if len(parts) < 6:
            await message.answer(
                "Формат:\n<code>/addnews БЕЙДЖ|default/alert/detroit|18.11.96|Заголовок|Описание|Пункт1;Пункт2</code>"
            )
            return

        badge, badge_type, date_label, title, summary, items_raw = parts[:6]
        items = [x.strip() for x in items_raw.split(";") if x.strip()]
        await db.execute_write(
            """
            INSERT INTO news (badge, badge_type, date_label, title, summary, items_json, is_published, author_tg_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
            """,
            (badge, badge_type, date_label, title, summary, json.dumps(items, ensure_ascii=False), message.from_user.id, now_ts()),
        )
        await cache.reload_news(db)
        await logs.audit("admin", "news_added", tg_id=message.from_user.id, details={"title": title})
        await message.answer(f"📰 Новость «<b>{title}</b>» опубликована в лаунчере!")

    @router.message(Command("userinfo"))
    async def cmd_userinfo(message: Message) -> None:
        if not message.from_user or not is_admin(message.from_user.id):
            return
        nick = (message.text or "").replace("/userinfo", "", 1).strip()
        if not nick:
            await message.answer("Использование: <code>/userinfo Ник</code>")
            return
        u = await db.fetch_one("SELECT * FROM users WHERE username_lower = ?", (nick.lower(),))
        if not u:
            await message.answer("Игрок не найден.")
            return
        hwids = await db.fetch_all("SELECT hwid_hash FROM user_devices WHERE user_id = ?", (u["id"],))
        hwid_list = ", ".join(h["hwid_hash"][:10] + "..." for h in hwids) or "-"
        await message.answer(
            f"🗂 <b>Досье: {u['username']}</b>\n"
            f"• ID / UUID: <code>{u['id']}</code> / <code>{u['account_uuid']}</code>\n"
            f"• TG: <code>{u['tg_id']}</code> (@{u['tg_username'] or '-'})\n"
            f"• Последний IP: <code>{u['last_ip'] or '-'}</code>\n"
            f"• HWID: <code>{hwid_list}</code>\n"
            f"• Бан: <b>{'ДА (' + (u['ban_reason'] or '') + ')' if u['is_banned'] else 'Нет'}</b>"
        )

    return router
