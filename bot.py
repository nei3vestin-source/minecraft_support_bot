"""
AuthGuard Discord Bot
Принимает HTTP-запросы от Minecraft-плагина и отправляет
embed-сообщения с одноразовыми паролями в Discord-канал.

Запуск:
    pip install -r requirements.txt
    python bot.py
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from aiohttp import web
import discord
from discord.ext import commands
from discord import app_commands

# ======================== ЛОГИРОВАНИЕ ========================
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("AuthGuardBot")

# ======================== ЗАГРУЗКА КОНФИГА ========================
CONFIG_PATH = Path(__file__).parent / "config.json"

if not CONFIG_PATH.exists():
    log.error(f"Файл {CONFIG_PATH} не найден! Создай его по примеру.")
    exit(1)

with open(CONFIG_PATH, "r", encoding="utf-8") as f:
    CONFIG = json.load(f)

BOT_TOKEN: str = CONFIG["bot_token"]
LOG_CHANNEL_ID: int = int(CONFIG["log_channel_id"])
API_PORT: int = int(CONFIG["api_port"])
API_SECRET: str = CONFIG["api_secret"]
ALLOWED_IPS: set[str] = set(CONFIG.get("allowed_ips", []))

# ======================== ХРАНИЛИЩЕ СЕССИЙ ========================
# Хранит активные сессии авторизации в памяти.
# Ключ — ник в нижнем регистре, значение — dict с данными.
ACTIVE_SESSIONS: dict[str, dict] = {}

# ======================== НАСТРОЙКА БОТА ========================
intents = discord.Intents.default()
intents.message_content = False  # Мы не читаем сообщения в чате

bot = commands.Bot(command_prefix="!", intents=intents)


# ======================== СОБЫТИЯ БОТА ========================
@bot.event
async def on_ready():
    """Вызывается когда бот успешно подключился к Discord."""
    log.info(f"Бот запущен как {bot.user} (ID: {bot.user.id})")
    log.info(f"Серверов: {len(bot.guilds)}")
    log.info(f"Канал для логов: {LOG_CHANNEL_ID}")

    # Синхронизация slash-команд
    try:
        synced = await bot.tree.sync()
        log.info(f"Синхронизировано slash-команд: {len(synced)}")
    except Exception as e:
        log.error(f"Ошибка синхронизации команд: {e}")


@bot.event
async def on_error(event: str, *args, **kwargs):
    """Глобальный обработчик ошибок."""
    log.exception(f"Ошибка в событии {event}")


# ======================== HTTP-СЕРВЕР (aiohttp) ========================
async def handle_auth_request(request: web.Request) -> web.Response:
    """
    Обрабатывает POST /auth-request от Minecraft-плагина.

    Ожидаемый JSON:
    {
        "nickname": "Steve",
        "uuid": "xxxx-xxxx-xxxx",
        "ip": "192.168.1.1",
        "password": "482917",
        "timestamp": "2025-01-15 14:32:07",
        "max_attempts": 3
    }

    Заголовок: Authorization: Bearer <api_secret>
    """

    # --- 1. Проверка IP белого списка ---
    peer_ip = request.remote
    if ALLOWED_IPS and peer_ip not in ALLOWED_IPS:
        log.warning(f"Отклонён запрос с недоверенного IP: {peer_ip}")
        return web.json_response(
            {"error": "forbidden", "reason": "IP not in whitelist"},
            status=403,
        )

    # --- 2. Проверка токена авторизации ---
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        log.warning(f"Запрос без Bearer-токена от {peer_ip}")
        return web.json_response(
            {"error": "unauthorized", "reason": "missing Bearer token"},
            status=401,
        )

    token = auth_header[len("Bearer "):].strip()
    if token != API_SECRET:
        log.warning(f"Неверный API-токен от {peer_ip}")
        return web.json_response(
            {"error": "forbidden", "reason": "invalid token"},
            status=403,
        )

    # --- 3. Парсинг JSON-тела ---
    try:
        data = await request.json()
    except Exception as e:
        log.error(f"Ошибка парсинга JSON: {e}")
        return web.json_response(
            {"error": "bad json", "reason": str(e)},
            status=400,
        )

    # --- 4. Проверка обязательных полей ---
    required_fields = ["nickname", "uuid", "ip", "password", "timestamp", "max_attempts"]
    for field in required_fields:
        if field not in data:
            log.warning(f"Отсутствует поле '{field}' в запросе от {peer_ip}")
            return web.json_response(
                {"error": f"missing field: {field}"},
                status=400,
            )

    nickname = str(data["nickname"])
    uuid = str(data["uuid"])
    player_ip = str(data["ip"])
    password = str(data["password"])
    timestamp = str(data["timestamp"])
    max_attempts = int(data["max_attempts"])

    # --- 5. Сохранение сессии в памяти ---
    ACTIVE_SESSIONS[nickname.lower()] = {
        "nickname": nickname,
        "uuid": uuid,
        "ip": player_ip,
        "password": password,
        "timestamp": timestamp,
        "max_attempts": max_attempts,
        "received_at": datetime.now(timezone.utc).isoformat(),
    }

    # --- 6. Формирование и отправка Embed в Discord ---
    channel = bot.get_channel(LOG_CHANNEL_ID)
    if channel is None:
        # Пытаемся получить канал через fetch если get_channel не нашёл
        try:
            channel = await bot.fetch_channel(LOG_CHANNEL_ID)
        except Exception as e:
            log.error(f"Канал {LOG_CHANNEL_ID} не найден: {e}")
            return web.json_response(
                {"error": "channel not found"},
                status=500,
            )

    embed = discord.Embed(
        title="🔐 Новая попытка входа",
        description=f"Игрок **{nickname}** пытается войти на сервер.",
        color=0xFF8C00,  # Оранжевый
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="👤 Ник", value=f"`{nickname}`", inline=True)
    embed.add_field(name="🆔 UUID", value=f"`{uuid}`", inline=True)
    embed.add_field(name="🌐 IP", value=f"`{player_ip}`", inline=True)
    embed.add_field(name="🔑 Одноразовый пароль", value=f"**`{password}`**", inline=True)
    embed.add_field(name="🕐 Время", value=f"`{timestamp}`", inline=True)
    embed.add_field(name="🔄 Попыток", value=f"`{max_attempts}`", inline=True)
    embed.set_footer(text="AuthGuard System")

    try:
        await channel.send(embed=embed)
        log.info(f"✅ Embed отправлен для {nickname} ({player_ip})")
    except discord.Forbidden:
        log.error(f"Нет прав на отправку сообщений в канал {LOG_CHANNEL_ID}")
        return web.json_response(
            {"error": "discord forbidden"},
            status=500,
        )
    except Exception as e:
        log.error(f"Не удалось отправить embed: {e}")
        return web.json_response(
            {"error": "discord send failed", "reason": str(e)},
            status=500,
        )

    return web.json_response({"status": "ok", "message": "auth request received"})


async def handle_health(request: web.Request) -> web.Response:
    """GET /health — проверка работоспособности бота."""
    return web.json_response({
        "status": "alive",
        "active_sessions": len(ACTIVE_SESSIONS),
        "guilds": len(bot.guilds),
        "bot_user": str(bot.user) if bot.user else None,
    })


async def start_http_server():
    """Запускает HTTP-сервер aiohttp параллельно с Discord-ботом."""
    app = web.Application()
    app.router.add_post("/auth-request", handle_auth_request)
    app.router.add_get("/health", handle_health)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="0.0.0.0", port=API_PORT)
    await site.start()
    log.info(f"🌐 HTTP API сервер запущен на 0.0.0.0:{API_PORT}")
    log.info(f"   POST http://0.0.0.0:{API_PORT}/auth-request")
    log.info(f"   GET  http://0.0.0.0:{API_PORT}/health")


# ======================== SLASH-КОМАНДЫ ========================
@bot.tree.command(
    name="authstatus",
    description="Показать текущую сессию авторизации игрока",
)
@app_commands.describe(nickname="Ник игрока в Minecraft")
async def cmd_authstatus(interaction: discord.Interaction, nickname: str):
    """Показывает активную сессию авторизации для указанного игрока."""
    session = ACTIVE_SESSIONS.get(nickname.lower())

    if session is None:
        await interaction.response.send_message(
            f"❌ Нет активной сессии для `{nickname}`.",
            ephemeral=True,
        )
        return

    embed = discord.Embed(
        title=f"📋 Сессия: {session['nickname']}",
        color=0x3498DB,
        timestamp=datetime.now(timezone.utc),
    )
    embed.add_field(name="🆔 UUID", value=f"`{session['uuid']}`", inline=False)
    embed.add_field(name="🌐 IP", value=f"`{session['ip']}`", inline=True)
    embed.add_field(name="🔑 Пароль", value=f"`{session['password']}`", inline=True)
    embed.add_field(name="🕐 Время запроса", value=f"`{session['timestamp']}`", inline=False)
    embed.add_field(name="🔄 Попыток", value=f"`{session['max_attempts']}`", inline=True)
    embed.add_field(
        name="📥 Получено ботом",
        value=f"`{session.get('received_at', 'N/A')}`",
        inline=True,
    )
    embed.set_footer(text="AuthGuard System")

    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(
    name="authunban",
    description="Удалить сессию и подсказать команду разбана",
)
@app_commands.describe(nickname="Ник игрока в Minecraft")
async def cmd_authunban(interaction: discord.Interaction, nickname: str):
    """Удаляет сессию из памяти бота и подсказывает команду разбана."""
    removed = ACTIVE_SESSIONS.pop(nickname.lower(), None)

    if removed:
        await interaction.response.send_message(
            f"✅ Сессия для `{nickname}` удалена из памяти бота.\n\n"
            f"⚠️ **Для полного разбана** выполните на Minecraft-сервере:\n"
            f"`/pardon {nickname}`",
            ephemeral=True,
        )
    else:
        await interaction.response.send_message(
            f"ℹ️ Активной сессии для `{nickname}` не найдено.\n\n"
            f"⚠️ **Для разбана** выполните на Minecraft-сервере:\n"
            f"`/pardon {nickname}`",
            ephemeral=True,
        )


@bot.tree.command(
    name="authlist",
    description="Показать все активные сессии авторизации",
)
async def cmd_authlist(interaction: discord.Interaction):
    """Показывает список всех активных сессий."""
    if not ACTIVE_SESSIONS:
        await interaction.response.send_message(
            "✅ Нет активных сессий авторизации.",
            ephemeral=True,
        )
        return

    lines = []
    for nick, sess in ACTIVE_SESSIONS.items():
        lines.append(
            f"• **{sess['nickname']}** — IP: `{sess['ip']}` — "
            f"Пароль: `{sess['password']}` — Попыток: `{sess['max_attempts']}`"
        )

    text = "\n".join(lines[:20])  # Ограничение на 20 записей
    if len(ACTIVE_SESSIONS) > 20:
        text += f"\n\n... и ещё {len(ACTIVE_SESSIONS) - 20} сессий"

    embed = discord.Embed(
        title=f"📋 Активные сессии ({len(ACTIVE_SESSIONS)})",
        description=text,
        color=0xF39C12,
        timestamp=datetime.now(timezone.utc),
    )
    embed.set_footer(text="AuthGuard System")

    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.command(
    name="authclear",
    description="Очистить все активные сессии",
)
async def cmd_authclear(interaction: discord.Interaction):
    """Очищает все сессии из памяти бота."""
    count = len(ACTIVE_SESSIONS)
    ACTIVE_SESSIONS.clear()
    await interaction.response.send_message(
        f"🗑️ Очищено {count} сессий.",
        ephemeral=True,
    )


# ======================== ТОЧКА ВХОДА ========================
async def main():
    """Главная функция: запускает HTTP-сервер и Discord-бота."""
    async with bot:
        await start_http_server()
        log.info("Подключение к Discord Gateway...")
        await bot.start(BOT_TOKEN)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Остановка по Ctrl+C")
    except discord.LoginFailure:
        log.error("❌ Неверный токен бота! Проверь config.json → bot_token")
    except Exception as e:
        log.exception(f"Критическая ошибка: {e}")
