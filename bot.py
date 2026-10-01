"""
Telegram-бот для загрузки файлов на Яндекс Диск.

Логика:
  /start -> две кнопки:
    1) «Подключить диск»  — человек становится админом своего Диска;
    2) «Загрузить файл»   — доступно, если человека добавил какой-то админ.
  Админ управляет токеном, корневой папкой, названием диска и списком пользователей.
  Человек может быть в списках у нескольких админов — тогда бот спрашивает, на какой диск грузить.
  В группах бот сначала спрашивает «Загрузить файл?», в личке этот вопрос пропускается.
"""
import asyncio
import json
import logging
import os
import posixpath
import tempfile
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlencode

import aiohttp
import yadisk
from aiogram import BaseMiddleware, Bot, Dispatcher, F, Router
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError
from aiogram.filters import Command, CommandObject
from aiogram.types import BotCommand, BotCommandScopeChat, CallbackQuery, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------- Конфигурация

BOT_TOKEN = os.environ["BOT_TOKEN"]
CLIENT_ID = os.getenv("YANDEX_CLIENT_ID", "").strip()
CLIENT_SECRET = os.getenv("YANDEX_CLIENT_SECRET", "").strip()
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "10"))

DATA_FILE = Path(__file__).parent / "data.json"
MAX_FOLDER_BUTTONS = 90  # лимит Telegram: 100 кнопок на клавиатуру
MAX_DISKNAME_LEN = 30
SESSION_TTL = 3600  # сколько секунд живут неотвеченные запросы выбора папки/диска

_key = os.getenv("ENCRYPTION_KEY", "").strip()
if not _key:
    raise SystemExit(
        "В .env не задан ENCRYPTION_KEY. Сгенерируй ключ командой:\n"
        '  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"'
    )
try:
    fernet = Fernet(_key.encode())
except ValueError:
    raise SystemExit("ENCRYPTION_KEY в .env некорректный. Сгенерируй новый (команда выше).")

NOT_IN_LIST = "Вас нет в списке пользователей. Обратитесь к админу."

USER_COMMANDS = [
    BotCommand(command="start", description="Главное меню"),
    BotCommand(command="help", description="Помощь"),
]
ADMIN_COMMANDS = USER_COMMANDS + [
    BotCommand(command="settings", description="Настройки диска"),
    BotCommand(command="code", description="Код входа через Яндекс"),
    BotCommand(command="settoken", description="Вставить токен вручную"),
    BotCommand(command="setroot", description="Корневая папка"),
    BotCommand(command="diskname", description="Название диска"),
    BotCommand(command="adduser", description="Добавить пользователя"),
    BotCommand(command="removeuser", description="Убрать пользователя"),
    BotCommand(command="users", description="Список пользователей"),
    BotCommand(command="logout", description="Отключить диск"),
]


# ---------------------------------------------------------------- Хранилище

class Store:
    """data.json: админы (с зашифрованными токенами), их пользователи, известные имена."""

    def __init__(self):
        self.data: dict = {"admins": {}, "known": {}}
        if DATA_FILE.exists():
            try:
                loaded = json.loads(DATA_FILE.read_text(encoding="utf-8"))
                self.data["admins"] = loaded.get("admins", {})
                self.data["known"] = loaded.get("known", {})
            except Exception:
                logging.exception("data.json повреждён, сохраняю копию .corrupt и начинаю с нуля")
                DATA_FILE.replace(DATA_FILE.with_suffix(".corrupt"))

    def save(self):
        tmp = DATA_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(DATA_FILE)

    # --- админы
    @property
    def admins(self) -> dict:
        return self.data["admins"]

    def is_admin(self, uid: int) -> bool:
        return str(uid) in self.admins

    def admin(self, uid: int) -> dict | None:
        return self.admins.get(str(uid))

    def is_relevant(self, uid: int) -> bool:
        """Админ или человек из чьего-то списка (только таких запоминаем при общении в группах)."""
        return self.is_admin(uid) or any(uid in a["users"] for a in self.admins.values())

    def create_admin(self, uid: int):
        if not self.is_admin(uid):
            self.admins[str(uid)] = {"token": None, "base_path": "/", "name": None, "users": []}
            self.save()

    # --- токен (хранится зашифрованным)
    def has_token(self, uid: int) -> bool:
        a = self.admin(uid)
        return bool(a and a.get("token"))

    def token(self, uid: int) -> str | None:
        a = self.admin(uid)
        if not a or not a.get("token"):
            return None
        try:
            return fernet.decrypt(a["token"].encode()).decode()
        except InvalidToken:
            logging.error("Не удалось расшифровать токен админа %s (изменился ENCRYPTION_KEY?)", uid)
            return None

    def set_token(self, uid: int, token: str):
        self.admin(uid)["token"] = fernet.encrypt(token.encode()).decode()
        self.save()

    def clear_token(self, uid: int):
        self.admin(uid)["token"] = None
        self.save()

    # --- имена
    def remember(self, user):
        info = {"name": user.full_name, "username": user.username}
        if self.data["known"].get(str(user.id)) != info:
            self.data["known"][str(user.id)] = info
            self.save()

    def display(self, uid: int) -> str:
        info = self.data["known"].get(str(uid))
        if not info:
            return str(uid)
        return f"{info['name']} (@{info['username']})" if info.get("username") else info["name"]

    def label(self, admin_id: int) -> str:
        """Название диска: заданное админом или его имя в Telegram."""
        a = self.admin(admin_id)
        if a and a.get("name"):
            return a["name"]
        info = self.data["known"].get(str(admin_id))
        return info["name"] if info else str(admin_id)

    def name_taken(self, name: str, exclude: int) -> bool:
        n = name.casefold()
        return any(self.label(int(u)).casefold() == n for u in self.admins if int(u) != exclude)

    # --- доступ
    def disks_for(self, user_id: int) -> list[int]:
        """ID админов, на чьи диски пользователь может грузить (свой диск — первым)."""
        result = [
            int(aid)
            for aid, a in self.admins.items()
            if a.get("token") and (int(aid) == user_id or user_id in a["users"])
        ]
        result.sort(key=lambda x: x != user_id)
        return result


store = Store()
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Команды управления и всё, что связано с токенами, — только в личных чатах
# (токены нельзя светить в группах). Загрузка файлов работает и в личке, и в группах.
private = Router(name="private")
private.message.filter(F.chat.type == "private")
private.callback_query.filter(F.message.chat.type == "private")
dp.include_router(private)


class TouchMiddleware(BaseMiddleware):
    """Запоминает имена пользователей — чтобы показывать их в /users."""

    async def __call__(self, handler, event, data):
        user = data.get("event_from_user")
        chat = data.get("event_chat")
        if user and not user.is_bot:
            in_private = bool(chat and chat.type == "private")
            if in_private or store.is_relevant(user.id):
                store.remember(user)
        return await handler(event, data)


dp.message.outer_middleware(TouchMiddleware())
dp.callback_query.outer_middleware(TouchMiddleware())

# ---------------------------------------------------------------- Состояние в памяти

pending: dict[str, dict] = {}   # файлы, ожидающие выбора диска/папки
browse: dict[str, dict] = {}    # сессии выбора корневой папки (/setroot)
awaiting_code: set[int] = set() # админы, от которых ждём код входа
hits: dict[int, deque] = defaultdict(deque)


def purge(sessions: dict):
    now = time.monotonic()
    for k in [k for k, v in sessions.items() if now - v["ts"] > SESSION_TTL]:
        del sessions[k]


def rate_limited(uid: int) -> bool:
    now = time.monotonic()
    q = hits[uid]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= RATE_LIMIT_PER_MIN:
        return True
    q.append(now)
    return False


# ---------------------------------------------------------------- Яндекс

class NoDisk(Exception):
    """У админа нет рабочего токена."""


def client_for(admin_id: int) -> yadisk.AsyncClient:
    token = store.token(admin_id)
    if not token:
        raise NoDisk
    return yadisk.AsyncClient(token=token)


def normalize_path(path: str) -> str:
    path = path.strip().replace("\\", "/").removeprefix("disk:")
    if not path.startswith("/"):
        path = "/" + path
    return path.rstrip("/") or "/"


async def list_folders(admin_id: int, path: str) -> list[tuple[str, str]]:
    folders = []
    async with client_for(admin_id) as d:
        async for item in d.listdir(path):
            if item.type == "dir":
                folders.append((item.name, item.path.removeprefix("disk:")))
    folders.sort(key=lambda x: x[0].lower())
    return folders


async def unique_path(d: yadisk.AsyncClient, folder: str, name: str) -> str:
    """Подбирает свободное имя, чтобы не перезаписать существующий файл."""
    folder = folder.rstrip("/")
    stem, suffix = Path(name).stem, Path(name).suffix
    candidate = f"{folder}/{name}"
    n = 1
    while await d.exists(candidate):
        candidate = f"{folder}/{stem} ({n}){suffix}"
        n += 1
    return candidate


async def validate_token(token: str) -> bool:
    try:
        async with yadisk.AsyncClient(token=token) as d:
            return bool(await d.check_token())
    except Exception:
        logging.exception("Ошибка проверки токена")
        return False


def auth_url() -> str:
    return "https://oauth.yandex.ru/authorize?" + urlencode(
        {"response_type": "code", "client_id": CLIENT_ID}
    )


async def exchange_code(code: str) -> str | None:
    """Меняет код подтверждения на OAuth-токен."""
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.post("https://oauth.yandex.ru/token", data=form) as r:
                body = await r.json(content_type=None)
                if r.status != 200:
                    logging.warning("Яндекс отклонил код: %s %s", r.status, body.get("error"))
                    return None
                return body.get("access_token")
    except Exception:
        logging.exception("Ошибка обмена кода на токен")
        return None


# ---------------------------------------------------------------- Вспомогательное

def extract_file(message: Message) -> tuple[str, str] | None:
    """(file_id, имя файла) для любого поддерживаемого вложения."""
    if message.document:
        d = message.document
        return d.file_id, d.file_name or f"file_{d.file_unique_id}"
    if message.photo:
        p = message.photo[-1]
        return p.file_id, f"photo_{p.file_unique_id}.jpg"
    if message.video:
        v = message.video
        return v.file_id, v.file_name or f"video_{v.file_unique_id}.mp4"
    if message.audio:
        a = message.audio
        return a.file_id, a.file_name or f"audio_{a.file_unique_id}.mp3"
    if message.voice:
        v = message.voice
        return v.file_id, f"voice_{v.file_unique_id}.ogg"
    if message.video_note:
        v = message.video_note
        return v.file_id, f"videonote_{v.file_unique_id}.mp4"
    return None


def not_in_list_text(uid: int) -> str:
    return f"{NOT_IN_LIST}\n\nВаш ID: {uid} — отправьте его админу."


def disk_labels(admin_ids: list[int]) -> list[str]:
    """Названия дисков для кнопок; при совпадении добавляем ID админа."""
    labels = [store.label(a) for a in admin_ids]
    return [
        f"{lb} · {a}" if labels.count(lb) > 1 else lb
        for lb, a in zip(labels, admin_ids)
    ]


async def set_admin_commands(uid: int):
    try:
        await bot.set_my_commands(ADMIN_COMMANDS, scope=BotCommandScopeChat(chat_id=uid))
    except Exception:
        logging.warning("Не удалось выставить меню команд для %s", uid)


async def require_admin(message: Message) -> bool:
    if store.is_admin(message.from_user.id):
        return True
    await message.answer("⛔ Команда недоступна. Вам доступны /start, /help и загрузка файлов.")
    return False


async def notify_token_failed(admin_id: int, user_id: int):
    """Сообщает админу, что его токен перестал работать."""
    if admin_id == user_id:
        return
    try:
        await bot.send_message(
            admin_id,
            f"⚠️ Токен диска «{store.label(admin_id)}» недействителен. "
            "Нажми /start → «Подключить диск», чтобы подключить заново.",
        )
    except (TelegramForbiddenError, TelegramBadRequest):
        pass


def token_failed_text(admin_id: int, user_id: int) -> str:
    if admin_id == user_id:
        return "⚠️ Токен твоего диска недействителен. Нажми /start → «Подключить диск»."
    return f"⚠️ Диск «{store.label(admin_id)}» сейчас недоступен. Сообщите об этом админу."


# ---------------------------------------------------------------- /start, /help

@private.message(Command("start"))
async def cmd_start(message: Message):
    kb = InlineKeyboardBuilder()
    kb.button(text="🔗 Подключить диск", callback_data="s:connect")
    kb.button(text="📤 Загрузить файл", callback_data="s:upload")
    kb.adjust(1)
    await message.answer(
        "Привет! Что хочешь сделать?\n\n"
        "1 — подключить свой Яндекс Диск (ты станешь его админом и сможешь добавлять пользователей)\n"
        "2 — загрузить файл на диск, к которому тебя добавил админ",
        reply_markup=kb.as_markup(),
    )


async def begin_connect(target: Message, uid: int):
    """Запускает подключение диска: вход по коду или ручной токен."""
    if CLIENT_ID and CLIENT_SECRET:
        awaiting_code.add(uid)
        await target.answer(
            "Подключаем диск:\n"
            "1. Открой ссылку и войди в аккаунт Яндекса, на чьём Диске будут храниться файлы:\n"
            f"{auth_url()}\n"
            "2. Разреши доступ.\n"
            "3. Яндекс покажет код — отправь его мне сообщением (или командой /code КОД)."
        )
    else:
        await target.answer(
            "Вход по коду не настроен, поэтому токен нужно вставить вручную.\n"
            "Получи OAuth-токен Яндекс Диска (права cloud_api:disk.read и cloud_api:disk.write) "
            "и отправь его командой:\n/settoken ТОКЕН\n"
            "Сообщение с токеном я сразу удалю из чата."
        )


@private.callback_query(F.data == "s:connect")
async def cb_connect(cb: CallbackQuery):
    uid = cb.from_user.id
    store.create_admin(uid)
    await set_admin_commands(uid)
    await cb.answer()
    if store.has_token(uid):
        await cb.message.answer(
            f"Диск «{store.label(uid)}» уже подключён. Чтобы подключить другой аккаунт "
            "или обновить токен, пройди вход заново. Остальные команды: /help."
        )
    else:
        await cb.message.answer("Ты теперь админ. Все команды админа — в /help.")
    await begin_connect(cb.message, uid)


@private.callback_query(F.data == "s:upload")
async def cb_upload(cb: CallbackQuery):
    await cb.answer()
    if not store.disks_for(cb.from_user.id):
        return await cb.message.answer(not_in_list_text(cb.from_user.id))
    await cb.message.answer(
        "Отправь файл (документ, фото, видео, аудио или голосовое) — "
        "я спрошу, куда его положить."
    )


@private.message(Command("help"))
async def cmd_help(message: Message):
    text = (
        "Как пользоваться:\n"
        "• Отправь файл (документ, фото, видео, аудио, голосовое) — бот спросит, "
        "на какой диск и в какую папку его положить.\n"
        "• /start — главное меню.\n"
        "• В группе бот сначала спросит, нужно ли загружать файл (кнопки «Да» и «Нет»), "
        "в личке этого вопроса нет.\n"
        "Если тебя нет в списке пользователей, обратись к админу диска.\n"
        "Обычный бот Telegram принимает файлы размером до 20 МБ."
    )
    if store.is_admin(message.from_user.id):
        text += (
            "\n\nКоманды админа:\n"
            "/settings — настройки диска\n"
            "/code КОД — подтвердить вход через Яндекс\n"
            "/settoken ТОКЕН — вставить OAuth-токен вручную\n"
            "/setroot [путь] — корневая папка диска\n"
            "/diskname [название] — название диска\n"
            "/adduser ID — добавить пользователя\n"
            "/removeuser ID — убрать пользователя\n"
            "/users — список пользователей\n"
            "/logout — отключить диск (токен удаляется, список пользователей остаётся)"
        )
    await message.answer(text)


# ---------------------------------------------------------------- Админ: токен

def connected_text(uid: int) -> str:
    a = store.admin(uid)
    return (
        "✅ Диск подключён.\n"
        f"Название: «{store.label(uid)}» (изменить: /diskname)\n"
        f"Корневая папка: {a['base_path']} (изменить: /setroot)\n"
        "Добавить пользователей: /adduser ID"
    )


async def finish_code(message: Message, code: str):
    uid = message.from_user.id
    if not (CLIENT_ID and CLIENT_SECRET):
        awaiting_code.discard(uid)
        return await message.answer("Вход по коду не настроен. Используй /settoken ТОКЕН.")
    token = await exchange_code(code)
    if not token or not await validate_token(token):
        return await message.answer(
            "❌ Код не подошёл (возможно, он устарел или введён с ошибкой). "
            "Открой ссылку из /start → «Подключить диск» ещё раз и отправь новый код."
        )
    store.set_token(uid, token)
    awaiting_code.discard(uid)
    await message.answer(connected_text(uid))


@private.message(Command("code"))
async def cmd_code(message: Message, command: CommandObject):
    if not await require_admin(message):
        return
    code = (command.args or "").strip()
    if not code:
        return await message.answer("Использование: /code КОД (код показывает Яндекс после входа).")
    await finish_code(message, code)


@private.message(Command("settoken"))
async def cmd_settoken(message: Message, command: CommandObject):
    if not await require_admin(message):
        return
    token = (command.args or "").strip()
    if not token:
        return await message.answer("Использование: /settoken ТОКЕН (OAuth-токен Яндекс Диска).")

    deleted = True
    try:
        await message.delete()  # сразу убираем токен из чата
    except TelegramBadRequest:
        deleted = False

    if not await validate_token(token):
        return await message.answer("❌ Токен не подошёл. Предыдущий токен остался без изменений.")

    uid = message.from_user.id
    store.set_token(uid, token)
    awaiting_code.discard(uid)
    note = "" if deleted else "\n⚠️ Удали своё сообщение с токеном вручную."
    await message.answer(connected_text(uid) + note)


@private.message(Command("logout"))
async def cmd_logout(message: Message):
    if not await require_admin(message):
        return
    uid = message.from_user.id
    store.clear_token(uid)
    awaiting_code.discard(uid)
    await message.answer(
        "Диск отключён, токен удалён. Список пользователей и настройки сохранены — "
        "при повторном подключении всё вернётся. Пока диск отключён, загружать на него нельзя."
    )


# ---------------------------------------------------------------- Админ: настройки

@private.message(Command("settings"))
async def cmd_settings(message: Message):
    if not await require_admin(message):
        return
    uid = message.from_user.id
    a = store.admin(uid)
    await message.answer(
        f"Название диска: «{store.label(uid)}»\n"
        f"Диск: {'подключён' if a['token'] else 'не подключён'}\n"
        f"Корневая папка: {a['base_path']}\n"
        f"Пользователей: {len(a['users'])}"
    )


@private.message(Command("diskname"))
async def cmd_diskname(message: Message, command: CommandObject):
    if not await require_admin(message):
        return
    uid = message.from_user.id
    name = " ".join((command.args or "").split())
    if not name:
        return await message.answer(
            f"Название диска: «{store.label(uid)}»\nИзменить: /diskname Новое название"
        )
    if len(name) > MAX_DISKNAME_LEN:
        return await message.answer(f"❌ Название не длиннее {MAX_DISKNAME_LEN} символов.")
    if store.name_taken(name, uid):
        return await message.answer("❌ Такое название уже занято. Выбери другое.")
    store.admin(uid)["name"] = name
    store.save()
    await message.answer(f"✅ Название диска: «{name}»")


# ---------------------------------------------------------------- Админ: пользователи

def parse_user_id(command: CommandObject) -> int | None:
    arg = (command.args or "").strip()
    return int(arg) if arg.isdigit() else None


@private.message(Command("adduser"))
async def cmd_adduser(message: Message, command: CommandObject):
    if not await require_admin(message):
        return
    uid = message.from_user.id
    target = parse_user_id(command)
    if target is None:
        return await message.answer(
            "Использование: /adduser ID\nID человека можно узнать у бота @userinfobot."
        )
    if target == uid:
        return await message.answer("Ты и так админ этого диска.")
    a = store.admin(uid)
    if target in a["users"]:
        return await message.answer("Этот человек уже в списке.")
    a["users"].append(target)
    store.save()
    await message.answer(f"✅ Добавлен: {store.display(target)}")
    try:
        await bot.send_message(
            target,
            f"Вас добавили к диску «{store.label(uid)}». Отправьте мне файл, чтобы загрузить его.",
        )
    except (TelegramForbiddenError, TelegramBadRequest):
        pass  # человек ещё не запускал бота — сообщить ему нужно самому


@private.message(Command("removeuser"))
async def cmd_removeuser(message: Message, command: CommandObject):
    if not await require_admin(message):
        return
    target = parse_user_id(command)
    if target is None:
        return await message.answer("Использование: /removeuser ID")
    a = store.admin(message.from_user.id)
    if target not in a["users"]:
        return await message.answer("Этого человека нет в списке.")
    a["users"].remove(target)
    store.save()
    await message.answer(f"✅ Убран: {store.display(target)}")


@private.message(Command("users"))
async def cmd_users(message: Message):
    if not await require_admin(message):
        return
    users = store.admin(message.from_user.id)["users"]
    if not users:
        return await message.answer("Список пуст. Добавить: /adduser ID")
    lines = [f"{i}. {store.display(u)} — {u}" for i, u in enumerate(users, 1)]
    await message.answer("Пользователи диска:\n" + "\n".join(lines))


# ---------------------------------------------------------------- Админ: корневая папка

@private.message(Command("setroot"))
async def cmd_setroot(message: Message, command: CommandObject):
    if not await require_admin(message):
        return
    uid = message.from_user.id
    if not store.has_token(uid):
        return await message.answer("Сначала подключи диск: /start → «Подключить диск».")

    if command.args:
        path = normalize_path(command.args)
        try:
            if path != "/":
                async with client_for(uid) as d:
                    if not await d.is_dir(path):
                        return await message.answer("❌ Такой папки нет на диске.")
        except (NoDisk, yadisk.exceptions.UnauthorizedError):
            return await message.answer("⚠️ Токен недействителен. Подключи диск заново: /start.")
        except Exception:
            logging.exception("Ошибка проверки папки")
            return await message.answer("❌ Не удалось проверить папку.")
        store.admin(uid)["base_path"] = path
        store.save()
        return await message.answer(f"✅ Корневая папка: {path}")

    purge(browse)
    key = uuid.uuid4().hex[:8]
    browse[key] = {"path": "/", "folders": [], "user_id": uid, "ts": time.monotonic()}
    sent = await message.answer("Загружаю папки…")
    await render_browser(key, sent)


async def render_browser(key: str, target: Message):
    st = browse[key]
    try:
        st["folders"] = await list_folders(st["user_id"], st["path"])
    except (NoDisk, yadisk.exceptions.UnauthorizedError):
        browse.pop(key, None)
        return await target.edit_text("⚠️ Токен недействителен. Подключи диск заново: /start.")
    except Exception:
        logging.exception("Ошибка чтения папок")
        browse.pop(key, None)
        return await target.edit_text("❌ Не удалось прочитать папки.")

    kb = InlineKeyboardBuilder()
    kb.button(text=f"✅ Выбрать: {st['path']}", callback_data=f"bs:{key}")
    for i, (name, _) in enumerate(st["folders"][:MAX_FOLDER_BUTTONS]):
        kb.button(text=f"📁 {name}", callback_data=f"be:{key}:{i}")
    if st["path"] != "/":
        kb.button(text="⬆️ Вверх", callback_data=f"bu:{key}")
    kb.button(text="✖️ Отмена", callback_data=f"bx:{key}")
    kb.adjust(1)
    await target.edit_text(
        f"Текущая папка: {st['path']}\n"
        "Зайди в подпапку или нажми «Выбрать», чтобы сделать эту папку корневой.",
        reply_markup=kb.as_markup(),
    )


def browse_session(cb: CallbackQuery, key: str) -> dict | None:
    st = browse.get(key)
    if not st or st["user_id"] != cb.from_user.id or not store.is_admin(cb.from_user.id):
        return None
    return st


@private.callback_query(F.data.startswith("be:"))
async def browse_enter(cb: CallbackQuery):
    _, key, idx = cb.data.split(":")
    st = browse_session(cb, key)
    if not st:
        return await cb.answer("Запрос устарел, вызови /setroot заново.", show_alert=True)
    st["path"] = st["folders"][int(idx)][1]
    await cb.answer()
    await render_browser(key, cb.message)


@private.callback_query(F.data.startswith("bu:"))
async def browse_up(cb: CallbackQuery):
    key = cb.data.split(":")[1]
    st = browse_session(cb, key)
    if not st:
        return await cb.answer("Запрос устарел, вызови /setroot заново.", show_alert=True)
    st["path"] = posixpath.dirname(st["path"].rstrip("/")) or "/"
    await cb.answer()
    await render_browser(key, cb.message)


@private.callback_query(F.data.startswith("bs:"))
async def browse_select(cb: CallbackQuery):
    key = cb.data.split(":")[1]
    st = browse_session(cb, key)
    if not st:
        return await cb.answer("Запрос устарел, вызови /setroot заново.", show_alert=True)
    store.admin(st["user_id"])["base_path"] = st["path"]
    store.save()
    browse.pop(key, None)
    await cb.message.edit_text(f"✅ Корневая папка: {st['path']}")
    await cb.answer()


@private.callback_query(F.data.startswith("bx:"))
async def browse_cancel(cb: CallbackQuery):
    key = cb.data.split(":")[1]
    if browse_session(cb, key):
        browse.pop(key, None)
    await cb.message.edit_text("Отменено.")
    await cb.answer()


# ---------------------------------------------------------------- Загрузка файлов

@private.message(F.text & ~F.text.startswith("/"))
async def on_text(message: Message):
    if message.from_user.id in awaiting_code:
        return await finish_code(message, message.text.strip())
    await message.answer("Отправь мне файл или нажми /start.")


@dp.message(F.document | F.photo | F.video | F.audio | F.voice | F.video_note)
async def on_file(message: Message):
    if not message.from_user:
        return
    uid = message.from_user.id
    in_group = message.chat.type != "private"

    disks = store.disks_for(uid)
    if not disks:
        if in_group:
            return  # в группе тем, кого нет в списках, не отвечаем
        return await message.reply(not_in_list_text(uid))
    if rate_limited(uid):
        if in_group:
            return
        return await message.reply("⏳ Слишком много файлов подряд. Подожди минуту.")

    info = extract_file(message)
    if not info:
        return
    file_id, name = info

    purge(pending)
    key = uuid.uuid4().hex[:8]
    pending[key] = {
        "file_id": file_id,
        "name": name,
        "user_id": uid,
        "disks": disks,
        "admin_id": None,
        "folders": [],
        "ts": time.monotonic(),
    }

    if in_group:
        # В группе сначала спрашиваем, нужно ли вообще загружать этот файл
        kb = InlineKeyboardBuilder()
        kb.button(text="✅ Да", callback_data=f"g:{key}:y")
        kb.button(text="✖️ Нет", callback_data=f"g:{key}:n")
        kb.adjust(2)
        return await message.reply(
            f"Загрузить «{name}» на Яндекс Диск?", reply_markup=kb.as_markup()
        )

    # В личке вопрос пропускаем — сразу выбор диска/папки
    sent = await message.reply("Минутку…")
    await proceed(key, sent)


async def proceed(key: str, target: Message):
    """Следующий шаг: выбор диска (если их несколько) или сразу выбор папки."""
    p = pending[key]
    disks = p["disks"]
    if len(disks) == 1:
        p["admin_id"] = disks[0]
        await target.edit_text("Загружаю список папок…")
        return await show_folders(key, target)

    kb = InlineKeyboardBuilder()
    for i, label in enumerate(disk_labels(disks)):
        kb.button(text=f"💽 {label}", callback_data=f"d:{key}:{i}")
    kb.button(text="✖️ Отмена", callback_data=f"x:{key}")
    kb.adjust(1)
    await target.edit_text(
        f"На какой диск загрузить «{p['name']}»?", reply_markup=kb.as_markup()
    )


@dp.callback_query(F.data.startswith("g:"))
async def on_group_confirm(cb: CallbackQuery):
    _, key, answer = cb.data.split(":")
    p = pending.get(key)
    if not p:
        return await cb.answer("Запрос устарел, отправь файл заново.", show_alert=True)
    if p["user_id"] != cb.from_user.id:
        return await cb.answer("Это не твой файл.", show_alert=True)

    if answer == "n":
        pending.pop(key, None)
        await cb.answer()
        try:
            await cb.message.delete()  # не засоряем группу
        except TelegramBadRequest:
            await cb.message.edit_text("Хорошо, этот файл не загружаю.")
        return

    await cb.answer()
    await proceed(key, cb.message)


async def show_folders(key: str, target: Message):
    p = pending[key]
    admin_id = p["admin_id"]
    base = store.admin(admin_id)["base_path"]
    try:
        p["folders"] = await list_folders(admin_id, base)
    except (NoDisk, yadisk.exceptions.UnauthorizedError):
        pending.pop(key, None)
        await notify_token_failed(admin_id, p["user_id"])
        return await target.edit_text(token_failed_text(admin_id, p["user_id"]))
    except Exception:
        logging.exception("Не удалось получить список папок")
        pending.pop(key, None)
        return await target.edit_text(
            "❌ Не удалось получить список папок. Возможно, корневая папка удалена — "
            "сообщите админу диска."
        )

    kb = InlineKeyboardBuilder()
    kb.button(text=f"📁 {base}", callback_data=f"f:{key}:root")
    for i, (folder_name, _) in enumerate(p["folders"][:MAX_FOLDER_BUTTONS]):
        kb.button(text=f"📁 {folder_name}", callback_data=f"f:{key}:{i}")
    kb.button(text="✖️ Отмена", callback_data=f"x:{key}")
    kb.adjust(1)
    await target.edit_text(f"Куда положить «{p['name']}»?", reply_markup=kb.as_markup())


@dp.callback_query(F.data.startswith("x:"))
async def on_cancel(cb: CallbackQuery):
    key = cb.data.split(":")[1]
    p = pending.get(key)
    if p and p["user_id"] != cb.from_user.id:
        return await cb.answer("Это не твой файл.", show_alert=True)
    pending.pop(key, None)
    await cb.message.edit_text("Отменено.")
    await cb.answer()


@dp.callback_query(F.data.startswith("d:"))
async def on_disk(cb: CallbackQuery):
    _, key, idx = cb.data.split(":")
    p = pending.get(key)
    if not p:
        return await cb.answer("Запрос устарел, отправь файл заново.", show_alert=True)
    if p["user_id"] != cb.from_user.id:
        return await cb.answer("Это не твой файл.", show_alert=True)
    admin_id = p["disks"][int(idx)]
    if admin_id not in store.disks_for(cb.from_user.id):
        pending.pop(key, None)
        await cb.message.edit_text("Доступ к этому диску закрыт.")
        return await cb.answer()
    p["admin_id"] = admin_id
    await cb.answer()
    await cb.message.edit_text("Загружаю список папок…")
    await show_folders(key, cb.message)


@dp.callback_query(F.data.startswith("f:"))
async def on_folder(cb: CallbackQuery):
    _, key, idx = cb.data.split(":")
    p = pending.get(key)
    if not p:
        return await cb.answer("Запрос устарел, отправь файл заново.", show_alert=True)
    if p["user_id"] != cb.from_user.id:
        return await cb.answer("Это не твой файл.", show_alert=True)

    admin_id = p["admin_id"]
    if admin_id not in store.disks_for(cb.from_user.id):
        pending.pop(key, None)
        await cb.message.edit_text("Доступ к этому диску закрыт.")
        return await cb.answer()

    if idx == "root":
        folder_name = folder_path = store.admin(admin_id)["base_path"]
    else:
        folder_name, folder_path = p["folders"][int(idx)]

    pending.pop(key, None)
    disk_label = store.label(admin_id)
    await cb.message.edit_text(f"⏳ Загружаю «{p['name']}» в «{disk_label}» → {folder_name}…")
    await cb.answer()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / p["name"]
            await bot.download(p["file_id"], destination=local)
            async with client_for(admin_id) as d:
                target = await unique_path(d, folder_path, p["name"])
                await d.upload(str(local), target)
    except TelegramBadRequest as e:
        if "too big" in str(e).lower():
            return await cb.message.edit_text(
                "❌ Файл больше 20 МБ — Telegram не отдаёт такие файлы обычным ботам."
            )
        return await cb.message.edit_text(f"❌ Ошибка Telegram: {e}")
    except (NoDisk, yadisk.exceptions.UnauthorizedError):
        await notify_token_failed(admin_id, p["user_id"])
        return await cb.message.edit_text(token_failed_text(admin_id, p["user_id"]))
    except Exception:
        logging.exception("Ошибка загрузки")
        return await cb.message.edit_text("❌ Не удалось загрузить файл на Яндекс Диск.")

    await cb.message.edit_text(f"✅ Готово: «{p['name']}» → «{disk_label}», {folder_name}")


# ---------------------------------------------------------------- Запуск

async def main():
    if not (CLIENT_ID and CLIENT_SECRET):
        logging.warning(
            "YANDEX_CLIENT_ID/YANDEX_CLIENT_SECRET не заданы: вход по коду отключён, "
            "диски подключаются через /settoken."
        )
    await bot.set_my_commands(USER_COMMANDS)
    for admin_id in list(store.admins):
        await set_admin_commands(int(admin_id))
    await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
