import asyncio
import logging
import os
import tempfile
import uuid
from pathlib import Path

import yadisk
from aiogram import Bot, Dispatcher, F
from aiogram.exceptions import TelegramBadRequest
from aiogram.types import CallbackQuery, Message
from aiogram.utils.keyboard import InlineKeyboardBuilder
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = os.environ["BOT_TOKEN"]
YADISK_TOKEN = os.environ["YADISK_TOKEN"]
# Папка на диске, внутри которой бот ищет подпапки для выбора ("/" = корень)
BASE_PATH = os.getenv("BASE_PATH", "/")
# ID пользователей Telegram, которым разрешено пользоваться ботом (через запятую)
ALLOWED_USERS = {
    int(x) for x in os.getenv("ALLOWED_USERS", "").replace(" ", "").split(",") if x
}

logging.basicConfig(level=logging.INFO)

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()
disk = yadisk.AsyncClient(token=YADISK_TOKEN)

# Файлы, ожидающие выбора папки: key -> {"file_id", "name", "folders", "user_id"}
pending: dict[str, dict] = {}


def is_allowed(user_id: int) -> bool:
    return not ALLOWED_USERS or user_id in ALLOWED_USERS


def extract_file(message: Message) -> tuple[str, str] | None:
    """Возвращает (file_id, имя файла) для любого поддерживаемого типа вложения."""
    if message.document:
        d = message.document
        return d.file_id, d.file_name or f"file_{d.file_unique_id}"
    if message.photo:
        p = message.photo[-1]  # самое большое разрешение
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


async def list_folders() -> list[tuple[str, str]]:
    """Список подпапок в BASE_PATH: [(имя, полный путь), ...]."""
    folders = []
    async for item in disk.listdir(BASE_PATH):
        if item.type == "dir":
            folders.append((item.name, item.path.removeprefix("disk:")))
    folders.sort(key=lambda x: x[0].lower())
    return folders


async def unique_path(folder: str, name: str) -> str:
    """Подбирает свободное имя, чтобы не перезаписать существующий файл."""
    folder = folder.rstrip("/")
    stem, suffix = Path(name).stem, Path(name).suffix
    candidate = f"{folder}/{name}"
    n = 1
    while await disk.exists(candidate):
        candidate = f"{folder}/{stem} ({n}){suffix}"
        n += 1
    return candidate


@dp.message(F.text == "/start")
async def start(message: Message):
    if not is_allowed(message.from_user.id):
        return await message.answer("⛔ Нет доступа.")
    await message.answer(
        "Привет! Отправь мне файл (документ, фото, видео, аудио) — "
        "я спрошу, в какую папку на Яндекс Диске его положить."
    )


@dp.message(F.document | F.photo | F.video | F.audio | F.voice | F.video_note)
async def on_file(message: Message):
    if not is_allowed(message.from_user.id):
        return await message.answer("⛔ Нет доступа.")

    file_info = extract_file(message)
    if not file_info:
        return
    file_id, name = file_info

    try:
        folders = await list_folders()
    except Exception:
        logging.exception("Не удалось получить список папок")
        return await message.reply("❌ Не удалось получить список папок с Яндекс Диска.")

    key = uuid.uuid4().hex[:8]
    pending[key] = {
        "file_id": file_id,
        "name": name,
        "folders": folders,
        "user_id": message.from_user.id,
    }

    kb = InlineKeyboardBuilder()
    kb.button(text="📁 Корень", callback_data=f"f:{key}:root")
    for i, (folder_name, _) in enumerate(folders):
        kb.button(text=f"📁 {folder_name}", callback_data=f"f:{key}:{i}")
    kb.button(text="✖️ Отмена", callback_data=f"x:{key}")
    kb.adjust(1)

    await message.reply(f"Куда положить «{name}»?", reply_markup=kb.as_markup())


@dp.callback_query(F.data.startswith("x:"))
async def on_cancel(cb: CallbackQuery):
    key = cb.data.split(":")[1]
    item = pending.get(key)
    if item and item["user_id"] != cb.from_user.id:
        return await cb.answer("Это не твой файл.", show_alert=True)
    pending.pop(key, None)
    await cb.message.edit_text("Отменено.")
    await cb.answer()


@dp.callback_query(F.data.startswith("f:"))
async def on_folder(cb: CallbackQuery):
    _, key, idx = cb.data.split(":")
    item = pending.get(key)
    if not item:
        return await cb.answer("Запрос устарел, отправь файл заново.", show_alert=True)
    if item["user_id"] != cb.from_user.id:
        return await cb.answer("Это не твой файл.", show_alert=True)

    if idx == "root":
        folder_name, folder_path = "Корень", BASE_PATH
    else:
        folder_name, folder_path = item["folders"][int(idx)]

    pending.pop(key, None)
    await cb.message.edit_text(f"⏳ Загружаю «{item['name']}» в «{folder_name}»…")
    await cb.answer()

    try:
        with tempfile.TemporaryDirectory() as tmp:
            local = Path(tmp) / item["name"]
            await bot.download(item["file_id"], destination=local)
            target = await unique_path(folder_path, item["name"])
            await disk.upload(str(local), target)
    except TelegramBadRequest as e:
        if "too big" in str(e).lower():
            await cb.message.edit_text(
                "❌ Файл больше 20 МБ — Telegram не отдаёт такие файлы обычным ботам."
            )
        else:
            await cb.message.edit_text(f"❌ Ошибка Telegram: {e}")
        return
    except Exception:
        logging.exception("Ошибка загрузки")
        await cb.message.edit_text("❌ Не удалось загрузить файл на Яндекс Диск.")
        return

    await cb.message.edit_text(f"✅ Готово: «{item['name']}» → {folder_name}")


async def main():
    async with disk:
        if not await disk.check_token():
            raise SystemExit("Неверный YADISK_TOKEN")
        await dp.start_polling(bot)


if __name__ == "__main__":
    asyncio.run(main())
