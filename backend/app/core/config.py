"""Настройки приложения из переменных окружения (.env)."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GRC_", env_file=".env", extra="ignore")

    # Строка подключения SQLAlchemy (GRC_DATABASE_URL). В Docker собирается в entrypoint.
    database_url: str = "sqlite+pysqlite:///./grc.db"

    # local — свой вход по паролю; platform — токены «Платформы» (этап 3).
    auth_mode: Literal["local", "platform"] = "local"

    # Ключ подписи токенов и шифрования секретов. Обязателен вне режима разработки.
    secret_key: str = ""

    # Режим разработки: разрешает пустой secret_key и SQLite.
    dev_mode: bool = False

    # Срок жизни токена доступа в режиме local, минуты.
    token_ttl_minutes: int = 480
    # Пауза после N неудачных входов подряд для одного имени.
    login_max_failures: int = 5
    login_lockout_seconds: int = 300

    # Первый администратор: создаётся при старте, если пользователей ещё нет.
    bootstrap_admin: str = "admin"
    bootstrap_admin_password: str = ""

    # Каталог справочников (YAML). В Docker — /srv/reference.
    reference_dir: Path = Path(__file__).resolve().parents[3] / "reference"

    # Пути, под которыми продукт виден в платформе (для манифеста).
    base_path: str = "/grc/"
    api_base: str = "/api/grc/"


@lru_cache
def get_settings() -> Settings:
    return Settings()
