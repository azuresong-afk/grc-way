"""Настройки приложения из переменных окружения (.env)."""

from functools import lru_cache
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

    # Пути, под которыми продукт виден в платформе (для манифеста).
    base_path: str = "/grc/"
    api_base: str = "/api/grc/"


@lru_cache
def get_settings() -> Settings:
    return Settings()
