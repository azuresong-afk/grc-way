"""Настройки приложения из переменных окружения (.env)."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="GRC_", env_file=".env", extra="ignore", populate_by_name=True
    )

    # Строка подключения SQLAlchemy (GRC_DATABASE_URL). В Docker задаётся в docker-compose.yml.
    # В комплекте «Платформы» приходит как DATABASE_URL (контракт v1.1, п. 12).
    database_url: str = Field(
        default="sqlite+pysqlite:///./grc.db",
        validation_alias=AliasChoices("GRC_DATABASE_URL", "DATABASE_URL"),
    )

    # local — свой вход по паролю; platform — токены «Платформы» (задача 3.5).
    # Комплект платформы передаёт AUTH_MODE без префикса.
    auth_mode: Literal["local", "platform"] = Field(
        default="local", validation_alias=AliasChoices("GRC_AUTH_MODE", "AUTH_MODE")
    )

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

    # «Сканер»: live — ходить в его REST API; fixture — отдавать сохранённый ответ
    # (тесты, демо, стенд без «Сканера»).
    scanner_mode: Literal["live", "fixture"] = "fixture"
    # Адрес API «Сканера» без завершающего «/», например http://scanner:8000.
    scanner_url: str = ""
    # Сервисная учётная запись с ролью auditor (только чтение) — или готовый токен.
    scanner_username: str = ""
    scanner_password: str = ""
    scanner_token: str = ""
    scanner_timeout_seconds: float = 20.0
    # Файл с корневыми сертификатами для HTTPS «Сканера»; пусто — системные.
    scanner_ca_file: str = ""
    # Каталог с фикстурами для scanner_mode=fixture; пусто — встроенные.
    scanner_fixture_dir: Path | None = None

    # «Устранение» (задача 3.4): live — создавать заявки через его REST API;
    # fixture — заявки создаются без «Устранения» (тесты, демо, стенд без соседа).
    vm_mode: Literal["live", "fixture"] = "fixture"
    # Адрес API «Устранения» без завершающего «/», например http://vm:8000.
    vm_url: str = ""
    # Токен сервисной учётной записи «Устранения» (роль руководителя).
    vm_token: str = ""
    vm_timeout_seconds: float = 20.0
    vm_ca_file: str = ""
    # Адрес веб-интерфейса «Устранения» для ссылок «Открыть заявку»; пусто — без ссылок.
    vm_web_url: str = ""
    # Общий секрет подписи входящих событий (X-Signature: sha256=<HMAC тела>);
    # пусто — приём событий выключен, статусы заявок обновляются опросом.
    # В комплекте платформы — PLATFORM_EVENTS_SECRET (тот же секрет в обе стороны).
    events_secret: str = Field(
        default="", validation_alias=AliasChoices("GRC_EVENTS_SECRET", "PLATFORM_EVENTS_SECRET")
    )

    # Вес меры «Частично» в проценте реализации (0 — считать нереализованной, 1 — реализованной).
    partial_weight: float = Field(default=0.5, ge=0, le=1)

    # Файлы доказательств: том, имя файла — sha256 содержимого. В Docker — /data/evidence.
    evidence_dir: Path = Path("./data/evidence")
    # Предел размера одного файла доказательства, МБ.
    evidence_max_mb: int = Field(default=50, ge=1, le=1024)

    # Выгрузки БДУ ФСТЭК (thrlist.xlsx, vullist.xlsx): том, имя — sha256. В Docker — /data/bdu.
    bdu_dir: Path = Path("./data/bdu")
    # Предел размера выгрузки, МБ (vullist.xlsx — около 100 МБ).
    bdu_max_mb: int = Field(default=400, ge=1, le=2048)

    # Реестр сертифицированных СЗИ (CSV/XLSX): том, имя — sha256. В Docker — /data/szi.
    szi_dir: Path = Path("./data/szi")
    szi_max_mb: int = Field(default=50, ge=1, le=1024)
    # За сколько дней до окончания срока сертификат СЗИ считается истекающим.
    szi_expiry_days: int = Field(default=90, ge=1, le=730)

    # Документы комплекта (задача 3.1): шаблоны DOCX и том со сформированными файлами
    # (имя — sha256). В Docker — /srv/templates и /data/documents.
    templates_dir: Path = Path(__file__).resolve().parents[3] / "templates" / "docx"
    documents_dir: Path = Path("./data/documents")
    # Преобразование DOCX → PDF: путь или имя soffice (LibreOffice); none — без PDF.
    pdf_converter: str = "soffice"
    pdf_timeout_seconds: float = Field(default=120, ge=5, le=900)

    # ---------- «Платформа» (задача 3.5, контракт v1.1) ----------
    # Переменные комплекта приходят без префикса GRC_ (docs/integration/README.md, п. 1).
    # Свой id: aud токена, products.<id>, X-Platform-Product, source событий.
    platform_product_id: str = Field(
        default="grc",
        validation_alias=AliasChoices("GRC_PLATFORM_PRODUCT_ID", "PLATFORM_PRODUCT_ID"),
    )
    # API платформы внутри сети, без /api/platform: GET /projects/{id}.
    platform_url: str = Field(
        default="", validation_alias=AliasChoices("GRC_PLATFORM_URL", "PLATFORM_URL")
    )
    # Открытые ключи Ed25519; пусто — {platform_url}/.well-known/jwks.json.
    platform_jwks_url: str = Field(
        default="", validation_alias=AliasChoices("GRC_PLATFORM_JWKS_URL", "PLATFORM_JWKS_URL")
    )
    # Куда отправлять события outbox; пусто — {platform_url}/events (в режиме platform).
    platform_events_url: str = Field(
        default="",
        validation_alias=AliasChoices("GRC_PLATFORM_EVENTS_URL", "PLATFORM_EVENTS_URL"),
    )
    platform_timeout_seconds: float = 10.0
    # Фоновая доставка outbox в процессе API (0 — выключить, например в тестах).
    outbox_worker: bool = True
    # Пауза между проходами доставки, секунды.
    outbox_poll_seconds: float = Field(default=5.0, ge=0.5, le=300)
    # grc.assessment.updated — не чаще раза в N секунд на объект (последнее значение).
    assessment_event_seconds: int = Field(default=60, ge=1, le=3600)

    # Пути, под которыми продукт виден в платформе (для манифеста).
    base_path: str = "/grc/"
    api_base: str = "/api/grc/"

    @property
    def jwks_url(self) -> str:
        if self.platform_jwks_url:
            return self.platform_jwks_url
        return self.platform_url.rstrip("/") + "/.well-known/jwks.json" if self.platform_url else ""

    @property
    def events_url(self) -> str:
        """Адрес приёма событий платформы; пусто — outbox не ведётся."""
        if self.platform_events_url:
            return self.platform_events_url
        if self.auth_mode == "platform" and self.platform_url:
            return self.platform_url.rstrip("/") + "/events"
        return ""

    @property
    def outbox_enabled(self) -> bool:
        return bool(self.events_url and self.events_secret)


@lru_cache
def get_settings() -> Settings:
    return Settings()
