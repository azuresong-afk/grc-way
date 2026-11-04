"""Клиент API «Сканера». Всё обращение к «Сканеру» — только через этот модуль.

- `LiveScannerClient` — REST API «Сканера» по токену сервисной учётной записи
  (роль auditor: только чтение). Токен берётся из GRC_SCANNER_TOKEN или
  получается через `POST /auth/token` по GRC_SCANNER_USERNAME/PASSWORD.
- `FixtureScannerClient` — сохранённые ответы из fixtures/: тесты, демо и стенд
  без «Сканера» (GRC_SCANNER_MODE=fixture).

Ошибки приводятся к `ScannerError` с понятным русским текстом; учётные данные
и токены в текст ошибок и журнал не попадают.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import TypeAdapter, ValidationError

from app.core.config import Settings, get_settings
from app.integrations.scanner.schemas import ScannerProfile

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_PROFILES = TypeAdapter(list[ScannerProfile])


class ScannerError(Exception):
    """«Сканер» недоступен или ответил не так, как ожидалось."""

    def __init__(self, message: str, code: str = "scanner_unavailable") -> None:
        super().__init__(message)
        self.code = code


class ScannerClient(Protocol):
    mode: str
    # Откуда берутся данные: адрес «Сканера» или имя фикстуры (для экрана и журнала).
    source: str

    def compliance_profiles(self) -> list[ScannerProfile]: ...


def _parse_profiles(data: Any) -> list[ScannerProfile]:
    try:
        profiles = _PROFILES.validate_python(data)
    except ValidationError as e:
        first = e.errors()[0]
        where = ".".join(str(x) for x in first["loc"])
        raise ScannerError(
            f"«Сканер» вернул неожиданный ответ на GET /compliance/profiles ({where}: "
            f"{first['msg']})",
            code="scanner_bad_response",
        ) from e
    ids = [p.id for p in profiles]
    if len(ids) != len(set(ids)):
        raise ScannerError(
            "«Сканер» вернул профили с повторяющимися идентификаторами",
            code="scanner_bad_response",
        )
    for p in profiles:
        cids = [c.id for c in p.controls]
        if len(cids) != len(set(cids)):
            raise ScannerError(
                f"«Сканер» вернул повторяющиеся меры в профиле {p.id}",
                code="scanner_bad_response",
            )
        codes = {g.code for g in p.groups}
        if stray := sorted({c.group for c in p.controls} - codes):
            raise ScannerError(
                f"«Сканер»: в профиле {p.id} меры ссылаются на неизвестные группы: "
                f"{', '.join(stray)}",
                code="scanner_bad_response",
            )
    return profiles


class FixtureScannerClient:
    mode = "fixture"

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or FIXTURES
        self.source = f"фикстура {self.directory.name}/compliance_profiles.json"

    def compliance_profiles(self) -> list[ScannerProfile]:
        path = self.directory / "compliance_profiles.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise ScannerError(f"Фикстура «Сканера» не читается: {path.name}") from e
        return _parse_profiles(data)


class LiveScannerClient:
    mode = "live"

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self.source = settings.scanner_url.rstrip("/") or "адрес не задан"
        self._transport = transport
        self._token = settings.scanner_token or None

    def ensure_configured(self) -> None:
        if not self.settings.scanner_url:
            raise ScannerError(
                "Адрес «Сканера» не задан (GRC_SCANNER_URL в .env)", code="scanner_not_configured"
            )
        if not self.settings.scanner_token and not (
            self.settings.scanner_username and self.settings.scanner_password
        ):
            raise ScannerError(
                "Не заданы учётные данные сервисной учётной записи «Сканера» "
                "(GRC_SCANNER_USERNAME и GRC_SCANNER_PASSWORD или GRC_SCANNER_TOKEN)",
                code="scanner_not_configured",
            )

    def _client(self) -> httpx.Client:
        verify: Any = self.settings.scanner_ca_file or True
        return httpx.Client(
            base_url=self.settings.scanner_url.rstrip("/"),
            timeout=self.settings.scanner_timeout_seconds,
            verify=verify,
            transport=self._transport,
            headers={"Accept": "application/json", "User-Agent": "grc-attestation"},
            follow_redirects=False,
        )

    def _login(self, http: httpx.Client) -> str:
        r = http.post(
            "/auth/token",
            json={
                "username": self.settings.scanner_username,
                "password": self.settings.scanner_password,
            },
        )
        if r.status_code in (401, 403):
            raise ScannerError(
                "«Сканер» отклонил учётные данные сервисной учётной записи", code="scanner_auth"
            )
        if r.status_code == 429:
            raise ScannerError(
                "«Сканер» временно заблокировал вход сервисной учётной записи после "
                "неудачных попыток",
                code="scanner_auth",
            )
        self._check(r, "POST /auth/token")
        try:
            return str(r.json()["access_token"])
        except (ValueError, KeyError, TypeError) as e:
            raise ScannerError(
                "«Сканер» вернул неожиданный ответ на вход", code="scanner_bad_response"
            ) from e

    @staticmethod
    def _check(r: httpx.Response, what: str) -> None:
        if r.status_code >= 400:
            raise ScannerError(f"«Сканер» ответил {r.status_code} на {what}")

    def _get(self, path: str) -> Any:
        self.ensure_configured()
        try:
            with self._client() as http:
                if self._token is None:
                    self._token = self._login(http)
                r = http.get(path, headers={"Authorization": f"Bearer {self._token}"})
                if r.status_code == 401 and self.settings.scanner_username:
                    # Токен истёк — один повторный вход.
                    self._token = self._login(http)
                    r = http.get(path, headers={"Authorization": f"Bearer {self._token}"})
        except httpx.TimeoutException as e:
            raise ScannerError(
                f"«Сканер» не ответил за {self.settings.scanner_timeout_seconds:g} с"
            ) from e
        except httpx.HTTPError as e:
            raise ScannerError(f"Не удалось связаться со «Сканером»: {type(e).__name__}") from e
        if r.status_code == 401:
            raise ScannerError(
                "«Сканер» не принял токен сервисной учётной записи", code="scanner_auth"
            )
        if r.status_code == 403:
            raise ScannerError(
                "У сервисной учётной записи нет права просмотра отчётов в «Сканере» "
                "(нужна роль auditor)",
                code="scanner_auth",
            )
        self._check(r, f"GET {path}")
        try:
            return r.json()
        except ValueError as e:
            raise ScannerError(
                f"«Сканер» вернул не JSON на GET {path}", code="scanner_bad_response"
            ) from e

    def compliance_profiles(self) -> list[ScannerProfile]:
        return _parse_profiles(self._get("/compliance/profiles"))


def get_scanner_client() -> ScannerClient:
    """Зависимость FastAPI; в тестах подменяется через app.dependency_overrides."""
    settings = get_settings()
    if settings.scanner_mode == "live":
        return LiveScannerClient(settings)
    return FixtureScannerClient(settings.scanner_fixture_dir)
