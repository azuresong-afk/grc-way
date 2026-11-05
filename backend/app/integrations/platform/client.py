"""API «Платформы» внутри сети (без префикса /api/platform).

`GET {PLATFORM_URL}/projects/{id}` — с токеном пользователя, сделавшего запрос
(сервисный токен не подходит: его aud — только наш продукт). Ответ:
`{id, name, client, contract_ref, period_from, period_to, status, created_at, archived_at}`.
"""

from __future__ import annotations

from typing import Any, Protocol

import httpx

from app.core.config import Settings


class PlatformUnavailable(Exception):
    """Платформа не ответила или ответила ошибкой."""


class PlatformClient(Protocol):
    def fetch_project(self, project_id: str, token: str) -> dict[str, Any] | None:
        """Проект или None (404/403 — проекта нет или он недоступен пользователю)."""


class LivePlatformClient:
    def __init__(self, settings: Settings):
        self.base = settings.platform_url.rstrip("/")
        self.timeout = settings.platform_timeout_seconds

    def fetch_project(self, project_id: str, token: str) -> dict[str, Any] | None:
        if not self.base:
            raise PlatformUnavailable("PLATFORM_URL не задан")
        try:
            r = httpx.get(
                f"{self.base}/projects/{project_id}",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                timeout=self.timeout,
            )
        except httpx.HTTPError as e:
            raise PlatformUnavailable(str(e)) from e
        if r.status_code in (403, 404):
            return None
        if r.status_code != 200:
            raise PlatformUnavailable(f"HTTP {r.status_code}")
        data = r.json()
        if not isinstance(data, dict) or not data.get("id"):
            raise PlatformUnavailable("ответ без id")
        return data


_client: PlatformClient | None = None


def set_client(client: PlatformClient | None) -> None:
    """Подмена клиента (тесты, демо со стендом без платформы)."""
    global _client
    _client = client


def get_client(settings: Settings) -> PlatformClient:
    return _client if _client is not None else LivePlatformClient(settings)
