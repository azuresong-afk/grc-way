"""Клиент API «Устранения». Всё обращение к «Устранению» — только через этот модуль.

Контракт (предложение «Аттестации», в «Устранении» — отдельная задача):

- `POST /projects/{vm_project_id}/external-tickets` — создать или обновить заявку
  по пункту плана. Тело — `TicketRequest.payload` (source «grc», external_id —
  id пункта плана). Повтор с тем же (source, external_id) не создаёт вторую
  заявку, а обновляет её. Ответ: `{"id": <номер заявки>, "status": "new", ...}`.
- `GET /tickets/{id}` — уже есть в «Устранении»: берём из ответа `status`
  (опрос, когда события не подключены).

Статусы и итог повторной проверки приходят событиями `vm.ticket.status_changed`
`{ticket_id, from, to}` и `vm.remediation.verified {ticket_id, run_id, result}`
(контракт платформы v1, п. 6) — их принимает app/api/nonconformities.py.

- `LiveVmClient` — REST по токену сервисной учётной записи (GRC_VM_TOKEN).
- `FixtureVmClient` — без «Устранения»: номер заявки выводится из id пункта,
  статус «Новая»; тесты, демо и стенд без соседа (GRC_VM_MODE=fixture).

Ошибки приводятся к `VmError` с русским текстом; токен в текст не попадает.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from app.core.config import Settings, get_settings


class VmError(Exception):
    """«Устранение» недоступно или ответило не так, как ожидалось."""

    def __init__(self, message: str, code: str = "vm_unavailable") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Ticket:
    id: str
    status: str


class VmClient(Protocol):
    mode: str
    source: str

    def upsert_ticket(self, vm_project_id: str, payload: dict[str, Any]) -> Ticket: ...

    def ticket(self, ticket_id: str) -> Ticket | None: ...


def _ticket(data: Any, what: str) -> Ticket:
    try:
        tid = data["id"]
        status = data.get("status") or "new"
    except (KeyError, TypeError, AttributeError) as e:
        raise VmError(
            f"«Устранение» вернуло неожиданный ответ на {what}", code="vm_bad_response"
        ) from e
    if tid is None or isinstance(tid, bool) or not str(tid).strip():
        raise VmError(f"«Устранение» не вернуло номер заявки на {what}", code="vm_bad_response")
    return Ticket(id=str(tid), status=str(status))


class LiveVmClient:
    mode = "live"

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self.source = settings.vm_url.rstrip("/") or "адрес не задан"
        self._transport = transport

    def ensure_configured(self) -> None:
        if not self.settings.vm_url:
            raise VmError(
                "Адрес «Устранения» не задан (GRC_VM_URL в .env)", code="vm_not_configured"
            )
        if not self.settings.vm_token:
            raise VmError(
                "Не задан токен сервисной учётной записи «Устранения» (GRC_VM_TOKEN)",
                code="vm_not_configured",
            )

    def _request(self, method: str, path: str, json: Any = None) -> httpx.Response:
        self.ensure_configured()
        verify: Any = self.settings.vm_ca_file or True
        try:
            with httpx.Client(
                base_url=self.settings.vm_url.rstrip("/"),
                timeout=self.settings.vm_timeout_seconds,
                verify=verify,
                transport=self._transport,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "grc-attestation",
                    "Authorization": f"Bearer {self.settings.vm_token}",
                },
                follow_redirects=False,
            ) as http:
                return http.request(method, path, json=json)
        except httpx.TimeoutException as e:
            raise VmError(
                f"«Устранение» не ответило за {self.settings.vm_timeout_seconds:g} с"
            ) from e
        except httpx.HTTPError as e:
            raise VmError(f"Нет связи с «Устранением» ({type(e).__name__})") from e

    @staticmethod
    def _check(r: httpx.Response, what: str) -> None:
        if r.status_code in (401, 403):
            raise VmError("«Устранение» отклонило токен сервисной учётной записи", code="vm_auth")
        if r.status_code >= 400:
            detail = ""
            try:
                d = r.json().get("detail")
                if isinstance(d, str):
                    detail = f": {d[:300]}"
            except (ValueError, AttributeError):
                pass
            raise VmError(f"«Устранение» ответило {r.status_code} на {what}{detail}")

    def upsert_ticket(self, vm_project_id: str, payload: dict[str, Any]) -> Ticket:
        what = "POST /projects/{id}/external-tickets"
        r = self._request("POST", f"/projects/{vm_project_id}/external-tickets", json=payload)
        if r.status_code == 404:
            raise VmError(
                f"В «Устранении» нет проекта {vm_project_id} или приём заявок из «Аттестации» "
                "ещё не включён",
                code="vm_not_found",
            )
        self._check(r, what)
        try:
            data = r.json()
        except ValueError as e:
            raise VmError(f"«Устранение» вернуло не JSON на {what}", "vm_bad_response") from e
        return _ticket(data, what)

    def ticket(self, ticket_id: str) -> Ticket | None:
        r = self._request("GET", f"/tickets/{ticket_id}")
        if r.status_code == 404:
            return None
        self._check(r, "GET /tickets/{id}")
        try:
            data = r.json()
        except ValueError as e:
            raise VmError("«Устранение» вернуло не JSON", "vm_bad_response") from e
        return _ticket(data, "GET /tickets/{id}")


class FixtureVmClient:
    """Заявки без «Устранения»: номер стабилен для пункта плана, статус не меняется."""

    mode = "fixture"
    source = "встроенная заглушка"

    def upsert_ticket(self, vm_project_id: str, payload: dict[str, Any]) -> Ticket:
        digest = hashlib.sha256(str(payload["external_id"]).encode()).hexdigest()
        return Ticket(id=str(100000 + int(digest[:8], 16) % 900000), status="new")

    def ticket(self, ticket_id: str) -> Ticket | None:
        return None  # статусы в заглушке приходят только событиями


def get_vm_client() -> VmClient:
    """Зависимость FastAPI; в тестах подменяется через app.dependency_overrides."""
    settings = get_settings()
    if settings.vm_mode == "live":
        return LiveVmClient(settings)
    return FixtureVmClient()
