"""План устранения несоответствий и связь с «Устранением» (задача 3.4).

Пункт плана — мера «Не реализована / Частично» или обнаруженная уязвимость
реестра. Правила, которые здесь живут:

- Срок уязвимости — из её текущей оценки по п. 21 Методики 2025 (от оценки,
  присвоившей уровень); вручную не меняется. Просрочка — срок прошёл, а
  устранение не подтверждено. Уязвимость в сертифицированном СЗИ получает
  критический уровень ещё при оценке (п. 4).
- У меры приоритет и срок необязательны: в план срок попадает, только если его
  внёс ответственный (п. 9 ТЗ).
- Способ устранения уязвимости (п. 22): обновление или компенсирующие меры.
  Обновление зарубежного и open source ПО — с отметкой о тестировании по
  Методике тестирования обновлений 2022 (п. 23); компенсирующие меры — только из
  перечня п. 25 (справочник Методики 2025, раздел compensating_measures).
- В «Устранение» уходят технические пункты: уязвимости с оценкой (V, уровень,
  срок) и меры с проверками «Сканера». Организационная мера закрывается
  документами, а не заявкой.
- Состояние пункта выводится из статуса заявки «Устранения»; итог повторной
  проверки «подтверждено» по мере добавляет мере доказательство.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

PRIORITIES = {"high": "Высокий", "medium": "Средний", "low": "Низкий"}
METHODS = {"update": "Обновление", "compensating": "Компенсирующие меры"}
UPDATE_ORIGINS = {
    "foreign": "зарубежное ПО",
    "opensource": "ПО с открытым кодом",
    "domestic": "российское ПО",
}
# Для этих обновлений п. 23 требует тестирования по Методике 2022.
NEEDS_TESTING = ("foreign", "opensource")

# Статусы заявки «Устранения» (vm-way, docs/roadmap.md, «Статусы заявки»).
VM_STATUSES = {
    "new": "Новая",
    "assigned": "Назначена",
    "in_progress": "В работе",
    "waiting_window": "Ожидает окна",
    "fixed": "Исправлено, ждёт проверки",
    "verified": "Подтверждено",
    "not_verified": "Не подтверждено",
    "risk_accepted": "Принят риск",
    "false_positive": "Ложное срабатывание",
    "no_vendor_fix": "Нет исправления у производителя",
    "regression": "Регрессия",
}
# Заявка закрыта не исправлением: решение за специалистом «Аттестации».
VM_DECISION = ("risk_accepted", "false_positive", "no_vendor_fix")

STATES = {
    "open": "Не отправлено",
    "in_work": "В работе",
    "fixed": "Ждёт проверки",
    "verified": "Устранено",
    "decision": "Требует решения",
    "closed": "Закрыто",
}
VERIFY_RESULTS = {
    "verified": "подтверждено",
    "not_verified": "не подтверждено",
    "partial": "подтверждено частично",
    "unverified": "не проверено",
}


class PlanError(ValueError):
    """Неверные данные пункта плана (текст — для пользователя)."""


def state(closed_at: datetime | None, vm_ticket_id: str | None, vm_status: str | None) -> str:
    if closed_at is not None:
        return "closed"
    if not vm_ticket_id:
        return "open"
    if vm_status == "verified":
        return "verified"
    if vm_status == "fixed":
        return "fixed"
    if vm_status in VM_DECISION:
        return "decision"
    return "in_work"


def _aware(at: datetime) -> datetime:
    return at if at.tzinfo else at.replace(tzinfo=UTC)


def overdue(
    *,
    kind: str,
    st: str,
    deadline_at: datetime | None,
    due_date: date | None,
    now: datetime,
) -> bool:
    """Срок прошёл, а устранение не подтверждено (закрытые и устранённые — не просрочены)."""
    if st in ("closed", "verified"):
        return False
    if kind == "vuln":
        return deadline_at is not None and _aware(deadline_at) < now
    return due_date is not None and due_date < now.date()


@dataclass(frozen=True)
class Remediation:
    method: str | None
    update_origin: str | None
    update_tested: bool | None
    compensating: list[str]


def check_remediation(
    method: str | None,
    update_origin: str | None,
    update_tested: bool | None,
    compensating: list[str] | None,
    known_codes: set[str],
) -> Remediation:
    """Проверяет способ устранения уязвимости; лишние поля другого способа сбрасываются."""
    if method is None:
        return Remediation(None, None, None, [])
    if method not in METHODS:
        raise PlanError("Способ устранения — обновление или компенсирующие меры")
    if method == "update":
        if update_origin is not None and update_origin not in UPDATE_ORIGINS:
            raise PlanError("Неизвестный вид ПО для обновления")
        tested = bool(update_tested) if update_origin in NEEDS_TESTING else None
        return Remediation("update", update_origin, tested, [])
    codes: list[str] = []
    for c in compensating or []:
        if c not in known_codes:
            raise PlanError(f"Компенсирующей меры {c} нет в перечне п. 25 Методики")
        if c not in codes:
            codes.append(c)
    if not codes:
        raise PlanError("Выберите хотя бы одну компенсирующую меру из перечня п. 25")
    return Remediation("compensating", None, None, codes)


def warnings(
    *,
    kind: str,
    st: str,
    method: str | None,
    update_origin: str | None,
    update_tested: bool | None,
    resend: bool,
    assessed: bool,
) -> list[str]:
    """Что специалисту стоит поправить в пункте (не мешает сохранению)."""
    out: list[str] = []
    if st == "closed":
        return out
    if kind == "vuln":
        if not assessed:
            out.append("Уязвимость не оценена: в «Устранение» уходят V, уровень и срок")
        if method == "update" and update_origin is None:
            out.append("Укажите, чьё ПО обновляется: от этого зависит тестирование (п. 23)")
        if method == "update" and update_origin in NEEDS_TESTING and not update_tested:
            out.append(
                "Обновление зарубежного или open source ПО — нет отметки о тестировании "
                "по Методике тестирования обновлений (п. 23)"
            )
    if st == "decision":
        out.append(
            "«Устранение» закрыло заявку без исправления: примите решение — компенсирующие "
            "меры или повторная отправка"
        )
    if resend:
        out.append(
            "После отправки изменились оценка, хосты или способ устранения — отправьте повторно"
        )
    return out


def payload_hash(payload: dict[str, Any]) -> str:
    """Хэш содержимого заявки без служебных полей (время формирования)."""
    body = {k: v for k, v in payload.items() if k not in ("generated_at",)}
    raw = json.dumps(body, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()
