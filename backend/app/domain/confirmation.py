"""Подтверждение итогового статуса меры испытателем.

Статус меры — предложение (автоматики или эксперта); подтверждение фиксирует, что
испытатель проверил доказательства и согласен со статусом. Правила:

- «Не оценена» и исключённые при адаптации меры не подтверждаются.
- «Реализована» и «Частично» требуют доказательства: хотя бы одно действующее ручное
  (файл, интервью, осмотр) или — для мер с проверками «Сканера» — совпадение статуса
  с предложением «Сканера» по текущему снимку.
- «Не применима» требует пояснения (комментарий подтверждения или меры).
- «Не реализована» подтверждается без доказательств: отсутствие — тоже результат.

Подтверждение снимается, когда меняется статус, меру исключают или отзывают
доказательство, на которое оно опиралось. Повторный импорт «Сканера» статус
подтверждённой меры не меняет (как и поставленный вручную).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

# remediation — повторная проверка «Устранения» подтвердила исправление (задача 3.4).
MANUAL_KINDS = ("file", "interview", "inspection", "certificate", "remediation")
NEEDS_EVIDENCE = ("implemented", "partial")


class Confirmable(Protocol):
    status: str
    adaptation: str
    status_source: str | None
    auto_status: str | None
    confirmed_at: object
    confirmed_by: object
    confirmed_by_name: str | None
    confirmed_status: str | None
    confirm_comment: str | None
    confirmed_evidence: list


@dataclass(frozen=True)
class Basis:
    """На что опирается подтверждение: ручные доказательства и текущее автоматическое."""

    manual_ids: tuple[str, ...]
    scanner_id: str | None


def blocker(m: Confirmable, basis: Basis, comment: str | None) -> str | None:
    """Почему меру нельзя подтвердить сейчас; None — можно."""
    if m.adaptation == "excluded":
        return "Исключённая при адаптации мера не подтверждается"
    if m.status == "unassessed":
        return "Сначала поставьте статус меры"
    if m.status in NEEDS_EVIDENCE:
        auto_ok = basis.scanner_id is not None and m.status == m.auto_status
        if not basis.manual_ids and not auto_ok:
            return (
                "Нет доказательств: приложите файл, протокол интервью или осмотра"
                if m.auto_status is None
                else "Статус расходится с «Сканером» — приложите ручное доказательство"
            )
    if m.status == "not_applicable" and not (comment or "").strip():
        return "Поясните, почему мера не применима"
    return None


def evidence_ids(m: Confirmable, basis: Basis) -> list[str]:
    ids = list(basis.manual_ids)
    if basis.scanner_id is not None and m.status == m.auto_status:
        ids.append(basis.scanner_id)
    return ids


def clear(m: Confirmable) -> bool:
    """Снимает подтверждение; True — оно было."""
    if m.confirmed_at is None:
        return False
    m.confirmed_at = None
    m.confirmed_by = None
    m.confirmed_by_name = None
    m.confirmed_status = None
    m.confirm_comment = None
    m.confirmed_evidence = []
    return True
