"""Набор мер объекта: базовый набор по классу, адаптация и процент реализации.

Код не содержит нормативных составов: базовый набор — меры профиля, у которых в
levels[] есть класс (уровень, категория) объекта. Процент считается по правилам
docs/roadmap.md («Как считается процент реализации»):

- знаменатель — меры после адаптации, кроме исключённых и «Не применима»;
- «Реализована» = 1, «Частично» = вес (по умолчанию 0,5), «Не реализована» и
  «Не оценена» = 0 (неоценённые — отдельной полосой);
- компенсированная мера считается по статусу компенсирующих: берётся худший
  (нарушение у любой компенсирующей — мера не закрыта);
- три числа: авто (меры с проверками «Сканера»), вручную (организационные), всего.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

STATUSES = ("implemented", "partial", "not_implemented", "not_applicable", "unassessed")
ADAPTATIONS = ("none", "excluded", "compensated")
ORIGINS = ("baseline", "added")
METHODS = ("auto", "manual", "mixed")

# Худший статус компенсирующих определяет статус компенсированной меры.
_WORST_FIRST = ("not_implemented", "unassessed", "partial", "implemented")


@dataclass(frozen=True)
class Item:
    """Минимум о мере объекта, нужный для процента."""

    measure_id: str
    method: str
    status: str
    adaptation: str = "none"
    compensating: tuple[str, ...] = ()


@dataclass
class Bucket:
    # Знаменатель: меры, которые оцениваются.
    total: int = 0
    implemented: int = 0
    partial: int = 0
    not_implemented: int = 0
    unassessed: int = 0
    # Вне знаменателя.
    excluded: int = 0
    not_applicable: int = 0
    # Из знаменателя — сколько считаются по компенсирующим.
    compensated: int = 0
    score: float = 0.0

    @property
    def percent(self) -> float | None:
        if self.total == 0:
            return None
        return round(self.score / self.total * 100, 1)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "implemented": self.implemented,
            "partial": self.partial,
            "not_implemented": self.not_implemented,
            "unassessed": self.unassessed,
            "excluded": self.excluded,
            "not_applicable": self.not_applicable,
            "compensated": self.compensated,
            "score": round(self.score, 2),
            "percent": self.percent,
        }


@dataclass
class Stats:
    total: Bucket = field(default_factory=Bucket)
    auto: Bucket = field(default_factory=Bucket)
    manual: Bucket = field(default_factory=Bucket)

    def as_dict(self) -> dict[str, Any]:
        return {
            "total": self.total.as_dict(),
            "auto": self.auto.as_dict(),
            "manual": self.manual.as_dict(),
        }


def worst(statuses: Iterable[str]) -> str:
    present = set(statuses)
    for s in _WORST_FIRST:
        if s in present:
            return s
    return "unassessed"


def effective_status(item: Item, by_id: Mapping[str, Item]) -> str | None:
    """Статус для процента; None — мера вне знаменателя."""
    if item.adaptation == "excluded":
        return None
    if item.adaptation == "compensated":
        statuses = []
        for cid in item.compensating:
            c = by_id.get(cid)
            # Пропавшая, исключённая или неприменимая компенсирующая ничего не закрывает.
            if c is None or c.adaptation != "none" or c.status == "not_applicable":
                statuses.append("not_implemented")
            else:
                statuses.append(c.status)
        return worst(statuses) if statuses else "not_implemented"
    if item.status == "not_applicable":
        return None
    return item.status if item.status in STATUSES else "unassessed"


def compute_stats(items: Sequence[Item], partial_weight: float = 0.5) -> Stats:
    by_id = {i.measure_id: i for i in items}
    stats = Stats()
    for item in items:
        buckets = [stats.total, stats.auto if item.method in ("auto", "mixed") else stats.manual]
        status = effective_status(item, by_id)
        for b in buckets:
            if status is None:
                if item.adaptation == "excluded":
                    b.excluded += 1
                else:
                    b.not_applicable += 1
                continue
            b.total += 1
            if item.adaptation == "compensated":
                b.compensated += 1
            if status == "implemented":
                b.implemented += 1
                b.score += 1
            elif status == "partial":
                b.partial += 1
                b.score += partial_weight
            elif status == "not_implemented":
                b.not_implemented += 1
            else:
                b.unassessed += 1
    return stats


# ---------- Базовый набор ----------


@dataclass(frozen=True)
class RefItem:
    measure_id: str
    group_code: str
    title: str
    levels: tuple[str, ...]


@dataclass(frozen=True)
class Current:
    measure_id: str
    profile_id: str
    origin: str
    adaptation: str
    compensating: tuple[str, ...]
    assessed: bool


@dataclass
class Plan:
    """Чем текущий набор отличается от базового набора по классу."""

    add: list[str] = field(default_factory=list)  # войдут в набор как базовые
    remove: list[str] = field(default_factory=list)  # базовые, которых больше нет в наборе класса
    promote: list[str] = field(default_factory=list)  # дополненные, ставшие базовыми
    reset: list[str] = field(default_factory=list)  # компенсация потеряет все компенсирующие
    foreign: list[str] = field(default_factory=list)  # меры другого профиля (сменился режим)
    unchanged: int = 0

    @property
    def empty(self) -> bool:
        return not (self.add or self.remove or self.promote or self.reset or self.foreign)


def baseline(refs: Iterable[RefItem], level: str) -> list[str]:
    return [r.measure_id for r in refs if level in r.levels]


def plan(refs: Sequence[RefItem], level: str, profile_id: str, current: Sequence[Current]) -> Plan:
    target = baseline(refs, level)
    target_set = set(target)
    known = {r.measure_id for r in refs}
    mine = {c.measure_id: c for c in current if c.profile_id == profile_id}
    p = Plan()
    p.foreign = sorted(
        f"{c.profile_id}:{c.measure_id}" for c in current if c.profile_id != profile_id
    )
    p.add = [m for m in target if m not in mine]
    for c in mine.values():
        if c.origin == "baseline" and c.measure_id not in target_set:
            p.remove.append(c.measure_id)
        elif c.origin == "added" and c.measure_id not in known:
            # Меру убрали из справочника — её не на что опереть.
            p.remove.append(c.measure_id)
        elif c.origin == "added" and c.measure_id in target_set:
            p.promote.append(c.measure_id)
        else:
            p.unchanged += 1
    gone = set(p.remove)
    for c in mine.values():
        if c.measure_id in gone or c.adaptation != "compensated":
            continue
        if c.compensating and all(x in gone for x in c.compensating):
            p.reset.append(c.measure_id)
    p.remove.sort(key=_order_key(refs))
    p.promote.sort(key=_order_key(refs))
    p.reset.sort(key=_order_key(refs))
    return p


def _order_key(refs: Sequence[RefItem]):
    pos = {r.measure_id: i for i, r in enumerate(refs)}
    return lambda m: (pos.get(m, len(pos)), m)


class AdaptationError(ValueError):
    """Нарушено правило адаптации (сообщение — на русском, для пользователя)."""


def check_compensation(
    measure_id: str, compensating: Sequence[str], items: Mapping[str, Item]
) -> None:
    """Компенсирующие — другие меры набора, сами не исключённые и не компенсированные."""
    if not compensating:
        raise AdaptationError("Укажите хотя бы одну компенсирующую меру")
    if len(set(compensating)) != len(compensating):
        raise AdaptationError("Компенсирующие меры повторяются")
    for cid in compensating:
        if cid == measure_id:
            raise AdaptationError("Мера не может компенсировать сама себя")
        c = items.get(cid)
        if c is None:
            raise AdaptationError(f"Мера {cid} не входит в набор объекта — сначала добавьте её")
        if c.adaptation == "excluded":
            raise AdaptationError(f"Мера {cid} исключена и не может быть компенсирующей")
        if c.adaptation == "compensated":
            raise AdaptationError(f"Мера {cid} сама компенсирована и не может быть компенсирующей")


def compensated_by(measure_id: str, items: Iterable[Item]) -> list[str]:
    """Какие меры набора опираются на эту как на компенсирующую."""
    return [
        i.measure_id
        for i in items
        if i.adaptation == "compensated" and measure_id in i.compensating
    ]
