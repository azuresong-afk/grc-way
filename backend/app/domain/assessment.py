"""Автостатус меры по снимку прогона «Сканера» (docs/roadmap.md, «Как считается процент»).

Чистые функции, без БД. Правила:

- считаются только хосты объекта (провал на хосте вне объекта меру объекта не
  задевает); если состав объекта пуст — все хосты прогона;
- хост проверен по мере, если хотя бы один модуль, которым «Сканер» проверяет
  её проверки, на этом хосте `completed`; модуль `not_applicable` (не та ОС)
  хост из рассмотрения убирает; иначе хост «не проверен» с причиной из покрытия;
- провал хотя бы на одном хосте объекта: «Не реализована», если мера провалена
  на всех проверенных хостах, иначе «Частично» [решение роадмапа];
- без провалов «Реализована» — только если проверены все хосты объекта:
  отсутствие нарушения засчитывается лишь при `completed` хост+модуль. Иначе
  мера остаётся «Не оценена» с пометкой, сколько хостов не проверено;
- меры нет в результате прогона, или «Сканер» не проверил её нигде — «Не оценена».

Автостатус — предложение: финальный статус подтверждает испытатель.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

# Источник проверки (checks.yaml «Сканера») → модули прогона, которые его дают.
SOURCE_MODULES: dict[str, tuple[str, ...]] = {
    "openscap": ("config_audit",),
    "lynis": ("config_audit",),
    "password_policy": ("config_audit",),
    "windows": ("win_inventory",),
    "services": ("discovery",),
    "cred_audit": ("cred_audit",),
}

MODULE_LABELS = {
    "discovery": "обнаружение",
    "vuln": "уязвимости по сети",
    "auth_inventory": "пакеты по SSH",
    "win_inventory": "инвентаризация Windows",
    "config_audit": "аудит конфигурации",
    "cred_audit": "аудит паролей",
}

COVERAGE_LABELS = {
    "completed": "выполнено",
    "not_applicable": "неприменимо",
    "skipped": "пропущено",
    "unreachable": "хост недоступен",
    "no_credentials": "нет учётной записи",
    "timeout": "таймаут",
    "error": "ошибка",
}


def check_modules(sources: Mapping[str, Any]) -> set[str]:
    """Модули, результаты которых нужны проверке (по её источникам)."""
    out: set[str] = set()
    for key, value in sources.items():
        if not value:
            continue
        if key == "vulns":
            mods = value.get("modules") if isinstance(value, Mapping) else None
            out.update(mods or ("vuln", "auth_inventory", "win_inventory"))
        else:
            out.update(SOURCE_MODULES.get(key, ()))
    return out


@dataclass(frozen=True)
class CoverageCell:
    status: str
    reason: str | None = None


Coverage = Mapping[str, Mapping[str, CoverageCell]]


@dataclass
class AutoResult:
    """Предложение статуса меры по одному снимку и его основания."""

    # implemented | partial | not_implemented | unassessed
    status: str
    # passed | failed_all | failed_some | not_checked | incomplete | absent
    reason: str
    note: str
    control_status: str | None
    hosts: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    # [{host, reason}] — хосты объекта, где проверку выполнить не удалось.
    unchecked: list[dict[str, str]] = field(default_factory=list)
    # Хосты, где проверка неприменима (не та ОС).
    not_applicable: list[str] = field(default_factory=list)
    # Провалы на хостах вне объекта — для сведения.
    outside_failed: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _plural(n: int, one: str, few: str, many: str) -> str:
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def hosts_word(n: int) -> str:
    return f"{n} {_plural(n, 'хост', 'хоста', 'хостов')}"


def _host_state(cells: Mapping[str, CoverageCell] | None, modules: set[str]) -> tuple[str, str]:
    """(checked | na | unchecked, причина)."""
    if cells is None:
        return "unchecked", "хост не входил в прогон"
    relevant = {m: c for m, c in cells.items() if not modules or m in modules}
    if any(c.status == "completed" for c in relevant.values()):
        return "checked", ""
    if relevant and all(c.status == "not_applicable" for c in relevant.values()):
        return "na", ""
    gaps = [(m, c) for m, c in relevant.items() if c.status != "not_applicable"]
    if not gaps:
        names = ", ".join(MODULE_LABELS.get(m, m) for m in sorted(modules)) or "нужные модули"
        return "unchecked", f"в прогоне не запускались: {names}"
    m, c = gaps[0]
    label = COVERAGE_LABELS.get(c.status, c.status)
    text = f"{MODULE_LABELS.get(m, m)}: {label}"
    return "unchecked", f"{text} ({c.reason})" if c.reason else text


def auto_status(
    control: Mapping[str, Any] | None,
    object_hosts: Sequence[str],
    coverage: Coverage,
    modules: Iterable[str],
) -> AutoResult:
    """Предложение статуса меры с проверками «Сканера» по одному прогону."""
    if control is None:
        return AutoResult(
            status="unassessed",
            reason="absent",
            note="Меры нет в результате прогона по профилю и классу объекта",
            control_status=None,
        )
    mods = set(modules)
    hosts = list(object_hosts) or sorted(coverage)
    in_object = set(hosts)
    failed_all = [fh["host"] for fh in control.get("failed_hosts") or ()]
    failed = [h for h in hosts if h in set(failed_all)]
    outside = [h for h in failed_all if h not in in_object]
    checked: list[str] = []
    na: list[str] = []
    unchecked: list[dict[str, str]] = []
    for h in hosts:
        if h in failed:
            checked.append(h)
            continue
        state, why = _host_state(coverage.get(h), mods)
        if state == "checked":
            checked.append(h)
        elif state == "na":
            na.append(h)
        else:
            unchecked.append({"host": h, "reason": why})
    base = {
        "control_status": str(control.get("status")),
        "hosts": hosts,
        "checked": checked,
        "failed": failed,
        "unchecked": unchecked,
        "not_applicable": na,
        "outside_failed": outside,
    }
    if failed:
        if len(failed) == len(checked):
            return AutoResult(
                status="not_implemented",
                reason="failed_all",
                note=f"Нарушения на всех проверенных хостах объекта ({hosts_word(len(failed))})",
                **base,
            )
        return AutoResult(
            status="partial",
            reason="failed_some",
            note=f"Нарушения на {len(failed)} из {hosts_word(len(checked))} объекта",
            **base,
        )
    if control.get("status") == "na" or not checked:
        return AutoResult(
            status="unassessed",
            reason="not_checked",
            note="«Сканер» не проверил меру ни на одном хосте объекта",
            **base,
        )
    if unchecked:
        return AutoResult(
            status="unassessed",
            reason="incomplete",
            note=(
                f"Нарушений нет на {len(checked)} из {hosts_word(len(checked) + len(unchecked))}"
                f", не проверено: {len(unchecked)} — без проверки отсутствие нарушений "
                "не засчитывается"
            ),
            **base,
        )
    return AutoResult(
        status="implemented",
        reason="passed",
        note=f"Нарушений нет, проверено {hosts_word(len(checked))} объекта",
        **base,
    )


def coverage_map(hosts: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, CoverageCell]]:
    """Покрытие из ответа `GET /runs/{id}/coverage` (hosts[].modules)."""
    out: dict[str, dict[str, CoverageCell]] = {}
    for h in hosts:
        out[str(h["host"])] = {
            m: CoverageCell(str(v.get("status")), v.get("reason"))
            for m, v in (h.get("modules") or {}).items()
        }
    return out
