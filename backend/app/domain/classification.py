"""Расчёт классификации по таблице-данным.

Код не содержит нормативных чисел: класс ГИС, уровень защищённости ПДн и
категория КИИ вычисляются только по определению таблицы (reference/classification/*.yaml,
затем ref_classification_tables). Определение:

    inputs: [{key, label, group?, help?, options: [{value, label, help?}]}]
    steps:  [{key, label, method, ...}]
        method=first_match: rows: [{id, when: {поле: [значения]}, value, source?, note?}]
            — первая строка, у которой все условия выполнены; пустой when — «иначе».
        method=max: fields: [поля], order: [значения от строгого к мягкому]
            — наиболее строгое значение среди полей.
    result: {key, label, values: [{value, label}]}

Расчёт детерминирован и воспроизводим: тот же снимок определения + те же
исходные данные дают тот же результат и ту же трассу (какая строка сработала).
"""

from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import dataclass, field
from typing import Any

METHODS = {"first_match", "max"}


class TableError(ValueError):
    """Определение таблицы некорректно."""


class InputError(ValueError):
    """Исходные данные не подходят к таблице."""


@dataclass
class StepTrace:
    key: str
    label: str
    method: str
    value: str
    row_id: str | None = None
    # Условия сработавшей строки / поля, давшие наиболее строгое значение.
    matched: dict[str, Any] = field(default_factory=dict)
    source: dict[str, Any] | None = None
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "method": self.method,
            "value": self.value,
            "row_id": self.row_id,
            "matched": self.matched,
            "source": self.source,
            "note": self.note,
        }


@dataclass
class Outcome:
    result: str
    result_label: str
    values: dict[str, str]
    trace: list[StepTrace]

    def as_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "result_label": self.result_label,
            "values": self.values,
            "trace": [t.as_dict() for t in self.trace],
        }


def definition_hash(definition: dict[str, Any]) -> str:
    """Отпечаток определения: по нему видно, что таблица менялась."""
    raw = json.dumps(definition, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _options(inp: dict[str, Any]) -> list[str]:
    return [str(o["value"]) for o in inp.get("options") or []]


def validate(definition: dict[str, Any]) -> None:
    """Проверяет определение; при ошибке — TableError с текстом на русском."""
    inputs = definition.get("inputs")
    steps = definition.get("steps")
    result = definition.get("result")
    if not isinstance(inputs, list) or not inputs:
        raise TableError("В таблице нет исходных данных (inputs)")
    if not isinstance(steps, list) or not steps:
        raise TableError("В таблице нет шагов расчёта (steps)")
    if not isinstance(result, dict) or not result.get("key"):
        raise TableError("Не указан итог таблицы (result.key)")

    domains: dict[str, set[str]] = {}
    for inp in inputs:
        key = inp.get("key")
        if not key or key in domains:
            raise TableError(f"Поле исходных данных без ключа или повторяется: {key!r}")
        opts = _options(inp)
        if not opts or len(opts) != len(set(opts)):
            raise TableError(f"У поля «{key}» нет вариантов или они повторяются")
        domains[key] = set(opts)

    for step in steps:
        key = step.get("key")
        method = step.get("method")
        if not key or key in domains:
            raise TableError(f"Шаг без ключа или ключ занят: {key!r}")
        if method not in METHODS:
            raise TableError(f"Шаг «{key}»: неизвестный способ расчёта {method!r}")
        produced: set[str] = set()
        if method == "first_match":
            rows = step.get("rows") or []
            if not rows:
                raise TableError(f"Шаг «{key}»: нет строк")
            ids = [r.get("id") for r in rows]
            if not all(ids) or len(ids) != len(set(ids)):
                raise TableError(f"Шаг «{key}»: у строк нет id или они повторяются")
            for r in rows:
                when = r.get("when") or {}
                if not isinstance(when, dict):
                    raise TableError(f"Строка «{r['id']}»: условие должно быть словарём")
                for f, allowed in when.items():
                    if f not in domains:
                        raise TableError(f"Строка «{r['id']}»: неизвестное поле «{f}»")
                    vals = allowed if isinstance(allowed, list) else [allowed]
                    if bad := {str(v) for v in vals} - domains[f]:
                        raise TableError(
                            f"Строка «{r['id']}»: у поля «{f}» нет значения "
                            f"{', '.join(sorted(bad))}"
                        )
                if r.get("value") in (None, ""):
                    raise TableError(f"Строка «{r['id']}»: не указано значение")
                produced.add(str(r["value"]))
        else:
            fields = step.get("fields") or []
            order = [str(v) for v in step.get("order") or []]
            if not fields or not order:
                raise TableError(f"Шаг «{key}»: нужны fields и order")
            for f in fields:
                if f not in domains:
                    raise TableError(f"Шаг «{key}»: неизвестное поле «{f}»")
                if bad := domains[f] - set(order):
                    raise TableError(
                        f"Шаг «{key}»: значения поля «{f}» не упорядочены: {', '.join(sorted(bad))}"
                    )
            produced = set(order)
        declared = {str(v["value"]) for v in step.get("values") or []}
        domains[key] = declared | produced

    rkey = result["key"]
    if rkey != steps[-1]["key"]:
        raise TableError("Итог таблицы должен быть значением последнего шага")
    allowed = {str(v["value"]) for v in result.get("values") or []}
    if not allowed:
        raise TableError("Не перечислены допустимые итоговые значения")
    if bad := domains[rkey] - allowed:
        raise TableError(f"Шаг «{rkey}» даёт значения вне итога: {', '.join(sorted(bad))}")


def _label(values: list[dict[str, Any]] | None, value: str) -> str:
    for v in values or []:
        if str(v["value"]) == value:
            return str(v.get("label") or value)
    return value


def compute(definition: dict[str, Any], inputs: dict[str, Any]) -> Outcome:
    """Вычисляет итог. Все поля inputs обязательны и должны быть из вариантов таблицы."""
    known: dict[str, str] = {}
    for inp in definition["inputs"]:
        key = inp["key"]
        raw = inputs.get(key)
        if raw is None or raw == "":
            raise InputError(f"Не заполнено: {inp.get('label') or key}")
        if str(raw) not in _options(inp):
            raise InputError(f"Недопустимое значение для «{inp.get('label') or key}»")
        known[key] = str(raw)
    if extra := set(inputs) - set(known):
        raise InputError(f"Лишние поля: {', '.join(sorted(extra))}")

    values = dict(known)
    trace: list[StepTrace] = []
    for step in definition["steps"]:
        key, method = step["key"], step["method"]
        label = step.get("label") or key
        if method == "first_match":
            for row in step["rows"]:
                when = row.get("when") or {}
                ok = all(
                    values.get(f) in {str(v) for v in (a if isinstance(a, list) else [a])}
                    for f, a in when.items()
                )
                if ok:
                    t = StepTrace(
                        key=key,
                        label=label,
                        method=method,
                        value=str(row["value"]),
                        row_id=row["id"],
                        matched={f: values[f] for f in when},
                        source=row.get("source") or step.get("source"),
                        note=row.get("note"),
                    )
                    break
            else:
                raise InputError(
                    f"Шаг «{label}»: ни одна строка таблицы не подходит — таблица неполна"
                )
        else:
            order = [str(v) for v in step["order"]]
            got = {f: values[f] for f in step["fields"]}
            best = min(got.values(), key=order.index)
            t = StepTrace(
                key=key,
                label=label,
                method=method,
                value=best,
                matched={f: v for f, v in got.items() if v == best},
                source=step.get("source"),
                note=step.get("note"),
            )
        values[key] = t.value
        trace.append(t)

    result = definition["result"]
    final = values[result["key"]]
    return Outcome(
        result=final,
        result_label=_label(result.get("values"), final),
        values={k: v for k, v in values.items() if k not in known},
        trace=trace,
    )


def input_space(definition: dict[str, Any]) -> list[dict[str, str]]:
    """Все сочетания исходных данных — для проверки полноты таблицы."""
    keys = [i["key"] for i in definition["inputs"]]
    opts = [_options(i) for i in definition["inputs"]]
    return [dict(zip(keys, combo, strict=True)) for combo in itertools.product(*opts)]


def gaps(definition: dict[str, Any], limit: int = 20) -> list[dict[str, str]]:
    """Сочетания, на которых таблица не даёт результата (пусто — таблица полна)."""
    out = []
    for combo in input_space(definition):
        try:
            compute(definition, combo)
        except InputError:
            out.append(combo)
            if len(out) >= limit:
                break
    return out
