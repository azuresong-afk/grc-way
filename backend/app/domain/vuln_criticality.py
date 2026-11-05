"""Методика оценки уровня критичности уязвимостей (ФСТЭК России, 30.06.2025).

Справочник (reference/vuln-criticality/*.yaml) — данные: показатели таблицы 1 с
весами и значениями, уровни таблицы 2 со сроками п. 21, компенсирующие меры
п. 25, правило п. 4 для сертифицированных СЗИ, контрольные примеры приложения.
Код не содержит чисел Методики: он собирает формулу п. 12

    V = I_cvss × I_infr × (I_at + I_imp),

где каждая группа (I_infr, I_at, I_imp) — сумма «вес × значение» её показателей
(п. 14, 16, 17), а уровень — строка таблицы 2, в границы которой попало V.

Арифметика — Decimal: 8,8 × 0,9 × 0,6 = 4,752 ровно, без ошибок float.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

GROUPS = ("infr", "at", "imp")
DEADLINE_UNITS = ("hours", "days", "weeks", "months")
MULTIPLE = ("max", "single")


class MethodologyError(ValueError):
    """Справочник Методики нарушает правила."""


class InputError(ValueError):
    """Исходные данные расчёта неполны или неверны."""


def definition_hash(definition: dict[str, Any]) -> str:
    raw = json.dumps(definition, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _dec(value: Any, what: str) -> Decimal:
    if isinstance(value, bool) or value is None:
        raise MethodologyError(f"{what}: нужно число")
    try:
        d = Decimal(str(value).replace(",", "."))
    except InvalidOperation as e:
        raise MethodologyError(f"{what}: «{value}» — не число") from e
    if not d.is_finite():
        raise MethodologyError(f"{what}: нужно конечное число")
    return d


def fmt(d: Decimal) -> str:
    """Число без лишних нулей: 0.50 → 0.5, 1.0 → 1."""
    s = format(d.normalize(), "f")
    return s


# ---------- Проверка справочника ----------


def _check_levels(levels: list[dict[str, Any]]) -> None:
    if not levels:
        raise MethodologyError("не заданы уровни критичности (таблица 2)")
    codes: set[str] = set()
    for lv in levels:
        code = lv.get("code")
        if not code or not (lv.get("title") or "").strip():
            raise MethodologyError("у уровня критичности нет кода или наименования")
        if code in codes:
            raise MethodologyError(f"уровень {code}: код повторяется")
        codes.add(code)
        for k in ("min", "max"):
            if lv.get(k) is not None:
                _dec(lv[k], f"уровень {code}, {k}")
        dl = lv.get("deadline") or {}
        if dl.get("unit") not in DEADLINE_UNITS:
            raise MethodologyError(f"уровень {code}: срок — часы, дни, недели или месяцы")
        if _dec(dl.get("value"), f"уровень {code}, срок") <= 0:
            raise MethodologyError(f"уровень {code}: срок должен быть больше нуля")

    _check_axis(levels, what="уровни", prefix="")


def _check_axis(items: list[dict[str, Any]], *, what: str, prefix: str) -> None:
    """Полосы покрывают всю ось без разрывов и наложений: снизу вверх каждая
    граница принадлежит ровно одной полосе. Ключи — {prefix}min, {prefix}max,
    {prefix}min_inclusive, {prefix}max_inclusive."""
    lo_k, hi_k = f"{prefix}min", f"{prefix}max"

    def lower(lv: dict[str, Any]) -> Decimal:
        return Decimal("-Infinity") if lv.get(lo_k) is None else _dec(lv[lo_k], lo_k)

    ordered = sorted(items, key=lower)
    if ordered[0].get(lo_k) is not None:
        raise MethodologyError(
            f"{what}: у нижней полосы {ordered[0]['code']} не должно быть {lo_k}"
        )
    if ordered[-1].get(hi_k) is not None:
        raise MethodologyError(
            f"{what}: у верхней полосы {ordered[-1]['code']} не должно быть {hi_k}"
        )
    for a, b in itertools.pairwise(ordered):
        if a.get(hi_k) is None or b.get(lo_k) is None:
            raise MethodologyError(f"{what}: {a['code']} и {b['code']} перекрываются")
        if _dec(a[hi_k], hi_k) != _dec(b[lo_k], lo_k):
            raise MethodologyError(f"{what}: между {a['code']} и {b['code']} разрыв или наложение")
        if bool(a.get(f"{hi_k}_inclusive")) == bool(b.get(f"{lo_k}_inclusive")):
            raise MethodologyError(
                f"{what}: граница {fmt(_dec(a[hi_k], hi_k))} должна относиться ровно к одному "
                f"из интервалов {a['code']} и {b['code']}"
            )


# Откуда значение показателя берётся у объекта (задача 2.7).
INVENTORY = ("component_type", "vulnerable_share", "internet")


def _check_inventory(indicators: list[dict[str, Any]]) -> None:
    seen: dict[str, str] = {}
    for ind in indicators:
        role = ind.get("inventory")
        if role is None:
            continue
        code = ind["code"]
        if role not in INVENTORY:
            raise MethodologyError(f"показатель {code}: неизвестный источник «{role}»")
        if role in seen:
            raise MethodologyError(
                f"показатели {seen[role]} и {code}: один источник инвентаризации у двух показателей"
            )
        seen[role] = code
        values = ind["values"]
        if role == "component_type":
            for v in values:
                if not (v.get("short") or "").strip():
                    raise MethodologyError(f"значение {v['code']}: нет короткой подписи типа")
        elif role == "vulnerable_share":
            for v in values:
                for k in ("share_min", "share_max"):
                    if v.get(k) is not None and not 0 <= _dec(v[k], f"{v['code']}, {k}") <= 100:
                        raise MethodologyError(f"значение {v['code']}: доля от 0 до 100 %")
            _check_axis(values, what=f"полосы доли показателя {code}", prefix="share_")
        else:
            flags = [v.get("internet") for v in values]
            if sorted(flags, key=str) != [False, True]:
                raise MethodologyError(
                    f"показатель {code}: нужны ровно два значения — доступно и недоступно из "
                    "сети «Интернет»"
                )


def validate(definition: dict[str, Any]) -> None:
    """Проверяет справочник целиком; при ошибке — MethodologyError с понятным текстом."""
    groups = {g.get("code") for g in definition.get("groups") or []}
    if groups != set(GROUPS):
        raise MethodologyError("группы показателей должны быть ровно I_infr, I_at и I_imp")
    indicators = definition.get("indicators") or []
    seen: set[str] = set()
    value_codes: set[str] = set()
    for ind in indicators:
        code = ind.get("code")
        if not code:
            raise MethodologyError("у показателя нет кода")
        if code in seen or code == "cvss":
            raise MethodologyError(f"показатель {code}: код повторяется")
        seen.add(code)
        if ind.get("group") not in GROUPS:
            raise MethodologyError(f"показатель {code}: неизвестная группа «{ind.get('group')}»")
        if ind.get("multiple", "single") not in MULTIPLE:
            raise MethodologyError(f"показатель {code}: multiple — max или single")
        if _dec(ind.get("weight"), f"показатель {code}, весовой коэффициент") < 0:
            raise MethodologyError(
                f"показатель {code}: весовой коэффициент не может быть меньше нуля"
            )
        values = ind.get("values") or []
        if not values:
            raise MethodologyError(f"показатель {code}: нет значений")
        for v in values:
            vc = v.get("code")
            if not vc or not (v.get("title") or "").strip():
                raise MethodologyError(f"показатель {code}: у значения нет кода или наименования")
            if vc in value_codes:
                raise MethodologyError(f"значение {vc}: код повторяется")
            value_codes.add(vc)
            if _dec(v.get("score"), f"значение {vc}") < 0:
                raise MethodologyError(f"значение {vc}: оценка не может быть меньше нуля")
    _check_inventory(indicators)
    for g in GROUPS:
        if not any(i.get("group") == g for i in indicators):
            raise MethodologyError(f"в группе {g} нет показателей")
    _check_levels(definition.get("levels") or [])
    level_codes = {lv["code"] for lv in definition["levels"]}
    szi = (definition.get("certified_szi") or {}).get("level")
    if szi is not None and szi not in level_codes:
        raise MethodologyError(f"п. 4: неизвестный уровень «{szi}»")
    digits = (definition.get("rounding") or {}).get("digits", 2)
    if not isinstance(digits, int) or not 0 <= digits <= 6:
        raise MethodologyError("округление: число знаков от 0 до 6")
    # Контрольные примеры приложения должны воспроизводиться.
    for ex in definition.get("examples") or []:
        try:
            out = compute(definition, ex.get("inputs") or {}, _validated=True)
        except InputError as e:
            raise MethodologyError(f"{ex.get('code')}: {e}") from e
        want = ex.get("expected") or {}
        got = {"v": out.v, "level": out.level["code"], "i_infr": out.groups["infr"]}
        for k, expected in want.items():
            actual = got.get(k)
            same = (
                actual == expected
                if k == "level"
                else actual is not None and _dec(actual, k) == _dec(expected, k)
            )
            if not same:
                raise MethodologyError(
                    f"{ex.get('title') or ex.get('code')}: ожидалось {k} = {expected}, "
                    f"получилось {actual}"
                )


# ---------- Расчёт ----------


@dataclass
class Outcome:
    v: str  # округлённое значение V
    v_exact: str  # без округления
    level: dict[str, Any]  # code, title, condition, deadline, source
    groups: dict[str, str]  # infr / at / imp
    cvss: str
    trace: list[dict[str, Any]] = field(default_factory=list)
    certified_szi: bool = False
    # Уровень по V до правила п. 4 (если правило сработало).
    level_by_v: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "v_exact": self.v_exact,
            "level": self.level,
            "level_by_v": self.level_by_v,
            "groups": self.groups,
            "cvss": self.cvss,
            "certified_szi": self.certified_szi,
            "trace": self.trace,
        }


def _in_level(v: Decimal, lv: dict[str, Any]) -> bool:
    if lv.get("min") is not None:
        lo = _dec(lv["min"], "min")
        if v < lo or (v == lo and not lv.get("min_inclusive")):
            return False
    if lv.get("max") is not None:
        hi = _dec(lv["max"], "max")
        if v > hi or (v == hi and not lv.get("max_inclusive")):
            return False
    return True


def level_for(definition: dict[str, Any], v: Decimal) -> dict[str, Any]:
    for lv in definition["levels"]:
        if _in_level(v, lv):
            return lv
    raise MethodologyError(f"значение {v} не попадает ни в один уровень")  # pragma: no cover


def _level_out(lv: dict[str, Any]) -> dict[str, Any]:
    return {k: lv.get(k) for k in ("code", "title", "condition", "deadline", "source")}


def indicator_row(ind: dict[str, Any], raw: Any) -> tuple[Decimal, dict[str, Any]]:
    """«Вес × значение» одного показателя и строка «как посчитано».

    raw — код значения или список кодов (у показателя с multiple: max берётся
    наибольшее; при равенстве — первое по порядку таблицы)."""
    code = ind["code"]
    chosen = [raw] if isinstance(raw, str) else list(raw or [])
    if not chosen:
        raise InputError(f"не выбрано значение показателя {code} — {ind['title']}")
    by_code = {v["code"]: v for v in ind["values"]}
    if unknown := [c for c in chosen if c not in by_code]:
        raise InputError(f"показатель {code}: неизвестные значения {', '.join(unknown)}")
    chosen = list(dict.fromkeys(chosen))
    if len(chosen) > 1 and ind.get("multiple", "single") != "max":
        raise InputError(f"показатель {code} принимает одно значение")
    order = [v["code"] for v in ind["values"]]
    picked = max(
        (by_code[c] for c in chosen),
        key=lambda v: (_dec(v["score"], v["code"]), -order.index(v["code"])),
    )
    weight = _dec(ind["weight"], code)
    score = _dec(picked["score"], picked["code"])
    product = weight * score
    return product, {
        "indicator": code,
        "group": ind["group"],
        "title": ind["title"],
        "weight_symbol": ind.get("weight_symbol"),
        "weight": fmt(weight),
        "chosen": [
            {"code": c, "title": by_code[c]["title"], "score": fmt(_dec(by_code[c]["score"], c))}
            for c in chosen
        ],
        "value": picked["code"],
        "value_title": picked["title"],
        "score": fmt(score),
        "product": fmt(product),
        "rule": "наибольшее из значений" if len(chosen) > 1 else None,
        "source": ind.get("source") or {},
    }


def compute(
    definition: dict[str, Any], inputs: dict[str, Any], *, _validated: bool = False
) -> Outcome:
    """Расчёт V по п. 12–18.

    inputs: cvss — базовая оценка (строка или число, 0–10); по каждому показателю —
    список кодов значений (у показателя с multiple: max — один или несколько, берётся
    наибольшее; иначе ровно один); certified_szi — уязвимость в сертифицированном
    СЗИ (п. 4).
    """
    if not _validated:
        validate(definition)
    cvss_ref = definition.get("cvss") or {}
    try:
        cvss = Decimal(str(inputs.get("cvss", "")).replace(",", "."))
    except InvalidOperation as e:
        raise InputError("не указана базовая оценка CVSS") from e
    if not cvss.is_finite():
        raise InputError("не указана базовая оценка CVSS")
    lo, hi = _dec(cvss_ref.get("min", 0), "cvss.min"), _dec(cvss_ref.get("max", 10), "cvss.max")
    if not lo <= cvss <= hi:
        raise InputError(f"оценка CVSS должна быть от {fmt(lo)} до {fmt(hi)}")

    known = {i["code"] for i in definition["indicators"]}
    if extra := set(inputs) - known - {"cvss", "certified_szi"}:
        raise InputError(f"неизвестные показатели: {', '.join(sorted(extra))}")

    sums = {g: Decimal(0) for g in GROUPS}
    trace: list[dict[str, Any]] = [
        {
            "indicator": "cvss",
            "title": f"Уровень опасности уязвимости по CVSS {cvss_ref.get('version', '')}".strip(),
            "score": fmt(cvss),
            "source": cvss_ref.get("source") or {},
        }
    ]
    for ind in definition["indicators"]:
        product, row = indicator_row(ind, inputs.get(ind["code"]))
        sums[ind["group"]] += product
        trace.append(row)

    exact = cvss * sums["infr"] * (sums["at"] + sums["imp"])
    digits = (definition.get("rounding") or {}).get("digits", 2)
    rounded = exact.quantize(Decimal(1).scaleb(-digits), rounding=ROUND_HALF_UP)
    by_v = level_for(definition, rounded)
    certified = bool(inputs.get("certified_szi"))
    level = by_v
    szi_rule = definition.get("certified_szi") or {}
    if certified and szi_rule.get("level"):
        level = next(lv for lv in definition["levels"] if lv["code"] == szi_rule["level"])
    return Outcome(
        v=format(rounded, "f"),
        v_exact=fmt(exact),
        level=_level_out(level),
        level_by_v=by_v["code"] if level is not by_v else None,
        groups={g: fmt(s) for g, s in sums.items()},
        cvss=fmt(cvss),
        trace=trace,
        certified_szi=certified,
    )
