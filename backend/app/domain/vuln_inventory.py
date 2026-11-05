"""Данные инвентаризации объекта для показателя I_infr (Методика 2025, п. 14, 15).

У каждого хоста объекта — тип компонента (значения показателя K таблицы 1) и
признак доступности из сети «Интернет» (показатель P). По ним для набора
уязвимых хостов определяются значения показателей:

- K — типы уязвимых хостов, итог — наибольшее (п. 15);
- L — по каждому типу уязвимых хостов: доля уязвимых хостов этого типа от всех
  хостов этого типа в объекте (так в примере 2 приложения), доля переводится в
  полосу таблицы 1; итог — наибольшее;
- P — «доступно», если доступен из сети «Интернет» хотя бы один уязвимый хост,
  иначе «недоступно».

Какой показатель за что отвечает, задаёт справочник (поле inventory), а не код:
в коде нет ни кодов значений, ни чисел Методики. Если данных не хватает,
результат перечисляет, чего именно и у каких хостов, и значение показателя не
определяется.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from fractions import Fraction
from typing import Any

from app.domain.vuln_criticality import InputError, MethodologyError, fmt, indicator_row


@dataclass(frozen=True)
class HostData:
    address: str
    hostname: str | None
    component_types: tuple[str, ...]  # пусто — тип не указан
    internet_exposed: bool | None  # None — не указано


def roles(definition: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Показатели справочника по источнику: component_type, vulnerable_share, internet."""
    return {i["inventory"]: i for i in definition.get("indicators") or [] if i.get("inventory")}


def require_roles(definition: dict[str, Any]) -> dict[str, dict[str, Any]]:
    r = roles(definition)
    if missing := [k for k in ("component_type", "vulnerable_share", "internet") if k not in r]:
        raise MethodologyError(
            "в справочнике Методики не указано, какой показатель берётся из инвентаризации: "
            + ", ".join(missing)
        )
    return r


def component_types(definition: dict[str, Any]) -> list[dict[str, Any]]:
    """Типы компонентов в порядке таблицы 1: code, short, title, score."""
    ind = require_roles(definition)["component_type"]
    return [
        {"code": v["code"], "short": v["short"], "title": v["title"], "score": v["score"]}
        for v in ind["values"]
    ]


def normalize_types(definition: dict[str, Any], codes: list[str] | None) -> list[str] | None:
    """Проверяет коды типов и упорядочивает их по таблице; пусто → None."""
    if not codes:
        return None
    order = [t["code"] for t in component_types(definition)]
    if unknown := [c for c in codes if c not in order]:
        raise InputError(f"неизвестный тип компонента: {', '.join(unknown[:5])}")
    return sorted(set(codes), key=order.index)


def _in_band(share: Fraction, v: dict[str, Any]) -> bool:
    lo, hi = v.get("share_min"), v.get("share_max")
    if lo is not None:
        lo_f = Fraction(Decimal(str(lo)))
        if share < lo_f or (share == lo_f and not v.get("share_min_inclusive")):
            return False
    if hi is not None:
        hi_f = Fraction(Decimal(str(hi)))
        if share > hi_f or (share == hi_f and not v.get("share_max_inclusive")):
            return False
    return True


def share_band(definition: dict[str, Any], share: Fraction) -> dict[str, Any]:
    """Значение показателя L для доли в процентах (точная дробь, без округления)."""
    ind = require_roles(definition)["vulnerable_share"]
    for v in ind["values"]:
        if _in_band(share, v):
            return v
    raise MethodologyError(
        f"доля {float(share):.2f} % не попадает ни в одну полосу"
    )  # pragma: no cover


def _pct(share: Fraction) -> str:
    d = Decimal(share.numerator) / Decimal(share.denominator)
    return fmt(d.quantize(Decimal("0.01")))


@dataclass
class Readiness:
    hosts_total: int
    missing_type: list[str]
    missing_internet: list[str]
    # По типам: code, short, title, total, internet (сколько доступны из «Интернета»).
    by_type: list[dict[str, Any]]

    @property
    def ready(self) -> bool:
        return self.hosts_total > 0 and not self.missing_type and not self.missing_internet


def readiness(definition: dict[str, Any], hosts: list[HostData]) -> Readiness:
    types = component_types(definition)
    by_type = []
    for t in types:
        of_type = [h for h in hosts if t["code"] in h.component_types]
        by_type.append(
            {
                **t,
                "total": len(of_type),
                "internet": sum(1 for h in of_type if h.internet_exposed),
            }
        )
    return Readiness(
        hosts_total=len(hosts),
        missing_type=[h.address for h in hosts if not h.component_types],
        missing_internet=[h.address for h in hosts if h.internet_exposed is None],
        by_type=by_type,
    )


@dataclass
class Infrastructure:
    """Значения K, L, P для набора уязвимых хостов и I_infr, если всё определено."""

    inputs: dict[str, list[str]]  # код показателя → коды значений (только определённые)
    missing: list[dict[str, Any]]  # indicator, text, addresses
    by_type: list[dict[str, Any]]  # тип: total, vulnerable, share, band
    exposed: list[str]  # уязвимые хосты, доступные из «Интернета»
    i_infr: str | None = None
    trace: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "inputs": self.inputs,
            "missing": self.missing,
            "by_type": self.by_type,
            "exposed": self.exposed,
            "i_infr": self.i_infr,
            "trace": self.trace,
            "complete": not self.missing,
        }


def infrastructure(
    definition: dict[str, Any], hosts: list[HostData], vulnerable: list[str]
) -> Infrastructure:
    """K, L, P и I_infr для уязвимых хостов `vulnerable` (адреса из `hosts`)."""
    r = require_roles(definition)
    k_ind, l_ind, p_ind = r["component_type"], r["vulnerable_share"], r["internet"]
    by_address = {h.address: h for h in hosts}
    wanted = list(dict.fromkeys(vulnerable))
    if not wanted:
        raise InputError("не выбраны уязвимые хосты")
    if unknown := [a for a in wanted if a not in by_address]:
        raise InputError(f"нет в составе объекта: {', '.join(unknown[:5])}")
    vuln = [by_address[a] for a in wanted]
    types = {t["code"]: t for t in component_types(definition)}
    missing: list[dict[str, Any]] = []
    inputs: dict[str, list[str]] = {}

    # K — типы уязвимых хостов.
    no_type_vuln = [h.address for h in vuln if not h.component_types]
    if no_type_vuln:
        missing.append(
            {
                "indicator": k_ind["code"],
                "text": "не указан тип компонента у уязвимых хостов",
                "addresses": no_type_vuln,
            }
        )
    vuln_types = [c for c in types if any(c in h.component_types for h in vuln)]
    if not no_type_vuln:
        inputs[k_ind["code"]] = vuln_types

    # L — доля уязвимых по каждому типу; знаменатель — все хосты объекта этого типа,
    # поэтому тип нужен у всех хостов, а не только у уязвимых.
    no_type_any = [h.address for h in hosts if not h.component_types]
    by_type: list[dict[str, Any]] = []
    for code in vuln_types:
        total = sum(1 for h in hosts if code in h.component_types)
        hit = sum(1 for h in vuln if code in h.component_types)
        share = Fraction(100 * hit, total)
        row: dict[str, Any] = {
            "code": code,
            "short": types[code]["short"],
            "title": types[code]["title"],
            "total": total,
            "vulnerable": hit,
            "share": _pct(share),
            "band": None,
            "band_title": None,
        }
        if not no_type_any:
            band = share_band(definition, share)
            row["band"], row["band_title"] = band["code"], band["title"]
        by_type.append(row)
    if no_type_any:
        missing.append(
            {
                "indicator": l_ind["code"],
                "text": "не указан тип компонента: без него неизвестно общее число "
                "компонентов каждого типа",
                "addresses": no_type_any,
            }
        )
    elif not no_type_vuln:
        inputs[l_ind["code"]] = list(dict.fromkeys(row["band"] for row in by_type))

    # P — доступность из «Интернета».
    exposed = [h.address for h in vuln if h.internet_exposed]
    unknown_net = [h.address for h in vuln if h.internet_exposed is None]
    p_values = {bool(v["internet"]): v["code"] for v in p_ind["values"]}
    if exposed:
        inputs[p_ind["code"]] = [p_values[True]]
    elif unknown_net:
        missing.append(
            {
                "indicator": p_ind["code"],
                "text": "не указано, доступны ли уязвимые хосты из сети «Интернет»",
                "addresses": unknown_net,
            }
        )
    else:
        inputs[p_ind["code"]] = [p_values[False]]

    out = Infrastructure(inputs=inputs, missing=missing, by_type=by_type, exposed=exposed)
    if not missing:
        total = Decimal(0)
        for ind in definition["indicators"]:
            if ind["group"] != "infr":
                continue
            if ind["code"] not in inputs:
                # Показатель I_infr, которого нет в инвентаризации: считать здесь нечем.
                missing.append(
                    {
                        "indicator": ind["code"],
                        "text": f"показатель {ind['code']} не берётся из инвентаризации",
                        "addresses": [],
                    }
                )
                continue
            product, row = indicator_row(ind, inputs[ind["code"]])
            total += product
            out.trace.append(row)
        if not missing:
            out.i_infr = fmt(total)
    return out
