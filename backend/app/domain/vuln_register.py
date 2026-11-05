"""Реестр уязвимостей объекта: оценка критичности по Методике 2025 (задача 2.8).

Запись реестра — одна уязвимость на объекте: уязвимость БДУ (одна запись на
идентификатор БДУ, сколько бы хостов и находок «Сканера» её ни показали) или
уязвимость без идентификатора, внесённая специалистом по результатам контроля
защищённости (тестирование на проникновение, учения — п. 8 «г»).

Откуда берётся каждый показатель формулы п. 12:

- I_cvss — базовая оценка CVSS 3.1 из БДУ (п. 13). Если её нет, версию и оценку
  выбирает специалист (CVSS 2.0 / 3.0 / 4.0 из БДУ, оценка «Сканера» или своя),
  и расчёт помечается: «версия CVSS выбрана специалистом».
- K, L, P — из инвентаризации объекта по уязвимым хостам (задача 2.7); у K и L
  при нескольких значениях — наибольшее (п. 15, пример 2).
- E — предлагается по сведениям БДУ об эксплуатации (п. 16); специалист может
  добавить значение по своим сведениям, итог — наибольшее из значений, поэтому
  выбор специалиста не может понизить то, что известно из БДУ.
- H — выбор специалиста из последствий таблицы 1, итог — наибольшее (п. 17).
- п. 4 — отметка «уязвимость в сертифицированном СЗИ».

Оценка — неизменяемая запись истории: повторный расчёт добавляет новую оценку и
не затирает прежнюю. Оценка устаревает, если с её момента изменилось что-то из
исходных данных (хосты в снимке, сведения БДУ, инвентаризация, выбор
специалиста, справочник Методики) или БДУ отметила изменение полей, влияющих на
критичность (флаг задачи 2.2, п. 16 и 19).

Срок устранения (п. 21) отсчитывается «с момента проведения такой оценки»:
от оценки, которая присвоила уровень. Пересчёт с тем же уровнем срок не
продлевает — сохраняется срок прежней оценки; новый уровень — новый срок от
момента пересчёта.
"""

from __future__ import annotations

import calendar
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from app.domain.vuln_criticality import InputError, compute, fmt
from app.domain.vuln_inventory import HostData, infrastructure

# Версии CVSS, которые специалист может выбрать, если оценки CVSS 3.1 нет (п. 13).
CVSS_VERSIONS = ("2.0", "3.0", "3.1", "4.0")
# Откуда специалист взял оценку.
CVSS_SOURCES = {
    "bdu": "БДУ ФСТЭК России",
    "scanner": "«Сканер»",
    "vendor": "сведения разработчика",
    "other_db": "иная база уязвимостей",
    "manual": "расчёт специалиста",
}
# Результаты контроля защищённости (п. 8 «г»).
MANUAL_SOURCES = {
    "pentest": "Тестирование на проникновение",
    "exercise": "Учения (тренировки)",
    "experiment": "Эксперимент по повышению защищённости (ПП № 372)",
    "other": "Иной контроль защищённости",
}
TRIGGERS = {
    "choices": "выбор специалиста",
    "manual": "пересчёт специалистом",
    "snapshot": "новый снимок «Сканера»",
    "bdu": "загрузка выгрузки БДУ",
    "recalc": "пересчёт реестра",
}


@dataclass(frozen=True)
class BduInfo:
    bdu_id: str
    title: str
    cvss3_score: float | None
    cvss3_version: str | None
    cvss3_vector: str | None
    cvss_other: dict[str, Any] | None
    exploit: str | None
    in_wild: str | None
    exploit_raw: str | None
    in_wild_raw: str | None
    e_level: str  # in_wild | exploit | none — app.domain.bdu.e_level
    withdrawn: bool = False
    criticality_changed_at: datetime | None = None


@dataclass
class Choices:
    """Выбор специалиста: CVSS (если в БДУ нет 3.1), E, H, отметка п. 4."""

    cvss: dict[str, Any] | None = None  # {version, score, source, note}
    e: list[str] = field(default_factory=list)
    h: list[str] = field(default_factory=list)
    certified_szi: bool = False


def _dec(raw: Any) -> Decimal | None:
    if raw is None or isinstance(raw, bool):
        return None
    try:
        d = Decimal(str(raw).replace(",", "."))
    except InvalidOperation:
        return None
    return d if d.is_finite() else None


def check_cvss_choice(raw: dict[str, Any] | None) -> dict[str, Any] | None:
    """Проверяет выбор CVSS специалистом; возвращает нормализованный словарь."""
    if not raw:
        return None
    version = str(raw.get("version") or "").strip()
    if version not in CVSS_VERSIONS:
        raise InputError("версия CVSS — 2.0, 3.0, 3.1 или 4.0")
    score = _dec(raw.get("score"))
    if score is None or not Decimal(0) <= score <= Decimal(10):
        raise InputError("оценка CVSS — число от 0 до 10")
    source = raw.get("source") or "manual"
    if source not in CVSS_SOURCES:
        raise InputError("неизвестный источник оценки CVSS")
    note = (raw.get("note") or "").strip() or None
    vector = (raw.get("vector") or "").strip() or None
    if (note and len(note) > 1000) or (vector and len(vector) > 200):
        raise InputError("слишком длинный комментарий или вектор CVSS")
    return {
        "version": version,
        "score": fmt(score),
        "source": source,
        "vector": vector,
        "note": note,
    }


def cvss_options(bdu: BduInfo | None, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Оценки, из которых специалист может выбрать, если в БДУ нет CVSS 3.1."""
    out: list[dict[str, Any]] = []
    if bdu is not None:
        if bdu.cvss3_score is not None:
            out.append(
                {
                    "version": bdu.cvss3_version or "3.0",
                    "score": fmt(Decimal(str(bdu.cvss3_score))),
                    "vector": bdu.cvss3_vector,
                    "source": "bdu",
                    "title": f"БДУ, CVSS {bdu.cvss3_version or '3.x'}",
                }
            )
        for key, version in (("cvss4", "4.0"), ("cvss2", "2.0")):
            item = (bdu.cvss_other or {}).get(key) or {}
            if item.get("score") is not None:
                out.append(
                    {
                        "version": version,
                        "score": fmt(Decimal(str(item["score"]))),
                        "vector": item.get("vector"),
                        "source": "bdu",
                        "title": f"БДУ, CVSS {version}",
                    }
                )
    scores = sorted({Decimal(str(f["cvss"])) for f in findings if f.get("cvss") is not None})
    if scores:
        out.append(
            {
                "version": None,
                "score": fmt(scores[-1]),
                "vector": None,
                "source": "scanner",
                "title": "«Сканер» (версия CVSS не указана)",
            }
        )
    return out


@dataclass
class Proposal:
    """Исходные данные расчёта на сейчас и результат, если данных хватает."""

    inputs: dict[str, Any]
    hosts: list[str]
    missing: list[dict[str, Any]]
    cvss: dict[str, Any]
    exploitation: dict[str, Any]
    infra: dict[str, Any] | None
    outcome: dict[str, Any] | None = None
    fingerprint: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.missing

    def as_dict(self) -> dict[str, Any]:
        return {
            "inputs": self.inputs,
            "hosts": self.hosts,
            "missing": self.missing,
            "complete": self.complete,
            "cvss": self.cvss,
            "exploitation": self.exploitation,
            "infra": self.infra,
            "outcome": self.outcome,
            "fingerprint": self.fingerprint,
            "notes": self.notes,
        }


def _indicator(definition: dict[str, Any], *, inventory: str | None = None, bdu: str | None = None):
    for ind in definition.get("indicators") or []:
        if inventory and ind.get("inventory") == inventory:
            return ind
        if bdu and ind.get("bdu") == bdu:
            return ind
    return None


def fingerprint(definition_hash: str, inputs: dict[str, Any], hosts: list[str]) -> str:
    raw = json.dumps(
        {"m": definition_hash, "inputs": inputs, "hosts": sorted(hosts)},
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def propose(
    definition: dict[str, Any],
    definition_hash: str,
    *,
    hosts: list[HostData],
    vulnerable: list[str],
    bdu: BduInfo | None,
    bdu_id: str | None,
    findings: list[dict[str, Any]],
    choices: Choices,
) -> Proposal:
    """Собирает исходные данные расчёта из БДУ, инвентаризации и выбора специалиста."""
    missing: list[dict[str, Any]] = []
    notes: list[str] = []
    inputs: dict[str, Any] = {}
    known = {h.address for h in hosts}
    vuln_hosts = [a for a in dict.fromkeys(vulnerable) if a in known]
    if gone := [a for a in dict.fromkeys(vulnerable) if a not in known]:
        notes.append("Хосты больше не входят в состав объекта: " + ", ".join(gone[:10]))

    # --- I_cvss (п. 13) ---
    target = str((definition.get("cvss") or {}).get("version") or "3.1")
    cvss: dict[str, Any] = {
        "target_version": target,
        "options": cvss_options(bdu, findings),
        "choice": choices.cvss,
    }
    if bdu is not None and bdu.cvss3_score is not None and (bdu.cvss3_version or "") == target:
        inputs["cvss"] = fmt(Decimal(str(bdu.cvss3_score)))
        cvss.update(
            score=inputs["cvss"],
            version=target,
            vector=bdu.cvss3_vector,
            source="bdu",
            fallback=False,
            basis=f"Базовая оценка CVSS {target} из БДУ ({bdu.bdu_id})",
        )
        if choices.cvss:
            notes.append(
                f"В БДУ появилась оценка CVSS {target}: она применяется вместо выбранной "
                "специалистом (п. 13)"
            )
    elif choices.cvss:
        c = choices.cvss
        inputs["cvss"] = c["score"]
        cvss.update(
            score=c["score"],
            version=c["version"],
            vector=c.get("vector"),
            source=c["source"],
            fallback=c["version"] != target,
            basis=(
                f"Оценки CVSS {target} в БДУ нет: специалист выбрал CVSS {c['version']}, "
                f"источник — {CVSS_SOURCES.get(c['source'], c['source'])} (п. 13)"
            ),
        )
    else:
        cvss.update(score=None, version=None, source=None, fallback=False, basis=None)
        missing.append(
            {
                "indicator": "cvss",
                "text": (
                    f"нет базовой оценки CVSS {target}: выберите версию CVSS и оценку (п. 13)"
                    if bdu is not None or not bdu_id
                    else f"уязвимости {bdu_id} нет в загруженной выгрузке БДУ: выберите версию "
                    "CVSS и оценку или загрузите выгрузку"
                ),
                "addresses": [],
            }
        )

    # --- K, L, P (п. 14, 15) ---
    infra = None
    if not vuln_hosts:
        missing.append(
            {
                "indicator": "infr",
                "text": "нет уязвимых хостов в составе объекта: показатели K, L, P определить "
                "не по чему",
                "addresses": [],
            }
        )
    else:
        out = infrastructure(definition, hosts, vuln_hosts)
        infra = out.as_dict()
        missing.extend(out.missing)
        inputs.update(out.inputs)

    # --- E (п. 16) ---
    e_ind = _indicator(definition, bdu="exploitation")
    e_code = None
    if e_ind is not None and bdu is not None:
        e_code = next((v["code"] for v in e_ind["values"] if v.get("bdu") == bdu.e_level), None)
    e_target = e_ind["code"] if e_ind is not None else "E"
    chosen = list(dict.fromkeys(choices.e))
    e_values = list(dict.fromkeys(([e_code] if e_code else []) + chosen))
    exploitation = {
        "indicator": e_target,
        "bdu": e_code,
        "bdu_exploit": bdu.exploit_raw if bdu else None,
        "bdu_in_wild": bdu.in_wild_raw if bdu else None,
        "chosen": chosen,
        "values": e_values,
    }
    if e_values:
        inputs[e_target] = e_values
    else:
        missing.append(
            {
                "indicator": e_target,
                "text": "нет сведений БДУ об эксплуатации: выберите значение показателя E (п. 16)",
                "addresses": [],
            }
        )

    # --- H (п. 17) ---
    h_ind = next((i for i in definition.get("indicators") or [] if i.get("group") == "imp"), None)
    h_code = h_ind["code"] if h_ind else "H"
    if choices.h:
        inputs[h_code] = list(dict.fromkeys(choices.h))
    else:
        missing.append(
            {
                "indicator": h_code,
                "text": "выберите последствия эксплуатации уязвимости (показатель H, п. 17)",
                "addresses": [],
            }
        )

    # Прочие показатели справочника, которые не берутся ни откуда выше.
    for ind in definition.get("indicators") or []:
        if ind["code"] in inputs or any(m["indicator"] == ind["code"] for m in missing):
            continue
        if ind.get("group") == "infr" and infra is None:
            continue
        missing.append(
            {
                "indicator": ind["code"],
                "text": f"показатель {ind['code']} не определён",
                "addresses": [],
            }
        )

    if choices.certified_szi:
        inputs["certified_szi"] = True

    proposal = Proposal(
        inputs=inputs,
        hosts=vuln_hosts,
        missing=missing,
        cvss=cvss,
        exploitation=exploitation,
        infra=infra,
        notes=notes,
    )
    if not missing:
        try:
            outcome = compute(definition, inputs, _validated=True)
        except InputError as e:
            proposal.missing.append({"indicator": "input", "text": str(e), "addresses": []})
        else:
            d = outcome.as_dict()
            _annotate(definition, d, proposal, bdu)
            proposal.outcome = d
            proposal.fingerprint = fingerprint(definition_hash, inputs, vuln_hosts)
    return proposal


def _annotate(
    definition: dict[str, Any], outcome: dict[str, Any], p: Proposal, bdu: BduInfo | None
) -> None:
    """Строка «откуда значение» у каждого показателя трассировки."""
    roles = {i.get("inventory"): i["code"] for i in definition["indicators"] if i.get("inventory")}
    k, l_, pp = roles.get("component_type"), roles.get("vulnerable_share"), roles.get("internet")
    e = p.exploitation["indicator"]
    infra = p.infra or {}
    for row in outcome["trace"]:
        code = row["indicator"]
        if code == "cvss":
            row["basis"], row["basis_kind"] = (
                p.cvss.get("basis"),
                (
                    "specialist"
                    if p.cvss.get("source") != "bdu" or p.cvss.get("fallback")
                    else "bdu"
                ),
            )
            row["fallback"] = bool(p.cvss.get("fallback"))
        elif code == k:
            row["basis_kind"] = "inventory"
            row["basis"] = "Типы компонента уязвимых хостов: " + ", ".join(
                f"{t['code']} {t['short']}" for t in infra.get("by_type") or []
            )
        elif code == l_:
            row["basis_kind"] = "inventory"
            row["basis"] = "; ".join(
                f"{t['short']}: {t['vulnerable']} из {t['total']} "
                f"({t['share'].replace('.', ',')} %) → {t['band']}"
                for t in infra.get("by_type") or []
            )
        elif code == pp:
            row["basis_kind"] = "inventory"
            exposed = infra.get("exposed") or []
            row["basis"] = (
                "Доступны из сети «Интернет»: " + ", ".join(exposed[:10])
                if exposed
                else "Ни один уязвимый хост не доступен из сети «Интернет»"
            )
        elif code == e:
            ex = p.exploitation
            parts = []
            if ex["bdu"]:
                src = []
                if bdu and bdu.in_wild_raw:
                    src.append(f"эксплуатация в атаках — «{bdu.in_wild_raw}»")
                if bdu and bdu.exploit_raw:
                    src.append(f"эксплойт — «{bdu.exploit_raw}»")
                parts.append(f"БДУ: {ex['bdu']}" + (f" ({'; '.join(src)})" if src else ""))
            if ex["chosen"]:
                parts.append("специалист: " + ", ".join(ex["chosen"]))
            row["basis"] = "; ".join(parts)
            row["basis_kind"] = "bdu" if ex["bdu"] and not ex["chosen"] else "specialist"
        else:
            row["basis"], row["basis_kind"] = "Выбор специалиста", "specialist"


# ---------- Устаревание оценки ----------


def _aware(at: datetime) -> datetime:
    # SQLite возвращает время без зоны; всё время в БД — UTC.
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


_INPUT_REASONS = (
    ("cvss", "изменилась оценка CVSS"),
    ("certified_szi", "изменилась отметка «уязвимость в сертифицированном СЗИ» (п. 4)"),
)


def stale_reasons(
    definition: dict[str, Any],
    definition_hash: str,
    last: dict[str, Any],
    proposal: Proposal,
    bdu: BduInfo | None,
) -> list[str]:
    """Почему последняя оценка уже не отражает исходные данные.

    last: inputs, hosts, methodology_hash, assessed_at.
    """
    reasons: list[str] = []
    if bdu is not None and bdu.criticality_changed_at is not None:
        if _aware(bdu.criticality_changed_at) > _aware(last["assessed_at"]):
            reasons.append("в БДУ изменились сведения, влияющие на критичность (п. 16, 19)")
    if last.get("methodology_hash") != definition_hash:
        reasons.append("изменился справочник Методики")
    before, now = last.get("inputs") or {}, proposal.inputs
    old_hosts, new_hosts = set(last.get("hosts") or []), set(proposal.hosts)
    if old_hosts != new_hosts:
        added, removed = sorted(new_hosts - old_hosts), sorted(old_hosts - new_hosts)
        part = []
        if added:
            part.append("добавились " + ", ".join(added[:5]))
        if removed:
            part.append("не обнаружены " + ", ".join(removed[:5]))
        reasons.append("изменился перечень уязвимых хостов: " + "; ".join(part))
    for key, text in _INPUT_REASONS:
        if before.get(key) != now.get(key):
            reasons.append(text)
    for ind in definition.get("indicators") or []:
        code = ind["code"]
        if before.get(code) == now.get(code):
            continue
        if ind.get("inventory"):
            text = f"изменились данные инвентаризации ({code})"
        elif ind.get("bdu"):
            text = f"изменились сведения об эксплуатации ({code}, п. 16)"
        else:
            text = f"изменён выбор специалиста ({code})"
        if text not in reasons:
            reasons.append(text)
    return reasons


# ---------- Срок устранения (п. 21) ----------


def _add_months(at: datetime, months: int) -> datetime:
    m = at.month - 1 + months
    year, month = at.year + m // 12, m % 12 + 1
    day = min(at.day, calendar.monthrange(year, month)[1])
    return at.replace(year=year, month=month, day=day)


def deadline_at(level: dict[str, Any], at: datetime) -> datetime:
    """Рекомендуемый срок устранения от момента оценки: «до N часов/дней/недель/месяцев»."""
    dl = level.get("deadline") or {}
    value = int(Decimal(str(dl.get("value"))))
    unit = dl.get("unit")
    if unit == "hours":
        return at + timedelta(hours=value)
    if unit == "days":
        return at + timedelta(days=value)
    if unit == "weeks":
        return at + timedelta(weeks=value)
    if unit == "months":
        return _add_months(at, value)
    raise InputError(f"неизвестная единица срока «{unit}»")
