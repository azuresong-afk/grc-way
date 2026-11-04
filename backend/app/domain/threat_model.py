"""Модель угроз по Методике оценки угроз 2021: шаги мастера, проверки, прогресс.

Шаги повторяют порядок Методики:

1. ``consequences`` — негативные последствия (виды У1–У3 и их примеры);
2. ``objects`` — объекты воздействия и виды воздействия на них;
3. ``intruders`` — виды нарушителей, их актуальность и уровни возможностей Н1–Н4;
4. ``methods`` — способы реализации угроз и интерфейсы объектов воздействия;
5. ``scenarios`` — тактики и техники сценариев;
6. ``threats`` — угрозы из БДУ: актуальна или нет, обоснование и связи с шагами 1–5.

Угроза признаётся актуальной, если для неё есть актуальный нарушитель, объект
воздействия, способ реализации, сценарий (тактика) и негативное последствие —
это требование Методики к актуальности угрозы; здесь оно проверяется как
полнота связей, а решение и обоснование остаются за методистом.

Сохранение шага отклоняет только неизвестные коды и неверную структуру. Ссылки
между шагами (объект ссылается на последствие, снятое на шаге 1) не блокируют
сохранение, а попадают в «проблемы» прогресса и блокируют утверждение.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

STEP_KEYS = ("consequences", "objects", "intruders", "methods", "scenarios", "threats")
STEP_TITLES = {
    "consequences": "Негативные последствия",
    "objects": "Объекты воздействия",
    "intruders": "Нарушители",
    "methods": "Способы и интерфейсы",
    "scenarios": "Сценарии",
    "threats": "Угрозы БДУ",
}
# Шаги, данные которых хранятся в threat_models.steps (угрозы — в отдельной таблице).
DATA_STEPS = STEP_KEYS[:-1]

_KEY = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


class ModelError(ValueError):
    """Данные шага нарушают правила (неизвестный код, повтор, неверная связь)."""


@dataclass
class StepProgress:
    key: str
    title: str
    done: bool
    count: int
    problems: list[str] = field(default_factory=list)
    # Замечания, которые не мешают утверждению (находки «Сканера» без угроз и т. п.).
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "title": self.title,
            "done": self.done,
            "count": self.count,
            "problems": self.problems,
            "warnings": self.warnings,
        }


@dataclass
class Progress:
    steps: list[StepProgress]

    @property
    def done(self) -> int:
        return sum(1 for s in self.steps if s.done)

    @property
    def ready(self) -> bool:
        """Все шаги заполнены и нет ни одной проблемы — можно утверждать."""
        return all(s.done and not s.problems for s in self.steps)

    def as_dict(self) -> dict[str, Any]:
        return {
            "steps": [s.as_dict() for s in self.steps],
            "done": self.done,
            "total": len(self.steps),
            "ready": self.ready,
        }


# ---------- Справочник для проверок ----------


@dataclass
class Refs:
    """Записи справочника Методики, нужные для проверок: код → (вид, родитель, атрибуты)."""

    kinds: dict[str, str]
    parents: dict[str, str | None]
    attrs: dict[str, dict[str, Any]]

    def of_kind(self, *kinds: str) -> set[str]:
        return {c for c, k in self.kinds.items() if k in kinds}


def _codes(items: list[dict[str, Any]], key: str = "code") -> list[str]:
    return [str(i.get(key)) for i in items]


def _unique(values: list[str], what: str) -> None:
    seen: set[str] = set()
    for v in values:
        if v in seen:
            raise ModelError(f"{what} {v} указан дважды")
        seen.add(v)


def _known(codes: list[str], allowed: set[str], what: str) -> None:
    for c in codes:
        if c not in allowed:
            raise ModelError(f"{what}: неизвестный код «{c}»")


def validate_step(key: str, data: dict[str, Any], refs: Refs) -> None:
    """Проверка структуры и кодов справочника при сохранении шага 1–5."""
    items = data.get("items") or []
    if key == "consequences":
        codes = _codes(items)
        _unique(codes, "Последствие")
        _known(codes, refs.of_kind("consequence"), "Негативное последствие")
    elif key == "objects":
        keys = _codes(items, "key")
        _unique(keys, "Объект воздействия")
        for o in items:
            if not _KEY.match(str(o.get("key"))):
                raise ModelError("Ключ объекта воздействия — латиница, цифры, дефис")
            if not (o.get("name") or "").strip():
                raise ModelError("У объекта воздействия не указано наименование")
            _known(o.get("impacts") or [], refs.of_kind("impact"), "Вид воздействия")
            _known(o.get("consequences") or [], refs.of_kind("consequence"), "Последствие")
    elif key == "intruders":
        codes = _codes(items)
        _unique(codes, "Нарушитель")
        _known(codes, refs.of_kind("intruder"), "Вид нарушителя")
        caps = refs.of_kind("capability")
        for i in items:
            if i.get("capability") is not None and i["capability"] not in caps:
                raise ModelError(f"{i['code']}: неизвестный уровень возможностей")
    elif key == "methods":
        codes = _codes(items)
        _unique(codes, "Способ")
        _known(codes, refs.of_kind("method"), "Способ реализации")
        _known(
            [c for m in items for c in m.get("intruders") or []],
            refs.of_kind("intruder"),
            "Нарушитель",
        )
    elif key == "scenarios":
        tactics = _codes(items, "tactic")
        _unique(tactics, "Тактика")
        _known(tactics, refs.of_kind("tactic"), "Тактика")
        for s in items:
            for t in s.get("techniques") or []:
                if refs.kinds.get(t) != "technique" or refs.parents.get(t) != s["tactic"]:
                    raise ModelError(f"Техника «{t}» не относится к тактике {s['tactic']}")
    else:
        raise ModelError(f"Неизвестный шаг «{key}»")


# ---------- Прогресс и проблемы ----------


def _items(steps: dict[str, Any], key: str) -> list[dict[str, Any]]:
    return list((steps.get(key) or {}).get("items") or [])


def relevant_intruders(steps: dict[str, Any]) -> set[str]:
    return {i["code"] for i in _items(steps, "intruders") if i.get("relevant")}


def scenario_codes(steps: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for s in _items(steps, "scenarios"):
        out.add(s["tactic"])
        out.update(s.get("techniques") or [])
    return out


def progress(
    steps: dict[str, Any],
    threats: list[dict[str, Any]],
    *,
    refs: Refs,
    hosts: set[str],
    bdu: dict[str, dict[str, Any]],
) -> Progress:
    """Заполненность шагов и проблемы, мешающие утверждению.

    ``threats`` — угрозы модели: {code, relevant, justification, intruders,
    objects, consequences, methods, tactics}; ``hosts`` — адреса хостов объекта;
    ``bdu`` — угрозы БДУ модели: код → {title, withdrawn}.
    """
    out: list[StepProgress] = []
    known = set(refs.kinds)

    def unknown(codes: list[str]) -> list[str]:
        return [c for c in codes if c not in known]

    # 1. Последствия.
    cons = _items(steps, "consequences")
    chosen = {c["code"] for c in cons}
    p = StepProgress("consequences", STEP_TITLES["consequences"], bool(cons), len(cons))
    p.problems += [f"Последствие {c} удалено из справочника" for c in unknown(sorted(chosen))]
    out.append(p)

    # 2. Объекты воздействия.
    objs = _items(steps, "objects")
    obj_keys = {o["key"] for o in objs}
    p = StepProgress("objects", STEP_TITLES["objects"], bool(objs), len(objs))
    for o in objs:
        name = o.get("name") or o["key"]
        if not o.get("impacts"):
            p.done = False
            p.problems.append(f"«{name}»: не выбран ни один вид воздействия")
        if not o.get("consequences"):
            p.done = False
            p.problems.append(f"«{name}»: не указано, к каким последствиям ведёт воздействие")
        for c in o.get("consequences") or []:
            if c not in chosen:
                p.problems.append(f"«{name}»: последствие {c} не выбрано на шаге 1")
        for h in o.get("hosts") or []:
            if h not in hosts:
                p.problems.append(f"«{name}»: хост {h} больше не входит в состав объекта")
    out.append(p)

    # 3. Нарушители.
    intr = _items(steps, "intruders")
    actual = relevant_intruders(steps)
    p = StepProgress("intruders", STEP_TITLES["intruders"], bool(actual), len(actual))
    for i in intr:
        if not (i.get("justification") or "").strip():
            p.done = False
            p.problems.append(f"{i['code']}: нет обоснования актуальности или неактуальности")
        if i.get("relevant") and not i.get("capability"):
            p.done = False
            p.problems.append(f"{i['code']}: не указан уровень возможностей")
    out.append(p)

    # 4. Способы и интерфейсы.
    meths = _items(steps, "methods")
    meth_codes = {m["code"] for m in meths}
    p = StepProgress("methods", STEP_TITLES["methods"], bool(meths), len(meths))
    for m in meths:
        if not (m.get("interfaces") or "").strip():
            p.done = False
            p.problems.append(f"{m['code']}: не указаны интерфейсы")
        if not m.get("objects"):
            p.done = False
            p.problems.append(f"{m['code']}: не выбраны объекты воздействия")
        for k in m.get("objects") or []:
            if k not in obj_keys:
                p.problems.append(f"{m['code']}: объект воздействия «{k}» удалён на шаге 2")
        for c in m.get("intruders") or []:
            if c not in actual:
                p.problems.append(f"{m['code']}: нарушитель {c} не признан актуальным на шаге 3")
    out.append(p)

    # 5. Сценарии.
    scen = _items(steps, "scenarios")
    scen_codes = scenario_codes(steps)
    out.append(StepProgress("scenarios", STEP_TITLES["scenarios"], bool(scen), len(scen)))

    # 6. Угрозы.
    rel = [t for t in threats if t.get("relevant")]
    p = StepProgress("threats", STEP_TITLES["threats"], bool(rel), len(rel))
    for t in threats:
        code = t["code"]
        info = bdu.get(code)
        if info is None:
            p.problems.append(f"{code}: угрозы нет в загруженной БДУ")
        if t.get("relevant") is None:
            p.done = False
            p.problems.append(f"{code}: не принято решение об актуальности")
            continue
        if not (t.get("justification") or "").strip():
            p.done = False
            p.problems.append(f"{code}: нет обоснования")
        if not t.get("relevant"):
            continue
        if info is not None and info.get("withdrawn"):
            p.problems.append(f"{code}: угроза исключена из БДУ, а признана актуальной")
        links = (
            ("intruders", actual, "актуального нарушителя", "не актуален на шаге 3"),
            ("objects", obj_keys, "объекта воздействия", "удалён на шаге 2"),
            ("consequences", chosen, "негативного последствия", "не выбрано на шаге 1"),
            ("methods", meth_codes, "способа реализации", "не выбран на шаге 4"),
            ("tactics", scen_codes, "тактики сценария", "не выбрана на шаге 5"),
        )
        for key, allowed, what, gone in links:
            values = t.get(key) or []
            if not values:
                p.done = False
                p.problems.append(f"{code}: актуальна, но нет {what}")
            for v in values:
                if v not in allowed:
                    p.problems.append(f"{code}: {v} {gone}")
    out.append(p)
    return Progress(out)


# ---------- Подсказки по БДУ ----------

_CATEGORY = re.compile(r"(внешн|внутренн)\w*\s+нарушител", re.IGNORECASE)
_POTENTIAL = re.compile(r"(низк|средн|высок)\w*\s+потенциал", re.IGNORECASE)
_POTENTIALS = {"низк": "низкий", "средн": "средний", "высок": "высокий"}


def bdu_source_hint(source: str | None) -> dict[str, list[str]]:
    """Категории нарушителя и потенциалы из поля «Источник угрозы» БДУ.

    «Внешний нарушитель с низким потенциалом; внутренний нарушитель со средним
    потенциалом» → {categories: [внешний, внутренний], potentials: [низкий, средний]}.
    Это подсказка для отбора, а не правило Методики.
    """
    text = source or ""
    cats: list[str] = []
    for m in _CATEGORY.finditer(text):
        c = "внешний" if m.group(1).lower().startswith("внешн") else "внутренний"
        if c not in cats:
            cats.append(c)
    pots: list[str] = []
    for m in _POTENTIAL.finditer(text):
        v = _POTENTIALS[m.group(1).lower()]
        if v not in pots:
            pots.append(v)
    return {"categories": cats, "potentials": pots}
