"""Разделы контекста документов комплекта (задача 3.2): меры, испытания, модель
угроз, уязвимости, несоответствия, ОРД.

Как и в context.py — только данные (строки, числа, списки словарей), без
оформления. Каждый раздел — ключ верхнего уровня контекста; документ хэширует и
сохраняет только те разделы, которые использует его шаблон (см.
domain/documents.py), поэтому правка модели угроз не делает «изменённым»
технический паспорт.

Несверенные записи справочников каждый раздел возвращает со своим ключом
(`section`): водяной знак получает только документ, который этот раздел выводит.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    Adaptation,
    AssessedObject,
    BduThreat,
    Evidence,
    ObjectMeasure,
    RefDocument,
    RefGroup,
    RefMeasure,
    RefProfile,
    RefThreatItem,
    RefVulnMethodology,
    ScannerSnapshot,
    ThreatModel,
)
from app.domain.measures import Item, compute_stats, effective_status

STATUS_TITLES = {
    "implemented": "Реализована",
    "partial": "Реализована частично",
    "not_implemented": "Не реализована",
    "not_applicable": "Не применима",
    "unassessed": "Не оценена",
}
METHOD_TITLES = {
    "auto": "Автоматически («Сканер»)",
    "manual": "Вручную",
    "mixed": "Автоматически и вручную",
}
ADAPTATION_TITLES = {"none": "", "excluded": "Исключена", "compensated": "Компенсирована"}
EVIDENCE_TITLES = {
    "file": "Документ",
    "interview": "Интервью",
    "inspection": "Осмотр",
    "certificate": "Сертификат СЗИ",
}
MODEL_STATUS_TITLES = {"draft": "Черновик", "approved": "Утверждена", "superseded": "Заменена"}
ADAPTATION_STATUS_TITLES = {"draft": "Черновик", "approved": "Утверждена", "superseded": "Заменена"}
NONCONFORMING = ("not_implemented", "partial")
VULN_LEVELS = ("critical", "high", "medium", "low")
# Сколько хостов с нарушениями перечислять в протоколе у одной меры.
_HOSTS_SHOWN = 12


def _d(v: date | datetime | None) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        v = v.date()
    return v.strftime("%d.%m.%Y")


def _dt(v: datetime | None) -> str | None:
    if v is None:
        return None
    if v.tzinfo is None:
        v = v.replace(tzinfo=UTC)
    return v.astimezone(UTC).strftime("%d.%m.%Y %H:%M UTC")


def _s(v: Any) -> str | None:
    if v is None:
        return None
    v = str(v).strip()
    return v or None


def _pct(v: float | None) -> str | None:
    if v is None:
        return None
    return f"{v:.1f}".replace(".", ",").removesuffix(",0") + " %"


def _hosts_text(hosts: list[str]) -> str:
    shown = ", ".join(hosts[:_HOSTS_SHOWN])
    if len(hosts) > _HOSTS_SHOWN:
        shown += f" и ещё {len(hosts) - _HOSTS_SHOWN}"
    return shown


# ---------- Снимок «Сканера» ----------


def latest_snapshot(session: Session, obj: AssessedObject) -> ScannerSnapshot | None:
    return session.scalars(
        select(ScannerSnapshot)
        .where(ScannerSnapshot.object_id == obj.id)
        .order_by(ScannerSnapshot.number.desc())
        .limit(1)
    ).first()


_SNAPSHOT_KEYS = (
    "number run_id run_name run_finished imported imported_by modules level percent "
    "passed failed hosts coverage_gaps"
).split()


def snapshot_section(snap: ScannerSnapshot | None) -> dict[str, Any]:
    """Текущий снимок; без снимка — те же ключи с пустыми значениями (шаблонам
    не нужно проверять, есть ли раздел)."""
    if snap is None:
        return dict.fromkeys(_SNAPSHOT_KEYS)
    cov = ((snap.coverage or {}).get("summary") or {}) if snap.coverage else {}
    counts = snap.counts or {}
    return {
        "number": snap.number,
        "run_id": snap.run_id,
        "run_name": _s(snap.run_name),
        "run_finished": _dt(snap.run_finished_at),
        "imported": _dt(snap.imported_at),
        "imported_by": _s(snap.imported_by_name),
        "modules": ", ".join(snap.run_modules or []) or None,
        "level": snap.level,
        "percent": _pct(snap.percent),
        "passed": counts.get("passed", 0),
        "failed": counts.get("failed", 0),
        "hosts": len(snap.object_hosts or []),
        "coverage_gaps": int(cov.get("gaps") or 0),
    }


# ---------- Меры, испытания, несоответствия ----------


_STATS_KEYS = (
    "percent auto_percent manual_percent total implemented partial not_implemented "
    "unassessed excluded not_applicable compensated confirmed partial_weight"
).split()


def empty_measures() -> dict[str, Any]:
    return {
        "profile": None,
        "profile_short": None,
        "level": None,
        "adaptation": dict.fromkeys(("version", "status_title", "approved", "approved_by")),
        "stats": dict.fromkeys(_STATS_KEYS),
        "groups": [],
        "excluded": [],
        "compensated": [],
        "added": [],
    }


def _evidence_by_measure(
    session: Session, obj: AssessedObject, snap: ScannerSnapshot | None
) -> tuple[dict[Any, Evidence], dict[Any, list[Evidence]]]:
    auto: dict[Any, Evidence] = {}
    manual: dict[Any, list[Evidence]] = defaultdict(list)
    rows = session.scalars(
        select(Evidence)
        .where(Evidence.object_id == obj.id, Evidence.withdrawn_at.is_(None))
        .order_by(Evidence.created_at)
    )
    for e in rows:
        if e.kind == "scanner":
            if snap is not None and e.snapshot_id == snap.id:
                auto[e.object_measure_id] = e
        else:
            manual[e.object_measure_id].append(e)
    return auto, manual


def _manual_text(e: Evidence) -> str:
    data = e.data or {}
    when = data.get("held_on") or _d(e.created_at)
    if isinstance(when, str) and len(when) == 10 and when[4] == "-":
        when = f"{when[8:10]}.{when[5:7]}.{when[0:4]}"
    parts = [f"{EVIDENCE_TITLES.get(e.kind, e.kind)} от {when}: {e.summary}"]
    if data.get("participants"):
        parts.append(f"участники: {data['participants']}")
    return "; ".join(parts)


def _auto_text(e: Evidence | None) -> tuple[str | None, list[str]]:
    if e is None:
        return None, []
    data = e.data or {}
    failed = [str(h) for h in data.get("failed") or []]
    checked = data.get("checked") or []
    note = _s(data.get("note")) or e.summary
    text = f"{note}; проверено хостов: {len(checked)}, с нарушениями: {len(failed)}"
    return text, failed


def measures_section(
    session: Session, obj: AssessedObject, snap: ScannerSnapshot | None, partial_weight: float
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]:
    """(measures, nonconformities, unverified)."""
    ms = list(
        session.scalars(
            select(ObjectMeasure)
            .where(ObjectMeasure.object_id == obj.id)
            .order_by(ObjectMeasure.position, ObjectMeasure.measure_id)
        )
    )
    if not ms:
        return empty_measures(), [], []
    profile_id = ms[0].profile_id
    profile = session.get(RefProfile, profile_id)
    groups = {
        g.code: g
        for g in session.scalars(select(RefGroup).where(RefGroup.profile_id == profile_id))
    }
    refs = {
        r.id: r
        for r in session.scalars(select(RefMeasure).where(RefMeasure.profile_id == profile_id))
    }
    adaptation = session.scalars(
        select(Adaptation)
        .where(Adaptation.object_id == obj.id)
        .order_by(Adaptation.version.desc())
        .limit(1)
    ).first()
    auto_ev, manual_ev = _evidence_by_measure(session, obj, snap)

    items = [
        Item(m.measure_id, m.method, m.status, m.adaptation, tuple(m.compensating_ids or ()))
        for m in ms
    ]
    by_id = {i.measure_id: i for i in items}
    stats = compute_stats(items, partial_weight)
    titles = {m.measure_id: m.title for m in ms}

    out_groups: dict[str, dict[str, Any]] = {}
    nonconformities: list[dict[str, Any]] = []
    excluded, compensated, added = [], [], []
    confirmed = 0
    for m, item in zip(ms, items, strict=True):
        eff = effective_status(item, by_id)
        auto_text, failed = _auto_text(auto_ev.get(m.id))
        manual = [_manual_text(e) for e in manual_ev.get(m.id, [])]
        row = {
            "id": m.measure_id,
            "title": m.title,
            "group": m.group_code,
            "method_title": METHOD_TITLES.get(m.method, m.method),
            "status_title": STATUS_TITLES.get(eff or m.status, m.status)
            if m.adaptation != "excluded"
            else "Исключена",
            "adaptation_title": ADAPTATION_TITLES.get(m.adaptation, m.adaptation),
            "reason": _s(m.adaptation_reason),
            "compensating": ", ".join(m.compensating_ids or []) or None,
            "auto": auto_text,
            "failed_hosts": _hosts_text(failed) if failed else None,
            "recommendation": None,
            "manual": "; ".join(manual) or None,
            "comment": _s(m.comment),
            "confirmed": (
                f"{_d(m.confirmed_at)}, {m.confirmed_by_name or '—'}" if m.confirmed_at else None
            ),
        }
        if m.confirmed_at is not None:
            confirmed += 1
        if m.adaptation == "excluded":
            excluded.append(row)
            continue
        if m.adaptation == "compensated":
            compensated.append(row)
        if m.origin == "added":
            added.append(row)
        g = out_groups.setdefault(
            m.group_code,
            {
                "code": m.group_code,
                "title": groups[m.group_code].title if m.group_code in groups else m.group_code,
                "rows": [],
                "implemented": 0,
                "nonconforming": 0,
                "unassessed": 0,
            },
        )
        g["rows"].append(row)
        if eff == "implemented":
            g["implemented"] += 1
        elif eff in NONCONFORMING:
            g["nonconforming"] += 1
        elif eff == "unassessed":
            g["unassessed"] += 1
        if eff in NONCONFORMING:
            nonconformities.append(
                {
                    "kind_title": "Мера",
                    "ref": m.measure_id,
                    "title": m.title,
                    "status_title": STATUS_TITLES[eff],
                    "details": "; ".join(
                        x
                        for x in (
                            auto_text,
                            f"хосты с нарушениями: {_hosts_text(failed)}" if failed else None,
                            _s(m.comment),
                        )
                        if x
                    )
                    or None,
                    "action": f"Реализовать меру {m.measure_id} «{titles[m.measure_id]}»"
                    + (" на хостах с нарушениями" if failed else ""),
                }
            )

    unverified_n = sum(
        1
        for m in ms
        if m.adaptation != "excluded"
        and (refs.get(m.measure_id) is None or not refs[m.measure_id].verified_at)
    )
    unverified = []
    if unverified_n:
        unverified.append(
            {
                "section": "measures",
                "title": f"Меры профиля «{profile.short if profile else profile_id}»",
                "note": f"не сверено методистом: {unverified_n}",
            }
        )
    t = stats.total
    section = {
        "profile": profile.title if profile else profile_id,
        "profile_short": profile.short if profile else profile_id,
        "level": adaptation.level_label if adaptation else None,
        "adaptation": (
            {
                "version": adaptation.version,
                "status_title": ADAPTATION_STATUS_TITLES.get(adaptation.status, adaptation.status),
                "approved": _d(adaptation.approved_at),
                "approved_by": _s(adaptation.approved_by_name),
            }
            if adaptation
            else empty_measures()["adaptation"]
        ),
        "stats": {
            "percent": _pct(t.percent),
            "auto_percent": _pct(stats.auto.percent),
            "manual_percent": _pct(stats.manual.percent),
            "total": t.total,
            "implemented": t.implemented,
            "partial": t.partial,
            "not_implemented": t.not_implemented,
            "unassessed": t.unassessed,
            "excluded": t.excluded,
            "not_applicable": t.not_applicable,
            "compensated": t.compensated,
            "confirmed": confirmed,
            "partial_weight": f"{partial_weight:g}".replace(".", ","),
        },
        "groups": list(out_groups.values()),
        "excluded": excluded,
        "compensated": compensated,
        "added": added,
    }
    return section, nonconformities, unverified


# ---------- Модель угроз ----------


def _join(codes: list[str], titles: dict[str, str], *, with_code: bool = True) -> str | None:
    out = []
    for c in codes or []:
        t = titles.get(c)
        out.append(f"{c} {t}" if (t and with_code) else (t or c))
    return "; ".join(out) or None


_STEP_KEYS = ("consequences", "objects", "intruders", "methods", "scenarios")


def empty_threat_model() -> dict[str, Any]:
    return {
        "version": None,
        "status": None,
        "status_title": None,
        "approved": None,
        "approved_by": None,
        "consequences": [],
        "objects": [],
        "intruders": [],
        "intruders_relevant": None,
        "methods": [],
        "scenarios": [],
        "threats": [],
        "relevant_threats": [],
        "counts": {"total": 0, "relevant": 0, "not_relevant": 0, "undecided": 0},
        "notes": dict.fromkeys(_STEP_KEYS),
    }


def threat_model_section(
    session: Session, obj: AssessedObject
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    models = list(
        session.scalars(
            select(ThreatModel)
            .where(ThreatModel.object_id == obj.id)
            .order_by(ThreatModel.version.desc())
        )
    )
    if not models:
        return empty_threat_model(), []
    # Утверждённая версия, если есть; иначе последняя (черновик) — с отметкой.
    model = next((m for m in models if m.status == "approved"), models[0])
    steps = model.steps or {}
    items = {r.code: r for r in session.scalars(select(RefThreatItem))}
    titles = {c: r.title for c, r in items.items()}
    codes = [t.threat_code for t in model.threats]
    bdu = (
        {
            t.code: t.title
            for t in session.scalars(select(BduThreat).where(BduThreat.code.in_(codes)))
        }
        if codes
        else {}
    )
    objects = (steps.get("objects") or {}).get("items") or []
    obj_names = {o.get("key"): o.get("name") for o in objects}

    def step(key: str) -> list[dict[str, Any]]:
        return (steps.get(key) or {}).get("items") or []

    used: set[str] = set()

    def mark(*cs: Any) -> None:
        for c in cs:
            if isinstance(c, list):
                used.update(str(x) for x in c)
            elif c:
                used.add(str(c))

    consequences = []
    for c in step("consequences"):
        mark(c.get("code"))
        consequences.append(
            {
                "code": c.get("code"),
                "title": titles.get(c.get("code"), c.get("code")),
                "justification": _s(c.get("justification")),
            }
        )
    impact_objects = []
    for o in objects:
        mark(o.get("impacts"), o.get("consequences"))
        impact_objects.append(
            {
                "name": o.get("name"),
                "description": _s(o.get("description")),
                "hosts": ", ".join(o.get("hosts") or []) or None,
                "impacts": ", ".join(o.get("impacts") or []) or None,
                "consequences": ", ".join(o.get("consequences") or []) or None,
            }
        )
    intruders = []
    for i in step("intruders"):
        mark(i.get("code"), i.get("capability"))
        intruders.append(
            {
                "code": i.get("code"),
                "title": titles.get(i.get("code"), i.get("code")),
                "relevant_title": "Актуален" if i.get("relevant") else "Неактуален",
                "relevant": bool(i.get("relevant")),
                "capability": _join([i["capability"]], titles) if i.get("capability") else None,
                "justification": _s(i.get("justification")),
            }
        )
    methods = []
    for m in step("methods"):
        mark(m.get("code"), m.get("intruders"))
        methods.append(
            {
                "code": m.get("code"),
                "title": titles.get(m.get("code"), m.get("code")),
                "interfaces": _s(m.get("interfaces")),
                "objects": ", ".join(obj_names.get(k, k) for k in m.get("objects") or []) or None,
                "intruders": ", ".join(m.get("intruders") or []) or None,
            }
        )
    scenarios = []
    for s in step("scenarios"):
        mark(s.get("tactic"), s.get("techniques"))
        scenarios.append(
            {
                "tactic": s.get("tactic"),
                "title": titles.get(s.get("tactic"), s.get("tactic")),
                "techniques": _join(s.get("techniques") or [], titles),
                "note": _s(s.get("note")),
            }
        )
    threats = []
    for t in model.threats:
        mark(t.intruders, t.consequences, t.methods, t.tactics)
        threats.append(
            {
                "code": t.threat_code,
                "title": bdu.get(t.threat_code, t.threat_code),
                "relevant": t.relevant,
                "relevant_title": {True: "Актуальна", False: "Неактуальна"}.get(
                    t.relevant,  # type: ignore[arg-type]
                    "Решение не принято",
                ),
                "justification": _s(t.justification),
                "intruders": ", ".join(t.intruders or []) or None,
                "objects": ", ".join(obj_names.get(k, k) for k in t.objects or []) or None,
                "consequences": ", ".join(t.consequences or []) or None,
                "methods": ", ".join(t.methods or []) or None,
                "tactics": ", ".join(t.tactics or []) or None,
                "findings": len(t.linked_findings or []),
            }
        )
    relevant = [t for t in threats if t["relevant"] is True]
    unverified_n = sum(1 for c in used if c in items and items[c].verified_at is None)
    unverified = []
    if unverified_n:
        unverified.append(
            {
                "section": "threat_model",
                "title": "Справочник Методики оценки угроз (ФСТЭК России, 2021)",
                "note": f"в модели использовано несверенных записей: {unverified_n}",
            }
        )
    section = {
        "version": model.version,
        "status": model.status,
        "status_title": MODEL_STATUS_TITLES.get(model.status, model.status),
        "approved": _d(model.approved_at),
        "approved_by": _s(model.approved_by_name),
        "consequences": consequences,
        "objects": impact_objects,
        "intruders": intruders,
        "intruders_relevant": ", ".join(
            f"{i['code']} {i['title']}" for i in intruders if i["relevant"]
        )
        or None,
        "methods": methods,
        "scenarios": scenarios,
        "threats": threats,
        "relevant_threats": relevant,
        "counts": {
            "total": len(threats),
            "relevant": len(relevant),
            "not_relevant": sum(1 for t in threats if t["relevant"] is False),
            "undecided": sum(1 for t in threats if t["relevant"] is None),
        },
        "notes": {k: _s((steps.get(k) or {}).get("note")) for k in _STEP_KEYS},
    }
    return section, unverified


# ---------- Уязвимости (Методика 2025) ----------


def _doc_ref(session: Session, code: str) -> dict[str, Any]:
    d = session.get(RefDocument, code)
    if d is None:
        return dict.fromkeys(_DOC_KEYS)
    return {
        "short": d.short,
        "title": d.title,
        "issuer": _s(d.issuer),
        "issued": _d(d.issued),
        "number": _s(d.number),
    }


_DOC_KEYS = ("short", "title", "issuer", "issued", "number")


def _counts(levels: dict[str, int] | None = None, **extra: int) -> dict[str, int]:
    out = dict.fromkeys(VULN_LEVELS, 0)
    out.update(levels or {})
    out.update(dict.fromkeys(("total", "assessed", "not_assessed", "overdue", "not_detected"), 0))
    out.update(extra)
    return out


def empty_vulns() -> dict[str, Any]:
    return {
        "methodology": {**dict.fromkeys(_DOC_KEYS), "version": None, "formula": None},
        "snapshot": None,
        "levels": [],
        "rows": [],
        "counts": _counts(),
    }


def vulns_section(
    session: Session, obj: AssessedObject
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]:
    """(vulns, несоответствия-уязвимости для плана, unverified)."""
    # Импорт здесь: реестр собирается теми же функциями, что и экран «Уязвимости».
    from fastapi import HTTPException

    from app.api.object_vulns import LEVEL_ORDER, register
    from app.api.objects import INVENTORY_METHODOLOGY

    m = session.get(RefVulnMethodology, INVENTORY_METHODOLOGY)
    if m is None:
        return empty_vulns(), [], []
    try:
        reg = register(session, obj, m)
    except HTTPException:
        return empty_vulns(), [], []
    definition = m.definition or {}
    levels = [
        {
            "code": lv.get("code"),
            "title": lv.get("title"),
            "condition": lv.get("condition"),
            "deadline": (lv.get("deadline") or {}).get("text"),
        }
        for lv in definition.get("levels") or []
    ]
    items, plan = [], []
    for r in reg.items:
        a = r.current
        detected = r.state != "not_detected"
        row = {
            "bdu_id": r.bdu_id or "—",
            "title": r.title,
            "cve": ", ".join(r.cve_ids) or None,
            "hosts": _hosts_text(r.hosts) if r.hosts else None,
            "source_title": r.manual_source_title or "«Сканер»",
            "state_title": r.state_title,
            "v": a.v.replace(".", ",") if a else None,
            "level": a.level if a else None,
            "level_title": a.level_title if a else None,
            "assessed": _d(a.assessed_at) if a else None,
            "deadline": _dt(a.deadline_at) if a else None,
            "overdue": bool(a and a.overdue),
            "detected": detected,
        }
        items.append(row)
        if detected and a is not None:
            plan.append(
                {
                    "kind_title": "Уязвимость",
                    "ref": r.bdu_id or "без идентификатора БДУ",
                    "title": r.title,
                    "status_title": f"{a.level_title} уровень, V = {row['v']}",
                    "details": f"хосты: {row['hosts']}" if row["hosts"] else None,
                    "action": "Устранить уязвимость (обновление или компенсирующие меры)",
                    "deadline": row["deadline"],
                    "level_order": LEVEL_ORDER.get(a.level, 9),
                }
            )
    detected = [i for i in items if i["detected"]]
    counts = _counts(
        {lv: sum(1 for i in detected if i["level"] == lv) for lv in VULN_LEVELS},
        total=len(detected),
        assessed=sum(1 for i in detected if i["level"]),
        not_assessed=sum(1 for i in detected if not i["level"]),
        overdue=sum(1 for i in detected if i["overdue"]),
        not_detected=len(items) - len(detected),
    )
    unverified = []
    if m.verified_at is None:
        unverified.append(
            {
                "section": "vulns",
                "title": "Методика оценки критичности уязвимостей (ФСТЭК России, 2025)",
                "note": f"версия {m.version}, ревизия {m.revision}",
            }
        )
    plan.sort(key=lambda p: p.pop("level_order"))
    section = {
        "methodology": {
            **_doc_ref(session, "fstec-vuln-2025"),
            "version": m.version,
            "formula": "V = I_cvss × I_infr × (I_at + I_imp)",
        },
        "snapshot": reg.snapshot.number if reg.snapshot else None,
        "levels": levels,
        # «rows», а не «items»: в шаблоне vulns.items — метод словаря.
        "rows": detected,
        "counts": counts,
    }
    return section, plan, unverified


# ---------- Нормативные документы ----------


def normative_section(session: Session, codes: list[str]) -> list[dict[str, Any]]:
    out = []
    for code in codes:
        ref = _doc_ref(session, code)
        if ref["title"]:
            out.append(ref)
    return out


# ---------- Организационно-распорядительные документы ----------


def org_docs_section(
    reference_dir: Path, measures: dict[str, Any], profile_id: str | None
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Разделы комплекта ОРД из reference/documents/org-docs.yaml и меры объекта по ним."""
    path = reference_dir / "documents" / "org-docs.yaml"
    if not path.is_file():
        return {"version": None, "sections": []}, []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    by_id = {m["id"]: m for g in measures.get("groups") or [] for m in g["rows"]}
    sections = []
    for i, raw in enumerate(data.get("sections") or [], start=1):
        ids = list((raw.get("measures") or {}).get(profile_id or "") or [])
        related = [
            {"id": mid, "title": by_id[mid]["title"], "status_title": by_id[mid]["status_title"]}
            for mid in ids
            if mid in by_id
        ]
        sections.append(
            {
                "number": i,
                "code": raw.get("code"),
                "title": raw.get("title"),
                "purpose": _s(raw.get("purpose")),
                "paragraphs": [
                    str(p).strip() for p in raw.get("paragraphs") or [] if str(p).strip()
                ],
                "measures": related,
            }
        )
    unverified = []
    if data.get("origin") != "official" or not data.get("verified"):
        unverified.append(
            {
                "section": "org",
                "title": "Типовые формулировки ОРД (reference/documents/org-docs.yaml)",
                "note": f"версия {data.get('version', '—')}, не сверены методистом",
            }
        )
    return {"version": data.get("version"), "sections": sections}, unverified
