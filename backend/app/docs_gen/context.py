"""Контекст документа: данные объекта из БД в виде простого словаря.

Контекст — только данные (строки, числа, списки словарей), без оформления:
его же показывает карта «из каких данных собран», от него считается хэш
(сформированный документ с тем же хэшем повторно не создаётся), он же
сохраняется в записи документа — что попало в версию, видно и потом.

Пустое значение — None, "" или []: шаблон получает на его месте заглушку
(см. fieldmap.fill_placeholders), карта показывает поле как незаполненное.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import AssessedObject, Classification, ObjectMeasure, ObjectSzi, Project
from app.docs_gen import sections
from app.domain import szi as szi_domain

KIND_TITLES = {
    "gis": "Государственная информационная система",
    "ispdn": "Информационная система персональных данных",
    "kii": "Значимый объект критической информационной инфраструктуры",
    "other": "Иная информационная система",
}
REGIME_TITLES = {
    "117": "Приказ ФСТЭК России №117",
    "21": "Приказ ФСТЭК России №21",
    "239": "Приказ ФСТЭК России №239",
}
DIRECTION_TITLES = {"in": "входящее", "out": "исходящее", "both": "двустороннее"}
HOST_SOURCE_TITLES = {"scanner": "из «Сканера»", "manual": "вручную"}


def _d(v: date | datetime | None) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        v = v.date()
    return v.strftime("%d.%m.%Y")


def _s(v: Any) -> str | None:
    if v is None:
        return None
    v = str(v).strip()
    return v or None


def _label(defn: dict[str, Any], value: Any) -> str:
    options = {str(o.get("value")): o.get("label") for o in defn.get("options") or []}
    values = value if isinstance(value, list) else [value]
    return ", ".join(str(options.get(str(v), v)) for v in values)


def _inputs(cls: Classification) -> list[dict[str, Any]]:
    """Исходные данные расчёта с подписями из снимка таблицы классификации."""
    defs = {d.get("key"): d for d in (cls.table_snapshot or {}).get("inputs") or []}
    out = []
    for key, value in (cls.inputs or {}).items():
        d = defs.get(key) or {}
        out.append({"name": d.get("label") or key, "value": _label(d, value) if d else _s(value)})
    return out


def empty_classification() -> dict[str, Any]:
    """Раздел classification без утверждённого расчёта: те же ключи, пустые значения."""
    keys = ("result", "result_label", "regime_title", "approved", "approved_by")
    return {
        **dict.fromkeys((*keys, "justification", "table_version")),
        "steps": [],
        "inputs": [],
    }


def _classification(session: Session, obj: AssessedObject) -> Classification | None:
    return session.scalars(
        select(Classification)
        .where(Classification.object_id == obj.id, Classification.status == "approved")
        .order_by(Classification.approved_at.desc())
        .limit(1)
    ).first()


def _szi(session: Session, obj: AssessedObject, today: date) -> list[dict[str, Any]]:
    rows = list(
        session.scalars(
            select(ObjectSzi)
            .where(ObjectSzi.object_id == obj.id)
            .order_by(ObjectSzi.kind, ObjectSzi.name)
        )
    )
    index = szi_domain.registry_index(session, (r.cert_number for r in rows))
    loaded = bool(index) or (bool(rows) and szi_domain.registry_loaded(session))
    out = []
    for r in rows:
        st = szi_domain.cert_state(
            number=r.cert_number,
            manual_valid_to=r.cert_valid_to,
            manual_trust=r.trust_level,
            entry=index.get(r.cert_number or ""),
            registry_loaded=loaded,
            today=today,
            expiry_days=get_settings().szi_expiry_days,
        )
        out.append(
            {
                "name": r.name,
                "kind_title": szi_domain.KINDS.get(r.kind, r.kind),
                "vendor": _s(r.vendor),
                "version": _s(r.version),
                "cert_number": _s(r.cert_number),
                "valid_to": _d(st.valid_to),
                "trust_level": st.trust_level,
                "state_title": szi_domain.STATES[st.state][0],
                "placement": _s(r.placement),
                "measures": ", ".join(r.measure_ids or []) or None,
            }
        )
    return out


def build(session: Session, obj: AssessedObject, *, today: date | None = None) -> dict[str, Any]:
    """Контекст объекта для документов комплекта."""
    today = today or date.today()
    project = session.get(Project, obj.project_id)
    assert project is not None  # noqa: S101 — внешний ключ
    customer = project.customer
    cls = _classification(session, obj)
    segments = {s.id: s for s in obj.segments}

    unverified: list[dict[str, str]] = []
    classification = empty_classification()
    if cls is not None:
        defs = {d.get("key"): d for d in (cls.table_snapshot or {}).get("inputs") or []}
        labels = {k: d.get("label") or k for k, d in defs.items()}
        labels.update({t.get("key"): t.get("label") for t in cls.trace or [] if t.get("key")})
        classification = {
            "result": cls.result,
            "result_label": cls.result_label,
            "regime_title": REGIME_TITLES.get(cls.regime, cls.regime),
            "approved": _d(cls.approved_at),
            "approved_by": _s(cls.approved_by_name),
            "justification": _s(cls.justification),
            "table_version": cls.table_version,
            "steps": [
                {
                    "label": _s(t.get("label")) or t.get("key"),
                    "value": _s(t.get("value")),
                    "matched": "; ".join(
                        f"{labels.get(k, k)}: {_label(defs.get(k) or {}, v) if k in defs else v}"
                        for k, v in (t.get("matched") or {}).items()
                    )
                    or None,
                    "source": "; ".join(
                        str(x)
                        for x in (
                            (t.get("source") or {}).get("document"),
                            (t.get("source") or {}).get("clause"),
                        )
                        if x
                    )
                    or None,
                }
                for t in cls.trace or []
            ],
            "inputs": _inputs(cls),
        }
        if not cls.table_verified:
            unverified.append(
                {
                    "section": "classification",
                    "title": f"Таблица классификации ({REGIME_TITLES.get(cls.regime, cls.regime)})",
                    "note": f"версия {cls.table_version}, ревизия {cls.table_revision}",
                }
            )

    snap = sections.latest_snapshot(session, obj)
    measures, nonconf, u_measures = sections.measures_section(
        session, obj, snap, get_settings().partial_weight
    )
    threat_model, u_threats = sections.threat_model_section(session, obj)
    vulns, vuln_plan, u_vulns = sections.vulns_section(session, obj)
    _plan_overrides(session, obj, nonconf, vuln_plan)
    org, u_org = sections.org_docs_section(
        get_settings().reference_dir, measures, _profile_id(session, obj)
    )
    unverified += u_measures + u_threats + u_vulns + u_org

    return {
        "customer": {
            "name": _s(customer.name),
            "inn": _s(customer.inn),
            "ogrn": _s(customer.ogrn),
            "address": _s(customer.address),
        },
        "project": {
            "name": project.name,
            "contract_ref": _s(project.contract_ref),
            "period_from": _d(project.period_from),
            "period_to": _d(project.period_to),
        },
        "object": {
            "name": obj.name,
            "kind": obj.kind,
            "kind_title": KIND_TITLES.get(obj.kind, obj.kind),
            "regime": obj.regime,
            "regime_title": REGIME_TITLES.get(obj.regime or "", None),
            "purpose": _s(obj.purpose),
            "boundaries": _s(obj.boundaries),
            "internet_title": "есть" if obj.internet else "нет",
            "responsible": [
                {
                    "name": _s(r.get("name")),
                    "position": _s(r.get("position")),
                    "role": _s(r.get("role")),
                    "phone": _s(r.get("phone")),
                    "email": _s(r.get("email")),
                }
                for r in obj.responsible or []
            ],
            "interconnections": [
                {
                    "system": _s(i.get("system")),
                    "owner": _s(i.get("owner")),
                    "direction_title": DIRECTION_TITLES.get(i.get("direction") or "both"),
                    "channel": _s(i.get("channel")),
                    "description": _s(i.get("description")),
                }
                for i in obj.interconnections or []
            ],
        },
        "classification": classification,
        "segments": [
            {
                "name": s.name,
                "description": _s(s.description),
                "host_count": sum(1 for h in obj.hosts if h.segment_id == s.id),
            }
            for s in obj.segments
        ],
        "hosts": [
            {
                "address": h.address,
                "hostname": _s(h.hostname),
                "role": _s(h.role),
                "os": _s(h.os),
                "segment": segments[h.segment_id].name if h.segment_id in segments else None,
                "source_title": HOST_SOURCE_TITLES.get(h.source, h.source),
                "internet_title": {True: "да", False: "нет"}.get(h.internet_exposed),  # type: ignore[arg-type]
            }
            for h in obj.hosts
        ],
        "szi": _szi(session, obj, today),
        "snapshot": sections.snapshot_section(snap),
        "measures": measures,
        "threat_model": threat_model,
        "vulns": vulns,
        # План устранения: меры с нарушениями, затем уязвимости по уровню.
        "nonconformities": nonconf,
        "vuln_plan": vuln_plan,
        "org": org,
        "normative": sections.normative_section(
            session, [c for c in NORMATIVE.get(obj.regime or "", ())]
        ),
        "unverified": unverified,
    }


_PLAN_KEYS = ("responsible", "due", "priority_title", "method_title", "ticket", "state_title")


def _plan_overrides(
    session: Session, obj: AssessedObject, nonconf: list[dict], vuln_plan: list[dict]
) -> None:
    """Мероприятие, ответственный, срок, способ и заявка из плана (задача 3.4)."""
    from app.api.nonconformities import document_overrides

    ov = document_overrides(session, obj)
    for kind, rows in (("measure", nonconf), ("vuln", vuln_plan)):
        for row in rows:
            key = row["ref"] if kind == "measure" else row.pop("vuln_id", None)
            o = ov.get((kind, str(key)), {})
            if o.get("action"):
                row["action"] = o["action"]
            for k in _PLAN_KEYS:
                row[k] = o.get(k)


# Разделы контекста (ключи верхнего уровня) — их может использовать свой шаблон.
CONTEXT_KEYS = (
    "customer",
    "project",
    "object",
    "classification",
    "segments",
    "hosts",
    "szi",
    "snapshot",
    "measures",
    "threat_model",
    "vulns",
    "nonconformities",
    "vuln_plan",
    "org",
    "normative",
    "unverified",
)


# Нормативные документы, на которые ссылается комплект (коды ref_documents).
NORMATIVE = {
    "117": ("fstec-117", "fstec-threats-2021", "fstec-vuln-2025", "fstec-updates-2022"),
    "21": ("fstec-21", "fstec-threats-2021", "fstec-vuln-2025", "fstec-updates-2022"),
    "239": ("fstec-239", "fstec-threats-2021", "fstec-vuln-2025", "fstec-updates-2022"),
    "": ("fstec-threats-2021", "fstec-vuln-2025"),
}


def _profile_id(session: Session, obj: AssessedObject) -> str | None:
    return session.scalars(
        select(ObjectMeasure.profile_id).where(ObjectMeasure.object_id == obj.id).limit(1)
    ).first()


def context_hash(context: dict[str, Any], template_sha256: str) -> str:
    """Хэш данных и шаблона: одинаковый — документ не изменился бы."""
    raw = json.dumps(
        {"context": context, "template": template_sha256},
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(raw.encode()).hexdigest()
