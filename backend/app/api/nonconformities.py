"""Несоответствия и план устранения; заявки в «Устранении» (задача 3.4).

GET   /objects/{id}/nonconformities             — план объекта (собирается из мер и реестра)
POST  /objects/{id}/nonconformities/send        — отправить выбранные пункты в «Устранение»
POST  /objects/{id}/nonconformities/vm-refresh  — опросить «Устранение» о статусах заявок
GET   /nonconformities/{id}                     — пункт плана с историей
PATCH /nonconformities/{id}                     — мероприятие, ответственный, срок, способ
POST  /nonconformities/{id}/send                — отправить (повторно) один пункт
GET   /object-measures/{id}/nonconformity       — пункт плана по мере (шторка меры)
POST  /events                                   — события «Устранения» / «Платформы»:
                                                  vm.ticket.status_changed, vm.remediation.verified

Подпись события — `X-Signature: sha256=<HMAC-SHA256 тела>` общим секретом
GRC_EVENTS_SECRET (контракт платформы v1, п. 6); обработка идемпотентна по id
события (таблица inbox).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import UTC, date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.objects import INVENTORY_METHODOLOGY, _editable, get_object_for
from app.core.config import get_settings
from app.core.rbac import Perm
from app.db.models import (
    AssessedObject,
    Evidence,
    InboxEvent,
    Nonconformity,
    NonconformityEvent,
    ObjectMeasure,
    ObjectVuln,
    Project,
    RefVulnMethodology,
    User,
    utcnow,
)
from app.domain import nonconformities as nc_rules
from app.domain.measures import Item, effective_status
from app.integrations.vm.client import VmClient, VmError, get_vm_client

router = APIRouter(tags=["nonconformities"])

Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Assessor = Annotated[User, Depends(require(Perm.ASSESSMENT_EDIT))]
Vm = Annotated[VmClient, Depends(get_vm_client)]

NONCONFORMING = ("not_implemented", "partial")
MEASURE_STATUS_TITLES = {
    "implemented": "Реализована",
    "partial": "Реализована частично",
    "not_implemented": "Не реализована",
    "not_applicable": "Не применима",
    "unassessed": "Не оценена",
}
LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}
VM_ACTOR = "«Устранение»"


# ---------- Схемы ----------


class EventOut(BaseModel):
    at: datetime
    kind: str
    text: str
    actor_name: str | None


class NcOut(BaseModel):
    id: uuid.UUID
    kind: str
    ref: str
    title: str
    object_measure_id: uuid.UUID | None
    object_vuln_id: uuid.UUID | None
    source_status: str | None
    source_status_title: str | None
    measure_method: str | None
    hosts: list[str]
    details: str | None
    v: str | None
    level: str | None
    level_title: str | None
    assessed_at: datetime | None
    deadline_at: datetime | None
    certified_szi: bool
    priority: str | None
    due_date: date | None
    action: str | None
    default_action: str
    responsible: str | None
    comment: str | None
    method: str | None
    update_origin: str | None
    update_tested: bool | None
    compensating: list[str]
    opened_at: datetime
    closed_at: datetime | None
    close_reason: str | None
    state: str
    state_title: str
    overdue: bool
    send_blocker: str | None
    resend: bool
    warnings: list[str]
    vm_ticket_id: str | None
    vm_status: str | None
    vm_status_title: str | None
    vm_status_at: datetime | None
    vm_verified_result: str | None
    vm_verified_at: datetime | None
    vm_verified_run_id: str | None
    ticket_url: str | None
    sent_at: datetime | None
    sent_by_name: str | None
    updated_at: datetime
    updated_by_name: str | None


class NcDetail(NcOut):
    history: list[EventOut]


class VmInfo(BaseModel):
    mode: str
    source: str
    project_id: str | None
    events: bool


class PlanOut(BaseModel):
    object_id: uuid.UUID
    vm: VmInfo
    compensating_measures: list[dict[str, str]]
    counts: dict[str, int]
    items: list[NcOut]


class NcPatch(BaseModel):
    action: str | None = Field(default=None, max_length=2000)
    responsible: str | None = Field(default=None, max_length=300)
    comment: str | None = Field(default=None, max_length=2000)
    priority: str | None = None
    due_date: date | None = None
    method: str | None = None
    update_origin: str | None = None
    update_tested: bool | None = None
    compensating: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("action", "responsible", "comment")
    @classmethod
    def _strip(cls, v: str | None) -> str | None:
        v = (v or "").strip()
        return v or None


class SendIn(BaseModel):
    ids: list[uuid.UUID] = Field(min_length=1, max_length=500)


class SendResult(BaseModel):
    id: uuid.UUID
    ok: bool
    ticket_id: str | None = None
    error: str | None = None
    # Ошибка связи с «Устранением» (а не правило «Аттестации»).
    vm_error: bool = False


class SendOut(BaseModel):
    sent: int
    results: list[SendResult]


class RefreshOut(BaseModel):
    checked: int
    changed: int
    errors: list[str]


# ---------- Справочник Методики: компенсирующие меры п. 25 ----------


def compensating_catalog(session: Session) -> list[dict[str, str]]:
    m = session.get(RefVulnMethodology, INVENTORY_METHODOLOGY)
    items = ((m.definition or {}).get("compensating_measures") or {}).get("items") if m else None
    return [{"code": str(i["code"]), "title": str(i["title"])} for i in items or []]


# ---------- Сборка плана ----------


def _event(
    session: Session, nc: Nonconformity, kind: str, text: str, actor: str | None, **data: Any
) -> None:
    session.add(
        NonconformityEvent(
            nonconformity_id=nc.id, kind=kind, text=text, actor_name=actor, data=data, at=utcnow()
        )
    )


def _set(nc: Nonconformity, **values: Any) -> bool:
    changed = False
    for k, v in values.items():
        if getattr(nc, k) != v:
            setattr(nc, k, v)
            changed = True
    return changed


def _close(session: Session, nc: Nonconformity, reason: str, actor: str | None) -> None:
    nc.closed_at = utcnow()
    nc.close_reason = reason
    _event(session, nc, "closed", f"Закрыто: {reason}", actor)


def _reopen(session: Session, nc: Nonconformity, why: str, actor: str | None) -> None:
    nc.closed_at = None
    nc.close_reason = None
    _event(session, nc, "reopened", f"Снова несоответствие: {why}", actor)


def _sync_measures(session: Session, obj: AssessedObject, actor: str | None) -> bool:
    from app.docs_gen import sections

    ms = list(session.scalars(select(ObjectMeasure).where(ObjectMeasure.object_id == obj.id)))
    items = [
        Item(m.measure_id, m.method, m.status, m.adaptation, tuple(m.compensating_ids or ()))
        for m in ms
    ]
    by_id = {i.measure_id: i for i in items}
    snap = sections.latest_snapshot(session, obj)
    auto_ev, _ = sections._evidence_by_measure(session, obj, snap)
    existing = {
        nc.object_measure_id: nc
        for nc in session.scalars(
            select(Nonconformity).where(
                Nonconformity.object_id == obj.id, Nonconformity.kind == "measure"
            )
        )
    }
    changed = False
    for m, item in zip(ms, items, strict=True):
        eff = effective_status(item, by_id)
        nc = existing.get(m.id)
        if eff in NONCONFORMING:
            auto_text, failed = sections._auto_text(auto_ev.get(m.id))
            details = "; ".join(x for x in (auto_text, m.comment) if x) or None
            if nc is None:
                nc = Nonconformity(
                    id=uuid.uuid4(),
                    object_id=obj.id,
                    project_id=obj.project_id,
                    kind="measure",
                    object_measure_id=m.id,
                    ref=m.measure_id,
                    title=m.title,
                    priority="high" if eff == "not_implemented" else "medium",
                    opened_at=utcnow(),
                    updated_at=utcnow(),
                    compensating=[],
                )
                session.add(nc)
                session.flush()
                _event(
                    session,
                    nc,
                    "opened",
                    f"Мера {m.measure_id}: {MEASURE_STATUS_TITLES[eff].lower()}",
                    actor,
                )
                changed = True
            elif nc.closed_at is not None:
                _reopen(session, nc, MEASURE_STATUS_TITLES[eff].lower(), actor)
                changed = True
            changed |= _set(
                nc,
                title=m.title,
                source_status=eff,
                hosts=failed,
                details=details[:4000] if details else None,
            )
        elif nc is not None and nc.closed_at is None:
            if m.adaptation == "excluded":
                reason = "мера исключена при адаптации"
            else:
                reason = f"статус меры — «{MEASURE_STATUS_TITLES.get(eff or 'not_applicable')}»"
            _close(session, nc, reason, actor)
            nc.source_status = eff
            changed = True
    return changed


def _sync_vulns(session: Session, obj: AssessedObject, actor: str | None) -> bool:
    from app.api.object_vulns import register

    m = session.get(RefVulnMethodology, INVENTORY_METHODOLOGY)
    if m is None:
        return False
    try:
        reg = register(session, obj, m)
    except HTTPException:
        return False
    vulns = {
        v.id: v for v in session.scalars(select(ObjectVuln).where(ObjectVuln.object_id == obj.id))
    }
    existing = {
        nc.object_vuln_id: nc
        for nc in session.scalars(
            select(Nonconformity).where(
                Nonconformity.object_id == obj.id, Nonconformity.kind == "vuln"
            )
        )
    }
    snap = reg.snapshot.number if reg.snapshot else None
    changed = False
    for r in reg.items:
        nc = existing.get(r.id)
        detected = r.state != "not_detected"
        if detected:
            a = r.current
            if nc is None:
                nc = Nonconformity(
                    id=uuid.uuid4(),
                    object_id=obj.id,
                    project_id=obj.project_id,
                    kind="vuln",
                    object_vuln_id=r.id,
                    ref=r.bdu_id or "без БДУ",
                    title=r.title,
                    opened_at=utcnow(),
                    updated_at=utcnow(),
                    compensating=[],
                )
                session.add(nc)
                session.flush()
                src = r.manual_source_title or "«Сканер»"
                _event(session, nc, "opened", f"Уязвимость в реестре объекта ({src})", actor)
                changed = True
            elif nc.closed_at is not None:
                _reopen(session, nc, "уязвимость снова обнаружена", actor)
                changed = True
            v = vulns.get(r.id)
            changed |= _set(
                nc,
                title=r.title[:2000],
                source_status=r.state,
                hosts=list(r.hosts),
                assessment_id=a.id if a else None,
                v=a.v if a else None,
                level=a.level if a else None,
                level_title=a.level_title if a else None,
                assessed_at=a.assessed_at if a else None,
                deadline_at=a.deadline_at if a else None,
                certified_szi=bool(v and v.certified_szi),
            )
        elif nc is not None and nc.closed_at is None:
            where = f" в снимке №{snap}" if snap else ""
            _close(session, nc, f"уязвимость не обнаружена{where}", actor)
            nc.source_status = r.state
            changed = True
    return changed


def sync_plan(session: Session, obj: AssessedObject, actor: str | None = None) -> None:
    """Приводит план объекта к текущим мерам и реестру уязвимостей (фиксирует сам)."""
    changed = _sync_measures(session, obj, actor)
    changed |= _sync_vulns(session, obj, actor)
    if changed:
        session.commit()


# ---------- Заявка для «Устранения» ----------


def _vm_project(project: Project) -> str | None:
    if project.vm_project_id:
        return project.vm_project_id
    return str(project.platform_project_id) if project.platform_project_id else None


def default_action(nc: Nonconformity) -> str:
    if nc.kind == "measure":
        return f"Реализовать меру {nc.ref} «{nc.title}»" + (
            " на хостах с нарушениями" if nc.hosts else ""
        )
    if nc.method == "update":
        return "Установить обновление безопасности"
    if nc.method == "compensating":
        return "Принять компенсирующие меры (п. 25 Методики)"
    return "Устранить уязвимость (обновление или компенсирующие меры)"


def send_blocker(nc: Nonconformity, measure: ObjectMeasure | None) -> str | None:
    if nc.closed_at is not None:
        return "Пункт закрыт"
    if nc.kind == "vuln":
        if not nc.level:
            return "Сначала оцените уязвимость: в «Устранение» уходят V, уровень и срок"
        if not nc.hosts:
            return "У уязвимости нет хостов"
        return None
    if measure is not None and measure.method == "manual":
        return "Организационная мера устраняется документами, а не заявкой"
    if not nc.hosts:
        return "«Сканер» не указал хосты с нарушениями — заявку не на что ставить"
    return None


def build_payload(
    nc: Nonconformity,
    obj: AssessedObject,
    project: Project,
    measure: ObjectMeasure | None,
    catalog: dict[str, str],
) -> dict[str, Any]:
    s = get_settings()
    link = f"{s.base_path.rstrip('/')}/objects/{obj.id}?tab=plan&project={project.id}&item={nc.id}"
    body: dict[str, Any] = {
        "source": "grc",
        "external_id": str(nc.id),
        "kind": "vulnerability" if nc.kind == "vuln" else "measure",
        "grc_project_id": str(project.id),
        "object": {"id": str(obj.id), "name": obj.name},
        "title": (f"{nc.ref}: {nc.title}" if nc.kind == "vuln" else f"Мера {nc.ref}: {nc.title}")[
            :500
        ],
        "action": nc.action or default_action(nc),
        "details": nc.details,
        "hosts": list(nc.hosts or []),
        "responsible": nc.responsible,
        "remediation": {
            "method": nc.method,
            "update_origin": nc.update_origin,
            "update_tested": nc.update_tested,
            "compensating": [
                {"code": c, "title": catalog.get(c, c)} for c in nc.compensating or []
            ],
        },
        "link": link,
    }
    if nc.kind == "vuln":
        body["vulnerability"] = {
            "bdu_id": nc.ref if nc.ref.startswith("BDU:") else None,
            "v": nc.v,
            "level": nc.level,
            "level_title": nc.level_title,
            "assessed_at": _iso(nc.assessed_at),
            "deadline_at": _iso(nc.deadline_at),
            "certified_szi": nc.certified_szi,
            "up_to_date": nc.source_status == "current",
            "assessment_id": str(nc.assessment_id) if nc.assessment_id else None,
            "methodology": "ФСТЭК России, Методика оценки уровня критичности уязвимостей, 2025",
        }
    else:
        body["measure"] = {
            "measure_id": nc.ref,
            "profile_id": measure.profile_id if measure else None,
            "status": nc.source_status,
            "priority": nc.priority,
            "due_date": nc.due_date.isoformat() if nc.due_date else None,
        }
    return body


def _iso(at: datetime | None) -> str | None:
    if at is None:
        return None
    return (at if at.tzinfo else at.replace(tzinfo=UTC)).isoformat()


def _ticket_url(nc: Nonconformity) -> str | None:
    s = get_settings()
    base = s.vm_web_url.rstrip("/")
    if not base and s.auth_mode == "platform":
        # Межпродуктовая ссылка того же origin: /vm/tickets/<id>?project=<uuid> (контракт, п. 7).
        base = "/vm"
    if not base or not nc.vm_ticket_id:
        return None
    q = f"?project={nc.vm_project_id}" if nc.vm_project_id else ""
    return f"{base}/tickets/{nc.vm_ticket_id}{q}"


# ---------- Вывод ----------


class _View:
    """Общие данные для вывода нескольких пунктов одного объекта."""

    def __init__(self, session: Session, obj: AssessedObject) -> None:
        self.session = session
        self.obj = obj
        project = session.get(Project, obj.project_id)
        assert project is not None  # noqa: S101 — внешний ключ
        self.project = project
        self.catalog = {c["code"]: c["title"] for c in compensating_catalog(session)}
        self.measures = {
            m.id: m
            for m in session.scalars(select(ObjectMeasure).where(ObjectMeasure.object_id == obj.id))
        }
        self.now = datetime.now(UTC)

    def out(self, nc: Nonconformity) -> NcOut:
        st = nc_rules.state(nc.closed_at, nc.vm_ticket_id, nc.vm_status)
        measure = self.measures.get(nc.object_measure_id) if nc.object_measure_id else None
        resend = bool(
            nc.sent_hash
            and st not in ("closed", "verified")
            and nc.sent_hash
            != nc_rules.payload_hash(
                build_payload(nc, self.obj, self.project, measure, self.catalog)
            )
        )
        if nc.kind == "measure":
            source_title = MEASURE_STATUS_TITLES.get(nc.source_status or "", nc.source_status)
        else:
            from app.api.object_vulns import STATES

            source_title = STATES.get(nc.source_status or "", nc.source_status)
        return NcOut(
            id=nc.id,
            kind=nc.kind,
            ref=nc.ref,
            title=nc.title,
            object_measure_id=nc.object_measure_id,
            object_vuln_id=nc.object_vuln_id,
            source_status=nc.source_status,
            source_status_title=source_title,
            measure_method=measure.method if measure else None,
            hosts=list(nc.hosts or []),
            details=nc.details,
            v=nc.v,
            level=nc.level,
            level_title=nc.level_title,
            assessed_at=nc.assessed_at,
            deadline_at=nc.deadline_at,
            certified_szi=nc.certified_szi,
            priority=nc.priority,
            due_date=nc.due_date,
            action=nc.action,
            default_action=default_action(nc),
            responsible=nc.responsible,
            comment=nc.comment,
            method=nc.method,
            update_origin=nc.update_origin,
            update_tested=nc.update_tested,
            compensating=list(nc.compensating or []),
            opened_at=nc.opened_at,
            closed_at=nc.closed_at,
            close_reason=nc.close_reason,
            state=st,
            state_title=nc_rules.STATES[st],
            overdue=nc_rules.overdue(
                kind=nc.kind,
                st=st,
                deadline_at=nc.deadline_at,
                due_date=nc.due_date,
                now=self.now,
            ),
            send_blocker=send_blocker(nc, measure),
            resend=resend,
            warnings=nc_rules.warnings(
                kind=nc.kind,
                st=st,
                method=nc.method,
                update_origin=nc.update_origin,
                update_tested=nc.update_tested,
                resend=resend,
                assessed=bool(nc.level),
            ),
            vm_ticket_id=nc.vm_ticket_id,
            vm_status=nc.vm_status,
            vm_status_title=nc_rules.VM_STATUSES.get(nc.vm_status or "", nc.vm_status),
            vm_status_at=nc.vm_status_at,
            vm_verified_result=nc.vm_verified_result,
            vm_verified_at=nc.vm_verified_at,
            vm_verified_run_id=nc.vm_verified_run_id,
            ticket_url=_ticket_url(nc),
            sent_at=nc.sent_at,
            sent_by_name=nc.sent_by_name,
            updated_at=nc.updated_at,
            updated_by_name=nc.updated_by_name,
        )

    def detail(self, nc: Nonconformity) -> NcDetail:
        history = self.session.scalars(
            select(NonconformityEvent)
            .where(NonconformityEvent.nonconformity_id == nc.id)
            .order_by(NonconformityEvent.at.desc())
        )
        return NcDetail(
            **self.out(nc).model_dump(),
            history=[
                EventOut(at=e.at, kind=e.kind, text=e.text, actor_name=e.actor_name)
                for e in history
            ],
        )


def _sort_key(n: NcOut) -> tuple:
    closed = n.state == "closed"
    if n.kind == "measure":
        return (closed, 0, PRIORITY_ORDER.get(n.priority or "", 9), n.ref)
    return (closed, 1, LEVEL_ORDER.get(n.level or "", 9), -float(n.v or 0), n.ref)


def plan_items(session: Session, obj: AssessedObject) -> list[NcOut]:
    """Пункты плана объекта (без синхронизации) — экран и документы комплекта."""
    view = _View(session, obj)
    rows = session.scalars(select(Nonconformity).where(Nonconformity.object_id == obj.id))
    return sorted((view.out(nc) for nc in rows), key=_sort_key)


def _get(session: Session, nc_id: uuid.UUID, user: User) -> tuple[Nonconformity, AssessedObject]:
    nc = session.get(Nonconformity, nc_id)
    if nc is None:
        raise HTTPException(404, detail="Пункт плана не найден")
    try:
        obj = get_object_for(session, nc.object_id, user)
    except HTTPException as e:
        raise HTTPException(404, detail="Пункт плана не найден") from e
    return nc, obj


# ---------- Эндпоинты ----------


@router.get("/objects/{object_id}/nonconformities", response_model=PlanOut)
def get_plan(object_id: uuid.UUID, user: Viewer, session: DbSession, vm: Vm) -> PlanOut:
    obj = get_object_for(session, object_id, user)
    sync_plan(session, obj)
    items = plan_items(session, obj)
    active = [i for i in items if i.state != "closed"]
    counts = {
        "total": len(active),
        "measures": sum(1 for i in active if i.kind == "measure"),
        "vulns": sum(1 for i in active if i.kind == "vuln"),
        "open": sum(1 for i in active if i.state == "open"),
        "in_vm": sum(1 for i in active if i.vm_ticket_id and i.state != "verified"),
        "verified": sum(1 for i in active if i.state == "verified"),
        "decision": sum(1 for i in active if i.state == "decision"),
        "overdue": sum(1 for i in active if i.overdue),
        "resend": sum(1 for i in active if i.resend),
        "closed": len(items) - len(active),
        **{lv: sum(1 for i in active if i.level == lv) for lv in LEVEL_ORDER},
    }
    project = session.get(Project, obj.project_id)
    assert project is not None  # noqa: S101
    return PlanOut(
        object_id=obj.id,
        vm=VmInfo(
            mode=vm.mode,
            source=vm.source,
            project_id=_vm_project(project),
            events=bool(get_settings().events_secret),
        ),
        compensating_measures=compensating_catalog(session),
        counts=counts,
        items=items,
    )


@router.get("/nonconformities/{nc_id}", response_model=NcDetail)
def get_item(nc_id: uuid.UUID, user: Viewer, session: DbSession) -> NcDetail:
    nc, obj = _get(session, nc_id, user)
    return _View(session, obj).detail(nc)


@router.get("/object-measures/{measure_id}/nonconformity", response_model=NcOut | None)
def get_for_measure(measure_id: uuid.UUID, user: Viewer, session: DbSession) -> NcOut | None:
    m = session.get(ObjectMeasure, measure_id)
    if m is None:
        raise HTTPException(404, detail="Мера не найдена")
    obj = get_object_for(session, m.object_id, user)
    sync_plan(session, obj)
    nc = session.scalars(
        select(Nonconformity).where(Nonconformity.object_measure_id == m.id)
    ).first()
    return _View(session, obj).out(nc) if nc else None


@router.patch("/nonconformities/{nc_id}", response_model=NcDetail)
def update_item(
    nc_id: uuid.UUID, body: NcPatch, request: Request, user: Assessor, session: DbSession
) -> NcDetail:
    nc, obj = _get(session, nc_id, user)
    _editable(session, obj)
    if nc.closed_at is not None:
        raise HTTPException(409, detail="Пункт закрыт: источник больше не несоответствие")
    if body.priority is not None and body.priority not in nc_rules.PRIORITIES:
        raise HTTPException(422, detail="Приоритет — высокий, средний или низкий")
    values: dict[str, Any] = {
        "action": body.action,
        "responsible": body.responsible,
        "comment": body.comment,
    }
    if nc.kind == "measure":
        if body.method is not None:
            raise HTTPException(422, detail="Способ устранения указывается для уязвимостей")
        values |= {"priority": body.priority, "due_date": body.due_date}
    else:
        if body.due_date is not None or body.priority is not None:
            raise HTTPException(
                422,
                detail="Срок и уровень уязвимости — из её оценки по Методике (п. 21), "
                "вручную не меняются",
            )
        known = {c["code"] for c in compensating_catalog(session)}
        try:
            r = nc_rules.check_remediation(
                body.method, body.update_origin, body.update_tested, body.compensating, known
            )
        except nc_rules.PlanError as e:
            raise HTTPException(422, detail=str(e)) from e
        values |= {
            "method": r.method,
            "update_origin": r.update_origin,
            "update_tested": r.update_tested,
            "compensating": r.compensating,
        }
    before = {k: getattr(nc, k) for k in values}
    changed = {k: v for k, v in values.items() if before[k] != v}
    if changed:
        for k, v in changed.items():
            setattr(nc, k, v)
        nc.updated_at = utcnow()
        nc.updated_by_name = user.display_name
        _event(
            session,
            nc,
            "edited",
            "Изменено: " + ", ".join(_FIELD_TITLES.get(k, k) for k in changed),
            user.display_name,
        )
        audit.record(
            session,
            action="nonconformity.update",
            actor=user,
            entity="nonconformity",
            entity_id=nc.id,
            project_id=nc.project_id,
            ip=client_ip(request),
            details={"ref": nc.ref, "fields": sorted(changed)},
        )
        session.commit()
    return _View(session, obj).detail(nc)


_FIELD_TITLES = {
    "action": "мероприятие",
    "responsible": "ответственный",
    "comment": "комментарий",
    "priority": "приоритет",
    "due_date": "срок",
    "method": "способ устранения",
    "update_origin": "вид ПО",
    "update_tested": "отметка о тестировании",
    "compensating": "компенсирующие меры",
}


def _send_one(
    session: Session, view: _View, nc: Nonconformity, vm: VmClient, user: User, ip: str | None
) -> SendResult:
    measure = view.measures.get(nc.object_measure_id) if nc.object_measure_id else None
    blocker = send_blocker(nc, measure)
    if blocker:
        return SendResult(id=nc.id, ok=False, error=blocker)
    vm_project = _vm_project(view.project)
    if not vm_project:
        return SendResult(
            id=nc.id,
            ok=False,
            error="У проекта не указан проект в «Устранении» (карточка проекта)",
        )
    payload = build_payload(nc, view.obj, view.project, measure, view.catalog)
    try:
        ticket = vm.upsert_ticket(vm_project, payload)
    except VmError as e:
        audit.record(
            session,
            action="nonconformity.send",
            actor=user,
            entity="nonconformity",
            entity_id=nc.id,
            project_id=nc.project_id,
            result="error",
            ip=ip,
            details={"ref": nc.ref, "error": str(e), "code": e.code},
        )
        return SendResult(id=nc.id, ok=False, error=str(e), vm_error=True)
    first = nc.vm_ticket_id is None
    nc.vm_ticket_id = ticket.id
    nc.vm_project_id = vm_project
    if first or nc.vm_status is None:
        nc.vm_status = ticket.status
        nc.vm_status_at = utcnow()
    nc.sent_at = utcnow()
    nc.sent_by = user.id
    nc.sent_by_name = user.display_name
    nc.sent_hash = nc_rules.payload_hash(payload)
    _event(
        session,
        nc,
        "sent",
        f"{'Отправлено' if first else 'Отправлено повторно'} в «Устранение»: заявка №{ticket.id}",
        user.display_name,
        ticket_id=ticket.id,
    )
    audit.record(
        session,
        action="nonconformity.send",
        actor=user,
        entity="nonconformity",
        entity_id=nc.id,
        project_id=nc.project_id,
        ip=ip,
        details={
            "ref": nc.ref,
            "ticket_id": ticket.id,
            "vm_project_id": vm_project,
            "level": nc.level,
            "v": nc.v,
            "deadline_at": _iso(nc.deadline_at),
            "repeat": not first,
        },
    )
    return SendResult(id=nc.id, ok=True, ticket_id=ticket.id)


@router.post("/nonconformities/{nc_id}/send", response_model=NcDetail)
def send_item(
    nc_id: uuid.UUID, request: Request, user: Assessor, session: DbSession, vm: Vm
) -> NcDetail:
    nc, obj = _get(session, nc_id, user)
    _editable(session, obj)
    view = _View(session, obj)
    r = _send_one(session, view, nc, vm, user, client_ip(request))
    session.commit()
    if not r.ok:
        raise HTTPException(502 if r.vm_error else 409, detail=r.error)
    return view.detail(nc)


@router.post("/objects/{object_id}/nonconformities/send", response_model=SendOut)
def send_many(
    object_id: uuid.UUID,
    body: SendIn,
    request: Request,
    user: Assessor,
    session: DbSession,
    vm: Vm,
) -> SendOut:
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    view = _View(session, obj)
    rows = {
        nc.id: nc
        for nc in session.scalars(
            select(Nonconformity).where(
                Nonconformity.object_id == obj.id, Nonconformity.id.in_(body.ids)
            )
        )
    }
    results = []
    ip = client_ip(request)
    for i in dict.fromkeys(body.ids):
        nc = rows.get(i)
        if nc is None:
            results.append(SendResult(id=i, ok=False, error="Пункт плана не найден"))
            continue
        results.append(_send_one(session, view, nc, vm, user, ip))
    session.commit()
    return SendOut(sent=sum(1 for r in results if r.ok), results=results)


@router.post("/objects/{object_id}/nonconformities/vm-refresh", response_model=RefreshOut)
def refresh_statuses(
    object_id: uuid.UUID, request: Request, user: Assessor, session: DbSession, vm: Vm
) -> RefreshOut:
    """Опрос «Устранения» (режим local без событий): статусы отправленных заявок."""
    obj = get_object_for(session, object_id, user)
    rows = list(
        session.scalars(
            select(Nonconformity).where(
                Nonconformity.object_id == obj.id,
                Nonconformity.vm_ticket_id.is_not(None),
                Nonconformity.closed_at.is_(None),
            )
        )
    )
    changed, errors = 0, []
    for nc in rows:
        try:
            t = vm.ticket(nc.vm_ticket_id or "")
        except VmError as e:
            errors.append(str(e))
            break
        if t is None or t.status == nc.vm_status:
            continue
        apply_status(session, nc, t.status, utcnow(), via="опрос")
        changed += 1
    audit.record(
        session,
        action="nonconformity.vm_refresh",
        actor=user,
        entity="object",
        entity_id=obj.id,
        project_id=obj.project_id,
        result="error" if errors else "ok",
        ip=client_ip(request),
        details={"checked": len(rows), "changed": changed},
    )
    session.commit()
    return RefreshOut(checked=len(rows), changed=changed, errors=errors)


# ---------- События «Устранения» ----------


def apply_status(
    session: Session, nc: Nonconformity, status: str, at: datetime, via: str = "событие"
) -> None:
    old = nc.vm_status
    nc.vm_status = status
    nc.vm_status_at = at
    title = nc_rules.VM_STATUSES.get(status, status)
    _event(
        session,
        nc,
        "vm_status",
        f"Заявка №{nc.vm_ticket_id}: {title}"
        + (f" (было: {nc_rules.VM_STATUSES.get(old, old)})" if old else ""),
        VM_ACTOR,
        status=status,
        via=via,
    )


def apply_verified(
    session: Session, nc: Nonconformity, result: str, run_id: str | None, at: datetime
) -> None:
    nc.vm_verified_result = result
    nc.vm_verified_at = at
    nc.vm_verified_run_id = run_id
    title = nc_rules.VERIFY_RESULTS.get(result, result)
    run = f", прогон «Сканера» №{run_id}" if run_id else ""
    _event(
        session,
        nc,
        "vm_verified",
        f"Повторная проверка «Устранения»: {title}{run}",
        VM_ACTOR,
        result=result,
        run_id=run_id,
    )
    if result == "verified" and nc.kind == "measure" and nc.object_measure_id:
        m = session.get(ObjectMeasure, nc.object_measure_id)
        if m is not None:
            session.add(
                Evidence(
                    object_measure_id=m.id,
                    object_id=m.object_id,
                    project_id=m.project_id,
                    measure_id=m.measure_id,
                    kind="remediation",
                    summary=(
                        f"«Устранение»: исправление по заявке №{nc.vm_ticket_id} подтверждено "
                        f"повторной проверкой «Сканера»{run}"
                    )[:1000],
                    data={
                        "ticket_id": nc.vm_ticket_id,
                        "run_id": run_id,
                        "result": result,
                        "hosts": list(nc.hosts or []),
                        "nonconformity_id": str(nc.id),
                    },
                    created_by_name=VM_ACTOR,
                )
            )


def handle_event(session: Session, envelope: dict[str, Any]) -> str:
    """Обрабатывает событие «Устранения»; возвращает итог для inbox (без фиксации)."""
    etype = envelope.get("type")
    data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
    if etype not in ("vm.ticket.status_changed", "vm.remediation.verified"):
        return "ignored"
    tid = data.get("ticket_id")
    if tid is None or isinstance(tid, bool):
        return "ignored"
    rows = list(
        session.scalars(select(Nonconformity).where(Nonconformity.vm_ticket_id == str(tid)))
    )
    project = envelope.get("project_id")
    if project:
        rows = [r for r in rows if r.vm_project_id in (None, str(project))] or rows
    if not rows:
        return "unknown_ticket"
    at = _parse_time(envelope.get("time")) or utcnow()
    result = "applied"
    for nc in rows:
        if etype == "vm.ticket.status_changed":
            to = data.get("to") or data.get("status")
            if not isinstance(to, str) or not to:
                return "ignored"
            last = nc.vm_status_at
            if last is not None and (last if last.tzinfo else last.replace(tzinfo=UTC)) > at:
                result = "stale"  # событие пришло позже более нового статуса
                continue
            apply_status(session, nc, to, at)
        else:
            res = data.get("result")
            if not isinstance(res, str) or not res:
                return "ignored"
            run = data.get("scanner_run_id") or data.get("run_id")
            apply_verified(session, nc, res, None if run is None else str(run), at)
        audit.record(
            session,
            action=f"nonconformity.{etype}",
            actor_name=VM_ACTOR,
            entity="nonconformity",
            entity_id=nc.id,
            project_id=nc.project_id,
            details={"event_id": envelope.get("id"), "ticket_id": str(tid), **data},
        )
    return result


def _parse_time(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    try:
        at = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    return at if at.tzinfo else at.replace(tzinfo=UTC)


def signature(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@router.post("/events")
async def receive_event(request: Request, session: DbSession) -> dict[str, str]:
    secret = get_settings().events_secret
    if not secret:
        raise HTTPException(503, detail="Приём событий выключен (GRC_EVENTS_SECRET не задан)")
    body = await request.body()
    if len(body) > 256 * 1024:
        raise HTTPException(413, detail="Событие слишком большое")
    got = request.headers.get("x-signature", "")
    if not hmac.compare_digest(got, signature(secret, body)):
        audit.record_now(
            session,
            action="event.receive",
            actor_name="—",
            result="denied",
            ip=client_ip(request),
            details={"reason": "bad_signature"},
        )
        raise HTTPException(401, detail="Неверная подпись события")
    try:
        envelope = json.loads(body)
    except ValueError as e:
        raise HTTPException(422, detail="Тело события — не JSON") from e
    if not isinstance(envelope, dict) or not envelope.get("id") or not envelope.get("type"):
        raise HTTPException(422, detail="В событии нет id или type")
    event_id = str(envelope["id"])[:64]
    if session.get(InboxEvent, event_id) is not None:
        return {"status": "duplicate"}
    result = handle_event(session, envelope)
    session.add(
        InboxEvent(
            event_id=event_id,
            type=str(envelope["type"])[:64],
            source=str(envelope.get("source") or "")[:32],
            result=result,
        )
    )
    try:
        session.commit()
    except IntegrityError:
        # Тот же id обработан параллельным запросом.
        session.rollback()
        return {"status": "duplicate"}
    return {"status": result}


# ---------- План в документах комплекта ----------


def _d(v: date | datetime | None) -> str | None:
    return v.strftime("%d.%m.%Y") if v else None


def _short(title: str) -> str:
    """Начало формулировки п. 25 — до первой запятой или скобки (для таблицы плана)."""
    head = title.split(",")[0].split(" (")[0].strip()
    return head if len(head) <= 90 else head[:89].rstrip() + "…"


def method_text(nc: Nonconformity, catalog: dict[str, str]) -> str | None:
    if nc.method == "update":
        origin = nc_rules.UPDATE_ORIGINS.get(nc.update_origin or "")
        text = "Обновление" + (f" ({origin})" if origin else "")
        if nc.update_origin in nc_rules.NEEDS_TESTING:
            text += (
                "; протестировано по Методике тестирования обновлений (2022)"
                if nc.update_tested
                else "; тестирование по Методике 2022 не отмечено"
            )
        return text
    if nc.method == "compensating":
        codes = "; ".join(f"{c} — {_short(catalog.get(c, c))}" for c in nc.compensating or [])
        return f"Компенсирующие меры (п. 25): {codes}"
    return None


def document_overrides(session: Session, obj: AssessedObject) -> dict[tuple[str, str], dict]:
    """Что внёс специалист в план — для строк плана в документах (без записи в БД).

    Ключ: ("measure", код меры) или ("vuln", id записи реестра).
    """
    catalog = {c["code"]: c["title"] for c in compensating_catalog(session)}
    out: dict[tuple[str, str], dict] = {}
    rows = session.scalars(
        select(Nonconformity).where(
            Nonconformity.object_id == obj.id, Nonconformity.closed_at.is_(None)
        )
    )
    for nc in rows:
        st = nc_rules.state(nc.closed_at, nc.vm_ticket_id, nc.vm_status)
        key = ("measure", nc.ref) if nc.kind == "measure" else ("vuln", str(nc.object_vuln_id))
        out[key] = {
            "action": nc.action,
            "responsible": nc.responsible,
            "due": _d(nc.due_date) if nc.kind == "measure" else None,
            "priority_title": nc_rules.PRIORITIES.get(nc.priority or "")
            if nc.kind == "measure"
            else None,
            "method_title": method_text(nc, catalog),
            "ticket": (
                f"№{nc.vm_ticket_id}, {nc_rules.VM_STATUSES.get(nc.vm_status or '', nc.vm_status)}"
                if nc.vm_ticket_id
                else None
            ),
            "state_title": nc_rules.STATES[st],
        }
    return out
