"""Реестр уязвимостей объекта: оценка критичности по Методике 2025 (задача 2.8).

GET   /objects/{id}/vulns              — реестр: текущая оценка, состояние, сводка
POST  /objects/{id}/vulns              — внести уязвимость вручную (п. 8 «г»)
POST  /objects/{id}/vulns/refresh      — сверить с текущим снимком и пересчитать
                                         устаревшие оценки
GET   /objects/{id}/vulns/remediation  — V, уровень и срок для «Устранения»
GET   /object-vulns/{id}               — карточка: исходные данные, «как посчитано»,
                                         история оценок
PATCH /object-vulns/{id}               — выбор специалиста; если данных хватает и
                                         что-то изменилось — новая оценка
POST  /object-vulns/{id}/assess        — пересчитать одну запись
DELETE /object-vulns/{id}              — удалить ручную запись без оценок

Импорт снимка «Сканера» и применение выгрузки БДУ вызывают refresh_object:
новые уязвимости попадают в реестр, устаревшие оценки пересчитываются, если
данных хватает (п. 19 — «по возможности автоматизированными средствами»).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.objects import (
    INVENTORY_METHODOLOGY,
    _canonical,
    _editable,
    _sort_key,
    get_object_for,
)
from app.api.snapshots import _latest_snapshot
from app.api.vuln_inventory import MethodologyRef, _hosts, _ref
from app.core.rbac import Perm
from app.db.models import (
    AssessedObject,
    BduVuln,
    ObjectVuln,
    ObjectVulnAssessment,
    RefVulnMethodology,
    User,
    utcnow,
)
from app.domain.bdu import bdu_id as parse_bdu_id
from app.domain.bdu import e_level
from app.domain.vuln_criticality import InputError, MethodologyError
from app.domain.vuln_register import (
    MANUAL_SOURCES,
    TRIGGERS,
    BduInfo,
    Choices,
    Proposal,
    check_cvss_choice,
    deadline_at,
    propose,
    stale_reasons,
)

router = APIRouter(tags=["objects"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Assessor = Annotated[User, Depends(require(Perm.ASSESSMENT_EDIT))]

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
STATES = {
    "current": "Оценка актуальна",
    "stale": "Требует пересчёта",
    "not_assessed": "Не оценена",
    "incomplete": "Не хватает данных",
    "not_detected": "Не обнаружена",
}


# ---------- Схемы ----------


class AssessmentBrief(BaseModel):
    id: uuid.UUID
    number: int
    v: str
    level: str
    level_title: str
    assessed_at: datetime
    assessed_by_name: str | None
    deadline_at: datetime
    deadline_from: int
    overdue: bool
    trigger: str
    trigger_title: str


class AssessmentOut(AssessmentBrief):
    reasons: list[str]
    hosts: list[str]
    inputs: dict[str, Any]
    outcome: dict[str, Any]
    details: dict[str, Any]
    methodology_id: str
    methodology_version: str
    methodology_revision: int
    snapshot_number: int | None


class VulnRow(BaseModel):
    id: uuid.UUID
    bdu_id: str | None
    title: str
    origin: str
    manual_source: str | None
    manual_source_title: str | None
    cve_ids: list[str]
    hosts: list[str]
    scanner_hosts: list[str]
    manual_hosts: list[str]
    last_seen_snapshot: int | None
    bdu_known: bool
    state: str
    state_title: str
    missing: list[dict[str, Any]]
    stale_reasons: list[str]
    preview: dict[str, Any] | None  # v, level, level_title — расчёт на сейчас
    current: AssessmentBrief | None
    assessments: int
    updated_at: datetime


class SnapshotRef(BaseModel):
    id: uuid.UUID
    number: int
    imported_at: datetime
    findings_loaded: bool


class RegisterOut(BaseModel):
    methodology: MethodologyRef
    snapshot: SnapshotRef | None
    counts: dict[str, int]
    items: list[VulnRow]


class VulnDetail(VulnRow):
    description: str | None
    comment: str | None
    choices: dict[str, Any]
    findings: list[dict[str, Any]]
    bdu: dict[str, Any] | None
    proposal: dict[str, Any]
    history: list[AssessmentOut]
    created_at: datetime
    created_by_name: str | None
    updated_by_name: str | None


class CvssChoiceIn(BaseModel):
    version: str = Field(max_length=8)
    score: float = Field(ge=0, le=10)
    source: str = Field(default="manual", max_length=16)
    vector: str | None = Field(default=None, max_length=200)
    note: str | None = Field(default=None, max_length=1000)


def _addresses(v: list[str] | None) -> list[str] | None:
    if v is None:
        return None
    return list(dict.fromkeys(_canonical(a) for a in v))


class ChoicesIn(BaseModel):
    cvss: CvssChoiceIn | None = None
    clear_cvss: bool = False
    e: list[str] | None = Field(default=None, max_length=10)
    h: list[str] | None = Field(default=None, max_length=20)
    certified_szi: bool | None = None
    comment: str | None = Field(default=None, max_length=2000)
    title: str | None = Field(default=None, min_length=1, max_length=2000)
    description: str | None = Field(default=None, max_length=20000)
    manual_source: str | None = Field(default=None, max_length=16)
    manual_hosts: list[str] | None = Field(default=None, max_length=5000)

    _hosts = field_validator("manual_hosts")(classmethod(lambda cls, v: _addresses(v)))


class ManualIn(ChoicesIn):
    bdu_id: str | None = Field(default=None, max_length=32)
    manual_source: str = Field(max_length=16)
    manual_hosts: list[str] = Field(min_length=1, max_length=5000)


class RefreshOut(BaseModel):
    snapshot: int | None
    created: int
    updated: int
    assessed: int
    stale_incomplete: int


class RemediationItem(BaseModel):
    vuln_id: uuid.UUID
    bdu_id: str | None
    cve_ids: list[str]
    title: str
    hosts: list[str]
    detected: bool
    v: str
    level: str
    level_title: str
    assessed_at: datetime
    deadline_at: datetime
    assessment_id: uuid.UUID
    assessment_number: int
    up_to_date: bool


class RemediationOut(BaseModel):
    product: str = "grc"
    object_id: uuid.UUID
    project_id: uuid.UUID
    generated_at: datetime
    methodology: MethodologyRef
    items: list[RemediationItem]


# ---------- Данные ----------


def _methodology(session: Session) -> RefVulnMethodology | None:
    return session.get(RefVulnMethodology, INVENTORY_METHODOLOGY)


def _require_methodology(session: Session) -> RefVulnMethodology:
    m = _methodology(session)
    if m is None:
        raise HTTPException(
            409, detail="Справочник Методики оценки критичности уязвимостей не загружен"
        )
    return m


def _bdu_info(session: Session, ids: list[str]) -> dict[str, BduInfo]:
    if not ids:
        return {}
    rows = session.scalars(select(BduVuln).where(BduVuln.bdu_id.in_(sorted(set(ids)))))
    return {
        r.bdu_id: BduInfo(
            bdu_id=r.bdu_id,
            title=r.title,
            cvss3_score=r.cvss3_score,
            cvss3_version=r.cvss3_version,
            cvss3_vector=r.cvss3_vector,
            cvss_other=r.cvss_other,
            exploit=r.exploit,
            in_wild=r.in_wild,
            exploit_raw=r.exploit_raw,
            in_wild_raw=r.in_wild_raw,
            e_level=e_level(r.exploit, r.in_wild),
            withdrawn=r.withdrawn_at is not None,
            criticality_changed_at=r.criticality_changed_at,
        )
        for r in rows
    }


def _vuln_hosts(v: ObjectVuln) -> list[str]:
    out = list(dict.fromkeys([*(v.scanner_hosts or []), *(v.manual_hosts or [])]))
    return sorted(out, key=_sort_key)


def _choices(v: ObjectVuln) -> Choices:
    return Choices(
        cvss=v.cvss_choice,
        e=list(v.e_choice or []),
        h=list(v.h_choice or []),
        certified_szi=bool(v.certified_szi),
    )


def _last(session: Session, ids: list[uuid.UUID]) -> dict[uuid.UUID, ObjectVulnAssessment]:
    if not ids:
        return {}
    top = (
        select(ObjectVulnAssessment.vuln_id, func.max(ObjectVulnAssessment.number).label("n"))
        .where(ObjectVulnAssessment.vuln_id.in_(ids))
        .group_by(ObjectVulnAssessment.vuln_id)
        .subquery()
    )
    rows = session.scalars(
        select(ObjectVulnAssessment).join(
            top,
            (ObjectVulnAssessment.vuln_id == top.c.vuln_id)
            & (ObjectVulnAssessment.number == top.c.n),
        )
    )
    return {r.vuln_id: r for r in rows}


def _counts_by_vuln(session: Session, ids: list[uuid.UUID]) -> dict[uuid.UUID, int]:
    if not ids:
        return {}
    rows = session.execute(
        select(ObjectVulnAssessment.vuln_id, func.count())
        .where(ObjectVulnAssessment.vuln_id.in_(ids))
        .group_by(ObjectVulnAssessment.vuln_id)
    )
    return {vid: n for vid, n in rows}


class _Ctx:
    """Всё, что нужно для расчёта по объекту: справочник, состав, снимок, БДУ."""

    def __init__(self, session: Session, obj: AssessedObject, m: RefVulnMethodology) -> None:
        self.session = session
        self.obj = obj
        self.m = m
        self.hosts = _hosts(obj)
        self.snapshot = _latest_snapshot(session, obj)
        self._bdu: dict[str, BduInfo] = {}

    def load_bdu(self, vulns: list[ObjectVuln]) -> None:
        self._bdu = _bdu_info(self.session, [v.bdu_id for v in vulns if v.bdu_id])

    def bdu(self, v: ObjectVuln) -> BduInfo | None:
        return self._bdu.get(v.bdu_id) if v.bdu_id else None

    def propose(self, v: ObjectVuln) -> Proposal:
        return propose(
            self.m.definition,
            self.m.definition_hash,
            hosts=self.hosts,
            vulnerable=_vuln_hosts(v),
            bdu=self.bdu(v),
            bdu_id=v.bdu_id,
            findings=v.scanner_findings or [],
            choices=_choices(v),
        )

    def reasons(self, v: ObjectVuln, last: ObjectVulnAssessment, p: Proposal) -> list[str]:
        return stale_reasons(
            self.m.definition,
            self.m.definition_hash,
            {
                "inputs": last.inputs,
                "hosts": last.hosts,
                "methodology_hash": last.methodology_hash,
                "assessed_at": last.assessed_at,
            },
            p,
            self.bdu(v),
        )


def _state(v: ObjectVuln, p: Proposal, last: ObjectVulnAssessment | None, reasons: list[str]):
    if not _vuln_hosts(v):
        return "not_detected"
    if not p.complete:
        return "incomplete"
    if last is None:
        return "not_assessed"
    return "stale" if reasons else "current"


def _aware(at: datetime) -> datetime:
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


def _brief(a: ObjectVulnAssessment, now: datetime) -> AssessmentBrief:
    return AssessmentBrief(
        id=a.id,
        number=a.number,
        v=a.v,
        level=a.level,
        level_title=a.level_title,
        assessed_at=_aware(a.assessed_at),
        assessed_by_name=a.assessed_by_name,
        deadline_at=_aware(a.deadline_at),
        deadline_from=a.deadline_from,
        overdue=_aware(a.deadline_at) < now,
        trigger=a.trigger,
        trigger_title=TRIGGERS.get(a.trigger, a.trigger),
    )


def _full(a: ObjectVulnAssessment, now: datetime) -> AssessmentOut:
    return AssessmentOut(
        **_brief(a, now).model_dump(),
        reasons=a.reasons or [],
        hosts=a.hosts or [],
        inputs=a.inputs,
        outcome=a.outcome,
        details=a.details or {},
        methodology_id=a.methodology_id,
        methodology_version=a.methodology_version,
        methodology_revision=a.methodology_revision,
        snapshot_number=a.snapshot_number,
    )


def _cve_ids(v: ObjectVuln) -> list[str]:
    return sorted({c for f in v.scanner_findings or [] for c in f.get("cve_ids") or []})


def _row(
    ctx: _Ctx,
    v: ObjectVuln,
    last: ObjectVulnAssessment | None,
    n: int,
    now: datetime,
    p: Proposal | None = None,
) -> VulnRow:
    p = p or ctx.propose(v)
    reasons = ctx.reasons(v, last, p) if last is not None and p.complete else []
    state = _state(v, p, last, reasons)
    preview = None
    if p.outcome:
        preview = {
            "v": p.outcome["v"],
            "level": p.outcome["level"]["code"],
            "level_title": p.outcome["level"]["title"],
        }
    return VulnRow(
        id=v.id,
        bdu_id=v.bdu_id,
        title=v.title,
        origin=v.origin,
        manual_source=v.manual_source,
        manual_source_title=MANUAL_SOURCES.get(v.manual_source or ""),
        cve_ids=_cve_ids(v),
        hosts=_vuln_hosts(v),
        scanner_hosts=list(v.scanner_hosts or []),
        manual_hosts=list(v.manual_hosts or []),
        last_seen_snapshot=v.last_seen_snapshot,
        bdu_known=ctx.bdu(v) is not None,
        state=state,
        state_title=STATES[state],
        missing=p.missing,
        stale_reasons=reasons,
        preview=preview,
        current=_brief(last, now) if last else None,
        assessments=n,
        updated_at=v.updated_at,
    )


# ---------- Сверка со снимком и расчёт ----------


def _sync(ctx: _Ctx, user: User | None, vulns: list[ObjectVuln]) -> tuple[int, int]:
    """Хосты и находки записей реестра — по текущему снимку; новые БДУ — новые записи."""
    snap = ctx.snapshot
    if snap is None or snap.findings is None:
        return 0, 0
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in snap.findings:
        for b in f.get("bdu_ids") or []:
            groups.setdefault(b, []).append(f)
    by_bdu = {v.bdu_id: v for v in vulns if v.bdu_id}
    bdu = _bdu_info(ctx.session, list(groups))
    now = utcnow()
    created = updated = 0
    for b, findings in groups.items():
        hosts = sorted({f["host"] for f in findings}, key=_sort_key)
        v = by_bdu.get(b)
        if v is None:
            info = bdu.get(b)
            v = ObjectVuln(
                id=uuid.uuid4(),
                object_id=ctx.obj.id,
                project_id=ctx.obj.project_id,
                bdu_id=b,
                title=(info.title if info else findings[0].get("title") or b)[:2000],
                origin="scanner",
                manual_hosts=[],
                scanner_hosts=hosts,
                scanner_findings=findings,
                snapshot_id=snap.id,
                snapshot_number=snap.number,
                last_seen_snapshot=snap.number,
                e_choice=[],
                h_choice=[],
                certified_szi=False,
                created_at=now,
                created_by=user.id if user else None,
                created_by_name=f"«Сканер», снимок №{snap.number}",
                updated_at=now,
            )
            ctx.session.add(v)
            vulns.append(v)
            created += 1
            continue
        if v.snapshot_id == snap.id:
            continue
        v.scanner_hosts, v.scanner_findings = hosts, findings
        v.snapshot_id, v.snapshot_number, v.last_seen_snapshot = snap.id, snap.number, snap.number
        v.updated_at = now
        updated += 1
    for v in vulns:
        if v.snapshot_id == snap.id or (v.bdu_id and v.bdu_id in groups):
            continue
        if v.scanner_hosts or v.scanner_findings or v.snapshot_id != snap.id:
            changed = bool(v.scanner_hosts)
            v.scanner_hosts, v.scanner_findings = [], []
            v.snapshot_id, v.snapshot_number = snap.id, snap.number
            if changed:
                v.updated_at = now
                updated += 1
    ctx.session.flush()
    return created, updated


def _assess(
    ctx: _Ctx,
    v: ObjectVuln,
    p: Proposal,
    last: ObjectVulnAssessment | None,
    *,
    trigger: str,
    reasons: list[str],
    user: User | None,
    actor_name: str | None = None,
) -> ObjectVulnAssessment:
    assert p.outcome is not None and p.fingerprint is not None  # noqa: S101
    now = utcnow()
    level = p.outcome["level"]
    number = (last.number if last else 0) + 1
    if last is not None and last.level == level["code"]:
        # Тот же уровень: срок отсчитывается от оценки, которая его присвоила (п. 21).
        due, due_from = _aware(last.deadline_at), last.deadline_from
    else:
        due, due_from = deadline_at(level, now), number
    bdu = ctx.bdu(v)
    a = ObjectVulnAssessment(
        id=uuid.uuid4(),
        vuln_id=v.id,
        object_id=v.object_id,
        project_id=v.project_id,
        number=number,
        trigger=trigger,
        reasons=reasons,
        hosts=p.hosts,
        inputs=p.inputs,
        outcome=p.outcome,
        details={
            "cvss": {k: val for k, val in p.cvss.items() if k != "options"},
            "exploitation": p.exploitation,
            "infra": p.infra,
            "notes": p.notes,
            "bdu_id": v.bdu_id,
        },
        v=p.outcome["v"],
        level=level["code"],
        level_title=level["title"],
        deadline_at=due,
        deadline_from=due_from,
        methodology_id=ctx.m.id,
        methodology_version=ctx.m.version,
        methodology_revision=ctx.m.revision,
        methodology_hash=ctx.m.definition_hash,
        snapshot_id=ctx.snapshot.id if ctx.snapshot else None,
        snapshot_number=ctx.snapshot.number if ctx.snapshot else None,
        bdu_changed_at=bdu.criticality_changed_at if bdu else None,
        fingerprint=p.fingerprint,
        assessed_at=now,
        assessed_by=user.id if user else None,
        assessed_by_name=actor_name or (user.display_name if user else None),
    )
    ctx.session.add(a)
    ctx.session.flush()
    return a


def refresh_object(
    session: Session,
    obj: AssessedObject,
    user: User | None,
    *,
    trigger: str,
    ip: str | None = None,
    only_bdu: set[str] | None = None,
) -> RefreshOut | None:
    """Сверяет реестр с текущим снимком и пересчитывает устаревшие оценки.

    Пересчитываются только записи, у которых уже есть оценка (выбор специалиста
    сделан) и хватает данных; первую оценку делает специалист. Без справочника
    Методики ничего не делает. Аудит — в текущей транзакции.
    """
    m = _methodology(session)
    if m is None:
        return None
    ctx = _Ctx(session, obj, m)
    vulns = list(session.scalars(select(ObjectVuln).where(ObjectVuln.object_id == obj.id)))
    created, updated = _sync(ctx, user, vulns) if only_bdu is None else (0, 0)
    ctx.load_bdu(vulns)
    last = _last(session, [v.id for v in vulns])
    assessed = incomplete = 0
    done: list[dict[str, Any]] = []
    for v in vulns:
        prev = last.get(v.id)
        if prev is None or (only_bdu is not None and v.bdu_id not in only_bdu):
            continue
        p = ctx.propose(v)
        if not _vuln_hosts(v):
            continue
        if not p.complete:
            incomplete += 1
            continue
        reasons = ctx.reasons(v, prev, p)
        if not reasons:
            continue
        a = _assess(ctx, v, p, prev, trigger=trigger, reasons=reasons, user=user)
        assessed += 1
        done.append({"vuln": v.bdu_id or str(v.id), "v": [prev.v, a.v], "level": a.level})
    out = RefreshOut(
        snapshot=ctx.snapshot.number if ctx.snapshot else None,
        created=created,
        updated=updated,
        assessed=assessed,
        stale_incomplete=incomplete,
    )
    if created or updated or assessed:
        audit.record(
            session,
            action="object_vulns.refresh",
            actor=user,
            entity="object",
            entity_id=obj.id,
            project_id=obj.project_id,
            ip=ip,
            details={**out.model_dump(), "trigger": trigger, "assessed_items": done[:50]},
        )
    return out


def refresh_for_bdu(session: Session, bdu_ids: set[str], user: User | None) -> int:
    """После применения выгрузки БДУ: пересчитать оценки уязвимостей с изменившимися
    сведениями во всех объектах. Возвращает число новых оценок."""
    if not bdu_ids:
        return 0
    object_ids = set(
        session.scalars(
            select(ObjectVuln.object_id).where(ObjectVuln.bdu_id.in_(sorted(bdu_ids))).distinct()
        )
    )
    total = 0
    for oid in sorted(object_ids, key=str):
        obj = session.get(AssessedObject, oid)
        if obj is None or obj.status != "active":
            continue
        out = refresh_object(session, obj, user, trigger="bdu", only_bdu=bdu_ids)
        total += out.assessed if out else 0
    return total


# ---------- Эндпоинты ----------


def _get_vuln(
    session: Session, vuln_id_: uuid.UUID, user: User
) -> tuple[ObjectVuln, AssessedObject]:
    v = session.get(ObjectVuln, vuln_id_)
    if v is None:
        raise HTTPException(404, detail="Запись реестра не найдена")
    obj = get_object_for(session, v.object_id, user)
    return v, obj


def _detail(session: Session, obj: AssessedObject, v: ObjectVuln) -> VulnDetail:
    m = _require_methodology(session)
    ctx = _Ctx(session, obj, m)
    ctx.load_bdu([v])
    now = datetime.now(UTC)
    history = list(
        session.scalars(
            select(ObjectVulnAssessment)
            .where(ObjectVulnAssessment.vuln_id == v.id)
            .order_by(ObjectVulnAssessment.number.desc())
        )
    )
    p = ctx.propose(v)
    row = _row(ctx, v, history[0] if history else None, len(history), now, p)
    bdu = session.get(BduVuln, v.bdu_id) if v.bdu_id else None
    return VulnDetail(
        **row.model_dump(),
        description=v.description,
        comment=v.comment,
        choices={
            "cvss": v.cvss_choice,
            "e": v.e_choice or [],
            "h": v.h_choice or [],
            "certified_szi": v.certified_szi,
        },
        findings=v.scanner_findings or [],
        bdu=(
            {
                "bdu_id": bdu.bdu_id,
                "title": bdu.title,
                "severity": bdu.severity,
                "cvss3_score": bdu.cvss3_score,
                "cvss3_version": bdu.cvss3_version,
                "cvss3_vector": bdu.cvss3_vector,
                "exploit_raw": bdu.exploit_raw,
                "in_wild_raw": bdu.in_wild_raw,
                "status": bdu.status,
                "fix_info": bdu.fix_info,
                "withdrawn": bdu.withdrawn_at is not None,
                "criticality_changed_at": bdu.criticality_changed_at,
                "criticality_changes": bdu.criticality_changes,
            }
            if bdu
            else None
        ),
        proposal=p.as_dict(),
        history=[_full(a, now) for a in history],
        created_at=v.created_at,
        created_by_name=v.created_by_name,
        updated_by_name=v.updated_by_name,
    )


@router.get("/objects/{object_id}/vulns", response_model=RegisterOut)
def list_register(object_id: uuid.UUID, user: Viewer, session: DbSession) -> RegisterOut:
    obj = get_object_for(session, object_id, user)
    return register(session, obj, _require_methodology(session))


def register(session: Session, obj: AssessedObject, m: RefVulnMethodology) -> RegisterOut:
    """Реестр объекта с текущими оценками (экран «Уязвимости» и документы комплекта)."""
    ctx = _Ctx(session, obj, m)
    vulns = list(session.scalars(select(ObjectVuln).where(ObjectVuln.object_id == obj.id)))
    ctx.load_bdu(vulns)
    ids = [v.id for v in vulns]
    last, n = _last(session, ids), _counts_by_vuln(session, ids)
    now = datetime.now(UTC)
    try:
        rows = [_row(ctx, v, last.get(v.id), n.get(v.id, 0), now) for v in vulns]
    except MethodologyError as e:
        raise HTTPException(409, detail=str(e)) from e

    def key(r: VulnRow):
        a = r.current
        detected = r.state != "not_detected"
        lvl = LEVEL_ORDER.get(a.level if a else (r.preview or {}).get("level", ""), 9)
        v = -float((a.v if a else (r.preview or {}).get("v")) or 0)
        return (not detected, lvl, v, r.bdu_id or "~", r.title)

    rows.sort(key=key)
    counts = dict.fromkeys(["total", *STATES, *LEVEL_ORDER, "overdue"], 0)
    for r in rows:
        counts["total"] += 1
        counts[r.state] += 1
        if r.current and r.state != "not_detected":
            counts[r.current.level] += 1
            counts["overdue"] += int(r.current.overdue)
    snap = ctx.snapshot
    return RegisterOut(
        methodology=_ref(m),
        snapshot=(
            SnapshotRef(
                id=snap.id,
                number=snap.number,
                imported_at=snap.imported_at,
                findings_loaded=snap.findings is not None,
            )
            if snap
            else None
        ),
        counts=counts,
        items=rows,
    )


def _apply_choices(definition: dict[str, Any], v: ObjectVuln, body: ChoicesIn, obj) -> None:
    by_code = {i["code"]: i for i in definition["indicators"]}
    e_ind = next((i for i in by_code.values() if i.get("bdu") == "exploitation"), None)
    h_ind = next((i for i in by_code.values() if i.get("group") == "imp"), None)

    def check(ind: dict[str, Any] | None, codes: list[str], what: str) -> list[str]:
        allowed = [x["code"] for x in (ind or {}).get("values") or []]
        if bad := [c for c in codes if c not in allowed]:
            raise HTTPException(422, detail=f"{what}: неизвестные значения {', '.join(bad[:5])}")
        return sorted(set(codes), key=allowed.index)

    if body.clear_cvss:
        v.cvss_choice = None
    elif body.cvss is not None:
        try:
            v.cvss_choice = check_cvss_choice(body.cvss.model_dump())
        except InputError as e:
            raise HTTPException(422, detail=str(e)) from e
    if body.e is not None:
        v.e_choice = check(e_ind, body.e, "показатель E")
    if body.h is not None:
        v.h_choice = check(h_ind, body.h, "показатель H")
    if body.certified_szi is not None:
        v.certified_szi = body.certified_szi
    if body.comment is not None:
        v.comment = body.comment.strip() or None
    if body.title is not None:
        v.title = body.title.strip()
    if body.description is not None:
        v.description = body.description.strip() or None
    if body.manual_source is not None:
        if body.manual_source not in MANUAL_SOURCES:
            raise HTTPException(422, detail="Неизвестный источник сведений об уязвимости")
        v.manual_source = body.manual_source
    if body.manual_hosts is not None:
        known = {h.address for h in obj.hosts}
        if unknown := [a for a in body.manual_hosts if a not in known]:
            raise HTTPException(422, detail="Нет в составе объекта: " + ", ".join(unknown[:5]))
        if v.origin == "manual" and not body.manual_hosts:
            raise HTTPException(422, detail="Укажите хотя бы один уязвимый хост")
        v.manual_hosts = sorted(body.manual_hosts, key=_sort_key)
        if body.manual_hosts and not v.manual_source:
            raise HTTPException(422, detail="Укажите, по результатам какого контроля найдены хосты")


def _assess_if_changed(
    session: Session, obj: AssessedObject, v: ObjectVuln, user: User, *, trigger: str, force: bool
) -> ObjectVulnAssessment | None:
    m = _require_methodology(session)
    ctx = _Ctx(session, obj, m)
    ctx.load_bdu([v])
    p = ctx.propose(v)
    if not p.complete or not _vuln_hosts(v):
        if force:
            raise HTTPException(
                409, detail="Не хватает данных: " + "; ".join(x["text"] for x in p.missing)
            )
        return None
    prev = _last(session, [v.id]).get(v.id)
    reasons = ctx.reasons(v, prev, p) if prev else []
    if prev is not None and not reasons:
        if force:
            raise HTTPException(409, detail="С последней оценки исходные данные не изменились")
        return None
    return _assess(
        ctx, v, p, prev, trigger=trigger, reasons=reasons or ["первая оценка"], user=user
    )


@router.post("/objects/{object_id}/vulns", response_model=VulnDetail, status_code=201)
def create_manual(
    object_id: uuid.UUID, body: ManualIn, request: Request, user: Assessor, session: DbSession
) -> VulnDetail:
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    m = _require_methodology(session)
    bdu_id = None
    if body.bdu_id and body.bdu_id.strip():
        bdu_id = parse_bdu_id(body.bdu_id)
        if bdu_id is None:
            raise HTTPException(422, detail="Идентификатор БДУ — в виде BDU:2025-01611")
        dup = session.scalar(
            select(ObjectVuln).where(ObjectVuln.object_id == obj.id, ObjectVuln.bdu_id == bdu_id)
        )
        if dup is not None:
            raise HTTPException(
                409,
                detail=f"{bdu_id} уже в реестре объекта: добавьте хосты в её карточке",
                headers={"X-Vuln-Id": str(dup.id)},
            )
    bdu = session.get(BduVuln, bdu_id) if bdu_id else None
    title = (body.title or "").strip() or (bdu.title if bdu else "")
    if not title:
        raise HTTPException(422, detail="Укажите наименование уязвимости")
    now = utcnow()
    v = ObjectVuln(
        id=uuid.uuid4(),
        object_id=obj.id,
        project_id=obj.project_id,
        bdu_id=bdu_id,
        title=title[:2000],
        origin="manual",
        manual_hosts=[],
        scanner_hosts=[],
        scanner_findings=[],
        e_choice=[],
        h_choice=[],
        certified_szi=False,
        created_at=now,
        created_by=user.id,
        created_by_name=user.display_name,
        updated_at=now,
        updated_by=user.id,
        updated_by_name=user.display_name,
    )
    _apply_choices(m.definition, v, body.model_copy(update={"title": None}), obj)
    session.add(v)
    session.flush()
    a = _assess_if_changed(session, obj, v, user, trigger="choices", force=False)
    audit.record(
        session,
        action="object_vuln.create",
        actor=user,
        entity="object_vuln",
        entity_id=v.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "object_id": str(obj.id),
            "bdu_id": bdu_id,
            "title": v.title,
            "source": v.manual_source,
            "hosts": v.manual_hosts,
            "assessment": {"v": a.v, "level": a.level} if a else None,
        },
    )
    session.commit()
    return _detail(session, obj, v)


@router.get("/object-vulns/{vuln_id_}", response_model=VulnDetail)
def get_vuln(vuln_id_: uuid.UUID, user: Viewer, session: DbSession) -> VulnDetail:
    v, obj = _get_vuln(session, vuln_id_, user)
    return _detail(session, obj, v)


@router.patch("/object-vulns/{vuln_id_}", response_model=VulnDetail)
def update_vuln(
    vuln_id_: uuid.UUID, body: ChoicesIn, request: Request, user: Assessor, session: DbSession
) -> VulnDetail:
    v, obj = _get_vuln(session, vuln_id_, user)
    _editable(session, obj)
    m = _require_methodology(session)
    if v.origin == "scanner" and body.title is not None:
        body = body.model_copy(update={"title": None})
    before = {
        "cvss": v.cvss_choice,
        "e": list(v.e_choice or []),
        "h": list(v.h_choice or []),
        "certified_szi": v.certified_szi,
        "manual_hosts": list(v.manual_hosts or []),
    }
    _apply_choices(m.definition, v, body, obj)
    v.updated_at, v.updated_by, v.updated_by_name = utcnow(), user.id, user.display_name
    session.flush()
    a = _assess_if_changed(session, obj, v, user, trigger="choices", force=False)
    after = {
        "cvss": v.cvss_choice,
        "e": v.e_choice,
        "h": v.h_choice,
        "certified_szi": v.certified_szi,
        "manual_hosts": v.manual_hosts,
    }
    audit.record(
        session,
        action="object_vuln.update",
        actor=user,
        entity="object_vuln",
        entity_id=v.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "object_id": str(obj.id),
            "bdu_id": v.bdu_id,
            "changed": {k: [before[k], after[k]] for k in before if before[k] != after[k]},
            "assessment": {"number": a.number, "v": a.v, "level": a.level} if a else None,
        },
    )
    session.commit()
    return _detail(session, obj, v)


@router.post("/object-vulns/{vuln_id_}/assess", response_model=VulnDetail)
def assess_vuln(
    vuln_id_: uuid.UUID, request: Request, user: Assessor, session: DbSession
) -> VulnDetail:
    v, obj = _get_vuln(session, vuln_id_, user)
    _editable(session, obj)
    a = _assess_if_changed(session, obj, v, user, trigger="manual", force=True)
    assert a is not None  # noqa: S101 — force
    audit.record(
        session,
        action="object_vuln.assess",
        actor=user,
        entity="object_vuln",
        entity_id=v.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "object_id": str(obj.id),
            "bdu_id": v.bdu_id,
            "number": a.number,
            "v": a.v,
            "level": a.level,
            "reasons": a.reasons,
        },
    )
    session.commit()
    return _detail(session, obj, v)


@router.delete("/object-vulns/{vuln_id_}", status_code=204)
def delete_vuln(
    vuln_id_: uuid.UUID, request: Request, user: Assessor, session: DbSession
) -> Response:
    v, obj = _get_vuln(session, vuln_id_, user)
    _editable(session, obj)
    if v.origin != "manual":
        raise HTTPException(409, detail="Запись из снимка «Сканера» удалить нельзя")
    if _last(session, [v.id]):
        raise HTTPException(409, detail="У записи есть оценки: история оценок не удаляется")
    audit.record(
        session,
        action="object_vuln.delete",
        actor=user,
        entity="object_vuln",
        entity_id=v.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={"object_id": str(obj.id), "bdu_id": v.bdu_id, "title": v.title},
    )
    session.delete(v)
    session.commit()
    return Response(status_code=204)


@router.post("/objects/{object_id}/vulns/refresh", response_model=RefreshOut)
def refresh_register(
    object_id: uuid.UUID, request: Request, user: Assessor, session: DbSession
) -> RefreshOut:
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    _require_methodology(session)
    out = refresh_object(session, obj, user, trigger="recalc", ip=client_ip(request))
    assert out is not None  # noqa: S101
    session.commit()
    return out


@router.get("/objects/{object_id}/vulns/remediation", response_model=RemediationOut)
def remediation_export(object_id: uuid.UUID, user: Viewer, session: DbSession) -> RemediationOut:
    """Текущие оценки для «Устранения»: V, уровень и срок по п. 21.

    Отдаются записи, у которых есть хотя бы одна оценка; up_to_date — оценка не
    устарела; detected — уязвимость есть в текущем снимке или внесена вручную.
    """
    obj = get_object_for(session, object_id, user)
    m = _require_methodology(session)
    ctx = _Ctx(session, obj, m)
    vulns = list(session.scalars(select(ObjectVuln).where(ObjectVuln.object_id == obj.id)))
    ctx.load_bdu(vulns)
    last = _last(session, [v.id for v in vulns])
    items = []
    for v in vulns:
        a = last.get(v.id)
        if a is None:
            continue
        p = ctx.propose(v)
        fresh = p.complete and not ctx.reasons(v, a, p)
        hosts = _vuln_hosts(v)
        items.append(
            RemediationItem(
                vuln_id=v.id,
                bdu_id=v.bdu_id,
                cve_ids=_cve_ids(v),
                title=v.title,
                hosts=hosts or a.hosts,
                detected=bool(hosts),
                v=a.v,
                level=a.level,
                level_title=a.level_title,
                assessed_at=_aware(a.assessed_at),
                deadline_at=_aware(a.deadline_at),
                assessment_id=a.id,
                assessment_number=a.number,
                up_to_date=bool(hosts) and fresh,
            )
        )
    items.sort(key=lambda i: (LEVEL_ORDER.get(i.level, 9), -float(i.v), i.bdu_id or "~"))
    return RemediationOut(
        object_id=obj.id,
        project_id=obj.project_id,
        generated_at=datetime.now(UTC),
        methodology=_ref(m),
        items=items,
    )
