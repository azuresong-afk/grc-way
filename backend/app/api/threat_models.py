"""Модель угроз объекта: мастер по шагам Методики 2021, угрозы БДУ, утверждение.

- Версии: черновик → утверждена → заменена. У объекта не больше одного черновика;
  новая версия копирует последнюю утверждённую (шаги и угрозы), прежняя
  утверждённая остаётся в истории неизменной.
- Шаги 1–5 сохраняются целиком (PUT), угрозы БДУ — построчно. Каждая правка
  записывает автора в editors: ни создатель, ни правившие версию утвердить её
  не могут (разделение обязанностей, как у адаптации).
- Утверждение: право approve, все шаги заполнены и без проблем, несверенные
  записи справочника Методики — только с явным подтверждением. В snapshot
  фиксируются записи справочника и угрозы БДУ на момент утверждения.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.objects import _editable, get_object_for
from app.core.rbac import Perm, SelfApprovalError, ensure_not_own_work
from app.db.models import (
    AssessedObject,
    BduImport,
    BduThreat,
    RefThreatItem,
    ThreatModel,
    ThreatModelThreat,
    User,
    utcnow,
)
from app.domain.bdu import threat_code
from app.domain.threat_model import (
    DATA_STEPS,
    ModelError,
    Progress,
    Refs,
    bdu_source_hint,
    progress,
    relevant_intruders,
    validate_step,
)

router = APIRouter(tags=["threat-models"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Editor = Annotated[User, Depends(require(Perm.THREATS_EDIT))]
Approver = Annotated[User, Depends(require(Perm.APPROVE))]

_Code = Annotated[str, Field(min_length=1, max_length=32)]
_Text = Annotated[str, Field(max_length=4000)]


# ---------- Шаги ----------


class ConsequenceIn(BaseModel):
    code: _Code
    justification: _Text | None = None


class ImpactObjectIn(BaseModel):
    key: _Code
    name: str = Field(min_length=1, max_length=300)
    description: _Text | None = None
    hosts: list[Annotated[str, Field(max_length=64)]] = Field(default_factory=list, max_length=500)
    impacts: list[_Code] = Field(default_factory=list, max_length=50)
    consequences: list[_Code] = Field(default_factory=list, max_length=200)


class IntruderIn(BaseModel):
    code: _Code
    relevant: bool
    capability: _Code | None = None
    justification: _Text | None = None


class MethodIn(BaseModel):
    code: _Code
    interfaces: _Text | None = None
    objects: list[_Code] = Field(default_factory=list, max_length=200)
    intruders: list[_Code] = Field(default_factory=list, max_length=100)


class ScenarioIn(BaseModel):
    tactic: _Code
    techniques: list[_Code] = Field(default_factory=list, max_length=300)
    note: _Text | None = None


class ConsequencesStep(BaseModel):
    items: list[ConsequenceIn] = Field(max_length=500)
    note: _Text | None = None


class ObjectsStep(BaseModel):
    items: list[ImpactObjectIn] = Field(max_length=200)
    note: _Text | None = None


class IntrudersStep(BaseModel):
    items: list[IntruderIn] = Field(max_length=200)
    note: _Text | None = None


class MethodsStep(BaseModel):
    items: list[MethodIn] = Field(max_length=100)
    note: _Text | None = None


class ScenariosStep(BaseModel):
    items: list[ScenarioIn] = Field(max_length=100)
    note: _Text | None = None


STEP_MODELS: dict[str, type[BaseModel]] = {
    "consequences": ConsequencesStep,
    "objects": ObjectsStep,
    "intruders": IntrudersStep,
    "methods": MethodsStep,
    "scenarios": ScenariosStep,
}


# ---------- Схемы ----------


class StepProgressOut(BaseModel):
    key: str
    title: str
    done: bool
    count: int
    problems: list[str]


class ProgressOut(BaseModel):
    steps: list[StepProgressOut]
    done: int
    total: int
    ready: bool


class ModelBrief(BaseModel):
    id: uuid.UUID
    object_id: uuid.UUID
    version: int
    status: str
    based_on: uuid.UUID | None
    created_at: datetime
    created_by: uuid.UUID | None
    created_by_name: str | None
    editor_ids: list[uuid.UUID]
    edits: int
    updated_at: datetime
    approved_at: datetime | None
    approved_by_name: str | None
    approval_comment: str | None
    unverified_acknowledged: bool
    superseded_at: datetime | None
    considered: int
    relevant: int


class ThreatOut(BaseModel):
    code: str
    title: str | None
    description: str | None
    source: str | None
    target: str | None
    conf: bool | None
    integ: bool | None
    avail: bool | None
    withdrawn: bool
    in_bdu: bool
    hint: dict[str, list[str]]
    relevant: bool | None
    justification: str | None
    intruders: list[str]
    objects: list[str]
    consequences: list[str]
    methods: list[str]
    tactics: list[str]
    linked_findings: list[Any]
    updated_at: datetime
    updated_by_name: str | None


class ModelDetail(ModelBrief):
    steps: dict[str, Any]
    threats: list[ThreatOut]
    progress: ProgressOut
    # Записи справочника Методики, на которые ссылается модель и которые не сверены.
    unverified_refs: list[str]
    bdu_version: date | None
    snapshot: dict[str, Any] | None


class StepIn(BaseModel):
    data: dict[str, Any]


class AddThreatsIn(BaseModel):
    codes: list[Annotated[str, Field(max_length=32)]] = Field(min_length=1, max_length=300)


class ThreatPatch(BaseModel):
    relevant: bool | None = None
    justification: _Text | None = None
    intruders: list[_Code] | None = Field(default=None, max_length=100)
    objects: list[_Code] | None = Field(default=None, max_length=200)
    consequences: list[_Code] | None = Field(default=None, max_length=200)
    methods: list[_Code] | None = Field(default=None, max_length=100)
    tactics: list[_Code] | None = Field(default=None, max_length=300)
    # Явно снять решение (relevant = null); иначе null в relevant — «не менять».
    clear_decision: bool = False


class CandidateOut(BaseModel):
    code: str
    title: str
    source: str | None
    target: str | None
    conf: bool | None
    integ: bool | None
    avail: bool | None
    hint: dict[str, list[str]]
    # Категория нарушителя из БДУ совпадает с категорией актуального нарушителя.
    category_match: bool
    in_model: bool


class ApproveIn(BaseModel):
    comment: str | None = Field(default=None, max_length=2000)
    acknowledge_unverified: bool = False


# ---------- Помощники ----------


def _refs(session: Session) -> tuple[Refs, dict[str, RefThreatItem]]:
    rows = {r.code: r for r in session.scalars(select(RefThreatItem))}
    refs = Refs(
        kinds={c: r.kind for c, r in rows.items()},
        parents={c: r.parent_code for c, r in rows.items()},
        attrs={c: dict(r.attrs or {}) for c, r in rows.items()},
    )
    return refs, rows


def _threat_dict(t: ThreatModelThreat) -> dict[str, Any]:
    return {
        "code": t.threat_code,
        "relevant": t.relevant,
        "justification": t.justification,
        "intruders": list(t.intruders or []),
        "objects": list(t.objects or []),
        "consequences": list(t.consequences or []),
        "methods": list(t.methods or []),
        "tactics": list(t.tactics or []),
    }


def _bdu_rows(session: Session, codes: list[str]) -> dict[str, BduThreat]:
    if not codes:
        return {}
    return {r.code: r for r in session.scalars(select(BduThreat).where(BduThreat.code.in_(codes)))}


def _bdu_version(session: Session) -> date | None:
    return session.scalar(
        select(BduImport.export_version)
        .where(BduImport.kind == "threats", BduImport.status == "applied")
        .order_by(BduImport.applied_at.desc())
        .limit(1)
    )


def _referenced(m: ThreatModel) -> set[str]:
    """Коды справочника Методики, на которые ссылается модель."""
    s = m.steps or {}
    out: set[str] = set()

    def items(key: str) -> list[dict[str, Any]]:
        return list((s.get(key) or {}).get("items") or [])

    out.update(c["code"] for c in items("consequences"))
    for o in items("objects"):
        out.update(o.get("impacts") or [])
        out.update(o.get("consequences") or [])
    for i in items("intruders"):
        out.add(i["code"])
        if i.get("capability"):
            out.add(i["capability"])
    for x in items("methods"):
        out.add(x["code"])
        out.update(x.get("intruders") or [])
    for sc in items("scenarios"):
        out.add(sc["tactic"])
        out.update(sc.get("techniques") or [])
    for t in m.threats:
        for key in ("intruders", "consequences", "methods", "tactics"):
            out.update(getattr(t, key) or [])
    return out


def _progress(session: Session, m: ThreatModel, obj: AssessedObject) -> Progress:
    refs, _ = _refs(session)
    bdu = _bdu_rows(session, [t.threat_code for t in m.threats])
    return progress(
        m.steps or {},
        [_threat_dict(t) for t in m.threats],
        refs=refs,
        hosts={h.address for h in obj.hosts},
        bdu={
            c: {"title": r.title, "withdrawn": r.withdrawn_at is not None} for c, r in bdu.items()
        },
    )


def _brief(m: ThreatModel) -> ModelBrief:
    return ModelBrief(
        id=m.id,
        object_id=m.object_id,
        version=m.version,
        status=m.status,
        based_on=m.based_on,
        created_at=m.created_at,
        created_by=m.created_by,
        created_by_name=m.created_by_name,
        editor_ids=[uuid.UUID(x) for x in m.editors or []],
        edits=m.edits,
        updated_at=m.updated_at,
        approved_at=m.approved_at,
        approved_by_name=m.approved_by_name,
        approval_comment=m.approval_comment,
        unverified_acknowledged=m.unverified_acknowledged,
        superseded_at=m.superseded_at,
        considered=len(m.threats),
        relevant=sum(1 for t in m.threats if t.relevant),
    )


def _threat_out(t: ThreatModelThreat, b: BduThreat | None) -> ThreatOut:
    return ThreatOut(
        code=t.threat_code,
        title=b.title if b else None,
        description=b.description if b else None,
        source=b.source if b else None,
        target=b.target if b else None,
        conf=b.conf if b else None,
        integ=b.integ if b else None,
        avail=b.avail if b else None,
        withdrawn=b is not None and b.withdrawn_at is not None,
        in_bdu=b is not None,
        hint=bdu_source_hint(b.source if b else None),
        relevant=t.relevant,
        justification=t.justification,
        intruders=list(t.intruders or []),
        objects=list(t.objects or []),
        consequences=list(t.consequences or []),
        methods=list(t.methods or []),
        tactics=list(t.tactics or []),
        linked_findings=list(t.linked_findings or []),
        updated_at=t.updated_at,
        updated_by_name=t.updated_by_name,
    )


def _detail(session: Session, m: ThreatModel) -> ModelDetail:
    obj = session.get(AssessedObject, m.object_id)
    assert obj is not None  # noqa: S101 — внешний ключ
    _, rows = _refs(session)
    bdu = _bdu_rows(session, [t.threat_code for t in m.threats])
    unverified = sorted(c for c in _referenced(m) if c in rows and rows[c].verified_at is None)
    return ModelDetail(
        **_brief(m).model_dump(),
        steps={k: (m.steps or {}).get(k) or {"items": []} for k in DATA_STEPS},
        threats=[_threat_out(t, bdu.get(t.threat_code)) for t in m.threats],
        progress=ProgressOut(**_progress(session, m, obj).as_dict()),
        unverified_refs=unverified,
        bdu_version=_bdu_version(session),
        snapshot=m.snapshot,
    )


def _get_model(session: Session, model_id: uuid.UUID, user: User) -> ThreatModel:
    m = session.get(ThreatModel, model_id)
    if m is None:
        raise HTTPException(404, detail="Модель угроз не найдена")
    try:
        get_object_for(session, m.object_id, user)
    except HTTPException as e:
        raise HTTPException(404, detail="Модель угроз не найдена") from e
    return m


def _draft_for_edit(session: Session, model_id: uuid.UUID, user: User) -> ThreatModel:
    m = _get_model(session, model_id, user)
    obj = session.get(AssessedObject, m.object_id)
    assert obj is not None  # noqa: S101 — внешний ключ
    _editable(session, obj)
    if m.status != "draft":
        raise HTTPException(409, detail="Утверждённая модель не меняется — начните новую версию")
    return m


def _touch(m: ThreatModel, user: User) -> None:
    m.edits += 1
    m.updated_at = utcnow()
    if str(user.id) not in (m.editors or []):
        m.editors = [*(m.editors or []), str(user.id)]


def _get_threat(m: ThreatModel, code: str) -> ThreatModelThreat:
    for t in m.threats:
        if t.threat_code == code:
            return t
    raise HTTPException(404, detail="Угрозы нет в модели")


# ---------- Версии ----------


@router.get("/objects/{object_id}/threat-models", response_model=list[ModelBrief])
def list_models(
    object_id: uuid.UUID, user: Viewer, session: DbSession, response: Response
) -> list[ModelBrief]:
    obj = get_object_for(session, object_id, user)
    rows = session.scalars(
        select(ThreatModel)
        .where(ThreatModel.object_id == obj.id)
        .order_by(ThreatModel.version.desc())
    ).all()
    response.headers["X-Total-Count"] = str(len(rows))
    return [_brief(m) for m in rows]


@router.post("/objects/{object_id}/threat-models", response_model=ModelDetail, status_code=201)
def create_model(
    object_id: uuid.UUID, request: Request, user: Editor, session: DbSession
) -> ModelDetail:
    """Новая версия-черновик: пустая или копия последней утверждённой."""
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    rows = session.scalars(
        select(ThreatModel)
        .where(ThreatModel.object_id == obj.id)
        .order_by(ThreatModel.version.desc())
    ).all()
    if any(m.status == "draft" for m in rows):
        raise HTTPException(409, detail="У объекта уже есть черновик модели угроз")
    base = next((m for m in rows if m.status == "approved"), None)
    now = utcnow()
    m = ThreatModel(
        object_id=obj.id,
        project_id=obj.project_id,
        version=(rows[0].version + 1) if rows else 1,
        status="draft",
        steps=dict(base.steps) if base else {},
        created_at=now,
        created_by=user.id,
        created_by_name=user.display_name,
        based_on=base.id if base else None,
        editors=[],
        edits=0,
        updated_at=now,
        unverified_acknowledged=False,
    )
    if base:
        m.threats = [
            ThreatModelThreat(
                threat_code=t.threat_code,
                relevant=t.relevant,
                justification=t.justification,
                intruders=list(t.intruders or []),
                objects=list(t.objects or []),
                consequences=list(t.consequences or []),
                methods=list(t.methods or []),
                tactics=list(t.tactics or []),
                linked_findings=list(t.linked_findings or []),
                added_at=now,
                updated_at=now,
                updated_by_name=t.updated_by_name,
            )
            for t in base.threats
        ]
    session.add(m)
    session.flush()
    audit.record(
        session,
        action="threat_model.create",
        actor=user,
        entity="threat_model",
        entity_id=m.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "object_id": str(obj.id),
            "version": m.version,
            "based_on": str(base.id) if base else None,
        },
    )
    session.commit()
    return _detail(session, m)


@router.get("/threat-models/{model_id}", response_model=ModelDetail)
def get_model(model_id: uuid.UUID, user: Viewer, session: DbSession) -> ModelDetail:
    return _detail(session, _get_model(session, model_id, user))


@router.delete("/threat-models/{model_id}", status_code=204)
def discard_draft(
    model_id: uuid.UUID, request: Request, user: Editor, session: DbSession
) -> Response:
    m = _draft_for_edit(session, model_id, user)
    audit.record(
        session,
        action="threat_model.discard",
        actor=user,
        entity="threat_model",
        entity_id=m.id,
        project_id=m.project_id,
        ip=client_ip(request),
        details={"object_id": str(m.object_id), "version": m.version},
    )
    session.delete(m)
    session.commit()
    return Response(status_code=204)


# ---------- Шаги 1–5 ----------


@router.put("/threat-models/{model_id}/steps/{step}", response_model=ModelDetail)
def save_step(
    model_id: uuid.UUID,
    step: Literal["consequences", "objects", "intruders", "methods", "scenarios"],
    body: StepIn,
    request: Request,
    user: Editor,
    session: DbSession,
) -> ModelDetail:
    m = _draft_for_edit(session, model_id, user)
    try:
        parsed = STEP_MODELS[step].model_validate(body.data)
    except ValueError as e:
        raise HTTPException(422, detail=f"Данные шага не разобраны: {e}") from e
    data = parsed.model_dump(exclude_none=True)
    refs, _ = _refs(session)
    try:
        validate_step(step, data, refs)
    except ModelError as e:
        raise HTTPException(422, detail=str(e)) from e
    before = (m.steps or {}).get(step) or {"items": []}
    m.steps = {**(m.steps or {}), step: data}
    _touch(m, user)
    audit.record(
        session,
        action="threat_model.step",
        actor=user,
        entity="threat_model",
        entity_id=m.id,
        project_id=m.project_id,
        ip=client_ip(request),
        details={
            "step": step,
            "items_before": len(before.get("items") or []),
            "items_after": len(data.get("items") or []),
        },
    )
    session.commit()
    return _detail(session, m)


# ---------- Угрозы БДУ ----------


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("/threat-models/{model_id}/candidates", response_model=list[CandidateOut])
def candidates(
    model_id: uuid.UUID,
    user: Viewer,
    session: DbSession,
    response: Response,
    q: Annotated[str | None, Query(max_length=200)] = None,
    match: Annotated[bool, Query(description="Только совпадающие по категории нарушителя")] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[CandidateOut]:
    """Угрозы БДУ для добавления в модель, с подсказкой по категории нарушителя."""
    m = _get_model(session, model_id, user)
    refs, _ = _refs(session)
    actual = relevant_intruders(m.steps or {})
    cats = {refs.attrs.get(c, {}).get("category") for c in actual} - {None}
    stmt = select(BduThreat).where(BduThreat.withdrawn_at.is_(None))
    if q and q.strip():
        s = q.strip()
        conds = [BduThreat.title.ilike(_like(s), escape="\\")]
        if code := threat_code(s):
            conds.append(BduThreat.code == code[0])
        stmt = stmt.where(or_(*conds))
    in_model = {t.threat_code for t in m.threats}
    rows = list(session.scalars(stmt.order_by(BduThreat.number)))

    def out(r: BduThreat) -> CandidateOut:
        hint = bdu_source_hint(r.source)
        return CandidateOut(
            code=r.code,
            title=r.title,
            source=r.source,
            target=r.target,
            conf=r.conf,
            integ=r.integ,
            avail=r.avail,
            hint=hint,
            category_match=bool(cats & set(hint["categories"])),
            in_model=r.code in in_model,
        )

    items = [out(r) for r in rows]
    if match:
        items = [c for c in items if c.category_match]
    response.headers["X-Total-Count"] = str(len(items))
    return items[offset : offset + limit]


@router.post("/threat-models/{model_id}/threats", response_model=ModelDetail)
def add_threats(
    model_id: uuid.UUID,
    body: AddThreatsIn,
    request: Request,
    user: Editor,
    session: DbSession,
) -> ModelDetail:
    m = _draft_for_edit(session, model_id, user)
    codes = list(dict.fromkeys(body.codes))
    found = _bdu_rows(session, codes)
    missing = [c for c in codes if c not in found or found[c].withdrawn_at is not None]
    if missing:
        raise HTTPException(
            422, detail=f"Нет в БДУ или исключены из неё: {', '.join(missing[:10])}"
        )
    have = {t.threat_code for t in m.threats}
    added = [c for c in codes if c not in have]
    now = utcnow()
    for c in added:
        m.threats.append(
            ThreatModelThreat(
                threat_code=c,
                relevant=None,
                intruders=[],
                objects=[],
                consequences=[],
                methods=[],
                tactics=[],
                linked_findings=[],
                added_at=now,
                updated_at=now,
                updated_by_name=user.display_name,
            )
        )
    if added:
        _touch(m, user)
        audit.record(
            session,
            action="threat_model.threat.add",
            actor=user,
            entity="threat_model",
            entity_id=m.id,
            project_id=m.project_id,
            ip=client_ip(request),
            details={"codes": added},
        )
    session.commit()
    session.refresh(m)
    return _detail(session, m)


@router.patch("/threat-models/{model_id}/threats/{code}", response_model=ModelDetail)
def update_threat(
    model_id: uuid.UUID,
    code: str,
    body: ThreatPatch,
    request: Request,
    user: Editor,
    session: DbSession,
) -> ModelDetail:
    m = _draft_for_edit(session, model_id, user)
    t = _get_threat(m, code)
    refs, _ = _refs(session)
    checks = {
        "intruders": refs.of_kind("intruder"),
        "consequences": refs.of_kind("consequence"),
        "methods": refs.of_kind("method"),
        "tactics": refs.of_kind("tactic", "technique"),
    }
    changes = body.model_dump(exclude_unset=True, exclude={"clear_decision"})
    for key, allowed in checks.items():
        for v in changes.get(key) or []:
            if v not in allowed:
                raise HTTPException(422, detail=f"Неизвестный код «{v}»")
    if body.clear_decision:
        changes["relevant"] = None
    elif changes.get("relevant", True) is None:
        changes.pop("relevant")
    if "justification" in changes:
        changes["justification"] = (changes["justification"] or "").strip() or None
    before = _threat_dict(t)
    for key, value in changes.items():
        setattr(t, key, list(dict.fromkeys(value)) if isinstance(value, list) else value)
    t.updated_at = utcnow()
    t.updated_by_name = user.display_name
    _touch(m, user)
    after = _threat_dict(t)
    audit.record(
        session,
        action="threat_model.threat.update",
        actor=user,
        entity="threat_model",
        entity_id=m.id,
        project_id=m.project_id,
        ip=client_ip(request),
        details={
            "code": code,
            "changes": {k: [before[k], after[k]] for k in after if before[k] != after[k]},
        },
    )
    session.commit()
    return _detail(session, m)


@router.delete("/threat-models/{model_id}/threats/{code}", response_model=ModelDetail)
def remove_threat(
    model_id: uuid.UUID, code: str, request: Request, user: Editor, session: DbSession
) -> ModelDetail:
    m = _draft_for_edit(session, model_id, user)
    t = _get_threat(m, code)
    m.threats.remove(t)
    _touch(m, user)
    audit.record(
        session,
        action="threat_model.threat.remove",
        actor=user,
        entity="threat_model",
        entity_id=m.id,
        project_id=m.project_id,
        ip=client_ip(request),
        details={"code": code, "relevant": t.relevant},
    )
    session.commit()
    session.refresh(m)
    return _detail(session, m)


# ---------- Утверждение ----------


def _snapshot(session: Session, m: ThreatModel) -> dict[str, Any]:
    _, rows = _refs(session)
    bdu = _bdu_rows(session, [t.threat_code for t in m.threats])
    version = _bdu_version(session)
    return {
        "refs": {
            c: {
                "kind": rows[c].kind,
                "title": rows[c].title,
                "revision": rows[c].revision,
                "origin": rows[c].origin,
                "verified": rows[c].verified_at is not None,
            }
            for c in sorted(_referenced(m))
            if c in rows
        },
        "bdu": {
            c: {
                "title": b.title,
                "changed_version": b.changed_version.isoformat() if b.changed_version else None,
            }
            for c, b in sorted(bdu.items())
        },
        "bdu_version": version.isoformat() if version else None,
    }


@router.post("/threat-models/{model_id}/approve", response_model=ModelDetail)
def approve_model(
    model_id: uuid.UUID,
    body: ApproveIn,
    request: Request,
    user: Approver,
    session: DbSession,
) -> ModelDetail:
    m = _get_model(session, model_id, user)
    obj = session.get(AssessedObject, m.object_id)
    assert obj is not None  # noqa: S101 — внешний ключ
    _editable(session, obj)
    ip = client_ip(request)

    def deny(status: int, detail: str, reason: str) -> HTTPException:
        audit.record_now(
            session,
            action="threat_model.approve",
            actor=user,
            entity="threat_model",
            entity_id=m.id,
            project_id=m.project_id,
            result="denied",
            ip=ip,
            details={"reason": reason},
        )
        return HTTPException(status, detail=detail)

    if m.status != "draft":
        raise HTTPException(409, detail="Утвердить можно только черновик")
    try:
        ensure_not_own_work(user.id, m.created_by, *(uuid.UUID(x) for x in m.editors or []))
    except SelfApprovalError as e:
        raise deny(403, "Нельзя утвердить модель, которую вы составляли или правили", "self") from e
    prog = _progress(session, m, obj)
    if not prog.ready:
        first = next(
            (f"{s.title}: {s.problems[0]}" if s.problems else f"{s.title}: шаг не заполнен")
            for s in prog.steps
            if not s.done or s.problems
        )
        raise HTTPException(409, detail=f"Модель не готова к утверждению. {first}")
    _, rows = _refs(session)
    unverified = [c for c in _referenced(m) if c in rows and rows[c].verified_at is None]
    if unverified and not body.acknowledge_unverified:
        raise HTTPException(
            409,
            detail=(
                f"Записи Методики не сверены методистом ({len(unverified)}): подтвердите, "
                "что утверждаете по несверенному справочнику"
            ),
            headers={"X-Error-Code": "unverified_refs"},
        )

    now = utcnow()
    previous = session.scalars(
        select(ThreatModel).where(
            ThreatModel.object_id == m.object_id, ThreatModel.status == "approved"
        )
    ).all()
    for p in previous:
        p.status = "superseded"
        p.superseded_at = now
    m.status = "approved"
    m.approved_at = now
    m.approved_by = user.id
    m.approved_by_name = user.display_name
    m.approval_comment = (body.comment or "").strip() or None
    m.unverified_acknowledged = bool(unverified)
    m.snapshot = _snapshot(session, m)
    audit.record(
        session,
        action="threat_model.approve",
        actor=user,
        entity="threat_model",
        entity_id=m.id,
        project_id=m.project_id,
        ip=ip,
        details={
            "object_id": str(m.object_id),
            "version": m.version,
            "relevant": sorted(t.threat_code for t in m.threats if t.relevant),
            "not_relevant": sorted(t.threat_code for t in m.threats if t.relevant is False),
            "unverified_acknowledged": m.unverified_acknowledged,
            "bdu_version": m.snapshot.get("bdu_version"),
            "replaced": [str(p.id) for p in previous],
            "comment": m.approval_comment,
        },
    )
    session.commit()
    return _detail(session, m)
