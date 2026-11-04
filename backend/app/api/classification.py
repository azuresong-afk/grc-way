"""Классификация: таблицы как данные, расчёт по мастеру, черновик → утверждение.

- Таблица режима (117 — класс ГИС, 21 — УЗ ПДн, 239 — категория КИИ) хранится в
  ref_classification_tables; правка — новая ревизия и снятие отметки о сверке.
- Расчёт сохраняет снимок определения таблицы и трассу: какая строка сработала.
  Поэтому любой прежний расчёт воспроизводится, даже если таблицу потом исправили.
- Утверждение: право approve, не своя работа (проверка в API и ограничение в БД),
  таблица не менялась после расчёта, несверенная таблица — только с явным
  подтверждением утверждающего. Утверждённая ранее классификация становится
  «заменённой», но остаётся в истории.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import CurrentUser, DbSession, client_ip, require
from app.api.objects import _editable, get_object_for
from app.core.rbac import Perm, SelfApprovalError, ensure_not_own_work
from app.db.models import (
    AssessedObject,
    Classification,
    RefClassificationTable,
    RefRevision,
    User,
    utcnow,
)
from app.domain.classification import (
    InputError,
    Outcome,
    TableError,
    compute,
    definition_hash,
    gaps,
    validate,
)
from app.refs.loader import table_snapshot

router = APIRouter(tags=["classification"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Classifier = Annotated[User, Depends(require(Perm.CLASSIFICATION_EDIT))]
Approver = Annotated[User, Depends(require(Perm.APPROVE))]
RefEditor = Annotated[User, Depends(require(Perm.REFS_MANAGE))]
RefVerifier = Annotated[User, Depends(require(Perm.REFS_VERIFY))]

REGIME_TITLES = {"117": "ФСТЭК №117 (ГИС)", "21": "ФСТЭК №21 (ИСПДн)", "239": "ФСТЭК №239 (КИИ)"}


# ---------- Схемы ----------


class SourceIn(BaseModel):
    document: str = Field(min_length=1, max_length=500)
    clause: str | None = Field(default=None, max_length=300)
    appendix: str | None = Field(default=None, max_length=100)
    url: str | None = Field(default=None, max_length=500)
    note: str | None = Field(default=None, max_length=2000)


class TableBrief(BaseModel):
    regime: str
    regime_title: str
    title: str
    version: str
    revision: int
    origin: str
    source: dict[str, Any]
    verified: bool
    verified_by_name: str | None
    verified_at: datetime | None
    updated_at: datetime
    # Сочетания исходных данных, на которых таблица не даёт результата.
    gaps: int


class TableRevisionOut(BaseModel):
    revision: int
    changed_by_name: str | None
    changed_at: datetime
    comment: str | None
    version: str | None


class TableOut(TableBrief):
    definition: dict[str, Any]
    definition_hash: str
    revisions: list[TableRevisionOut]


class TablePatch(BaseModel):
    definition: dict[str, Any] | None = None
    source: SourceIn | None = None
    version: str | None = Field(default=None, min_length=1, max_length=64)
    comment: str = Field(min_length=1, max_length=1000, description="Основание правки")


class VerifyIn(BaseModel):
    revision: int = Field(ge=1, description="Сверяемая ревизия — защита от гонки с правкой")


class ComputeIn(BaseModel):
    inputs: dict[str, str] = Field(max_length=100)


class ClassificationIn(ComputeIn):
    justification: str | None = Field(default=None, max_length=10000)


class OutcomeOut(BaseModel):
    regime: str
    result: str
    result_label: str
    values: dict[str, str]
    trace: list[dict[str, Any]]
    table_version: str
    table_revision: int
    table_verified: bool
    table_source: dict[str, Any]


class ClassificationOut(BaseModel):
    id: uuid.UUID
    object_id: uuid.UUID
    regime: str
    inputs: dict[str, str]
    result: str
    result_label: str
    values: dict[str, str]
    trace: list[dict[str, Any]]
    justification: str | None
    table_version: str
    table_revision: int
    table_verified: bool
    status: str
    created_at: datetime
    created_by: uuid.UUID | None
    created_by_name: str | None
    approved_at: datetime | None
    approved_by_name: str | None
    approval_comment: str | None
    unverified_acknowledged: bool
    superseded_at: datetime | None
    # Таблица с тех пор изменилась: утверждать нельзя, нужен новый расчёт.
    table_changed: bool


class ClassificationDetail(ClassificationOut):
    # Определение таблицы на момент расчёта — для показа строк и источников.
    table_snapshot: dict[str, Any]
    table_source: dict[str, Any]
    # Повторный расчёт по снимку дал тот же результат и ту же трассу.
    reproducible: bool


class ApproveIn(BaseModel):
    comment: str | None = Field(default=None, max_length=2000)
    acknowledge_unverified: bool = False


# ---------- Таблицы ----------


def _get_table(session: Session, regime: str) -> RefClassificationTable:
    t = session.get(RefClassificationTable, regime)
    if t is None:
        raise HTTPException(404, detail="Таблица классификации не загружена")
    return t


def _brief(t: RefClassificationTable) -> TableBrief:
    return TableBrief(
        regime=t.regime,
        regime_title=REGIME_TITLES.get(t.regime, t.regime),
        title=t.title,
        version=t.version,
        revision=t.revision,
        origin=t.origin,
        source=t.source,
        verified=t.verified_at is not None,
        verified_by_name=t.verified_by_name,
        verified_at=t.verified_at,
        updated_at=t.updated_at,
        gaps=len(gaps(t.definition)),
    )


def _table_out(session: Session, t: RefClassificationTable) -> TableOut:
    revisions = session.scalars(
        select(RefRevision)
        .where(RefRevision.entity == "classification_table", RefRevision.entity_key == t.regime)
        .order_by(RefRevision.id.desc())
    )
    return TableOut(
        **_brief(t).model_dump(),
        definition=t.definition,
        definition_hash=t.definition_hash,
        revisions=[
            TableRevisionOut(
                revision=r.revision,
                changed_by_name=r.changed_by_name,
                changed_at=r.changed_at,
                comment=r.comment,
                version=(r.data or {}).get("version"),
            )
            for r in revisions
        ],
    )


@router.get("/refs/classification-tables", response_model=list[TableBrief])
def list_tables(_: CurrentUser, session: DbSession) -> list[TableBrief]:
    rows = session.scalars(select(RefClassificationTable))
    order = list(REGIME_TITLES)
    return sorted(
        (_brief(t) for t in rows),
        key=lambda b: order.index(b.regime) if b.regime in order else len(order),
    )


@router.get("/refs/classification-tables/{regime}", response_model=TableOut)
def get_table(regime: str, _: CurrentUser, session: DbSession) -> TableOut:
    return _table_out(session, _get_table(session, regime))


@router.patch("/refs/classification-tables/{regime}", response_model=TableOut)
def update_table(
    regime: str, body: TablePatch, request: Request, user: RefEditor, session: DbSession
) -> TableOut:
    t = _get_table(session, regime)
    changes: dict[str, Any] = {}
    if body.definition is not None and body.definition != t.definition:
        try:
            validate(body.definition)
        except TableError as e:
            raise HTTPException(422, detail=str(e)) from e
        changes["definition"] = body.definition
    if body.source is not None:
        src = body.source.model_dump(exclude_none=True)
        if src != t.source:
            changes["source"] = src
    if body.version is not None and body.version != t.version:
        changes["version"] = body.version
    if not changes:
        return _table_out(session, t)

    session.add(
        RefRevision(
            entity="classification_table",
            entity_key=t.regime,
            revision=t.revision,
            data=table_snapshot(t),
            changed_by=user.id,
            changed_by_name=user.display_name,
            comment=body.comment,
        )
    )
    for k, v in changes.items():
        setattr(t, k, v)
    t.definition_hash = definition_hash(t.definition)
    t.origin = "local"
    t.revision += 1
    t.updated_at = utcnow()
    t.updated_by = user.id
    # Изменённая таблица снова требует сверки.
    t.verified_by = t.verified_by_name = t.verified_at = None
    audit.record(
        session,
        action="refs.classification.update",
        actor=user,
        entity="classification_table",
        entity_id=t.regime,
        ip=client_ip(request),
        details={"fields": sorted(changes), "revision": t.revision, "comment": body.comment},
    )
    session.commit()
    return _table_out(session, t)


@router.post("/refs/classification-tables/{regime}/verify", response_model=TableOut)
def verify_table(
    regime: str, body: VerifyIn, request: Request, user: RefVerifier, session: DbSession
) -> TableOut:
    t = _get_table(session, regime)
    if body.revision != t.revision:
        raise HTTPException(
            409, detail="Таблица изменилась, пока вы её смотрели. Обновите страницу"
        )
    try:
        ensure_not_own_work(user.id, t.updated_by)
    except SelfApprovalError as e:
        raise HTTPException(403, detail="Нельзя сверить собственную правку") from e
    t.verified_by = user.id
    t.verified_by_name = user.display_name
    t.verified_at = utcnow()
    audit.record(
        session,
        action="refs.classification.verify",
        actor=user,
        entity="classification_table",
        entity_id=t.regime,
        ip=client_ip(request),
        details={"revision": t.revision, "version": t.version},
    )
    session.commit()
    return _table_out(session, t)


# ---------- Расчёт ----------


def _table_for(session: Session, obj: AssessedObject) -> RefClassificationTable:
    if obj.regime is None:
        raise HTTPException(409, detail="У объекта не выбран нормативный режим")
    t = session.get(RefClassificationTable, obj.regime)
    if t is None:
        raise HTTPException(409, detail="Таблица классификации для режима не загружена")
    return t


def _compute(definition: dict[str, Any], inputs: dict[str, str]) -> Outcome:
    try:
        return compute(definition, inputs)
    except InputError as e:
        raise HTTPException(422, detail=str(e)) from e


def _with_table_source(trace: list[dict[str, Any]], source: dict[str, Any]) -> list[dict[str, Any]]:
    """Строка без своего источника ссылается на источник таблицы."""
    return [{**t, "source": {**source, **(t.get("source") or {})}} for t in trace]


@router.post("/objects/{object_id}/classifications/preview", response_model=OutcomeOut)
def preview(
    object_id: uuid.UUID, body: ComputeIn, user: Classifier, session: DbSession
) -> OutcomeOut:
    """Расчёт без сохранения — для мастера."""
    obj = get_object_for(session, object_id, user)
    t = _table_for(session, obj)
    out = _compute(t.definition, body.inputs)
    return OutcomeOut(
        regime=t.regime,
        result=out.result,
        result_label=out.result_label,
        values=out.values,
        trace=_with_table_source([x.as_dict() for x in out.trace], t.source),
        table_version=t.version,
        table_revision=t.revision,
        table_verified=t.verified_at is not None,
        table_source=t.source,
    )


def _out(c: Classification, current: RefClassificationTable | None) -> ClassificationOut:
    return ClassificationOut(
        id=c.id,
        object_id=c.object_id,
        regime=c.regime,
        inputs=c.inputs,
        result=c.result,
        result_label=c.result_label,
        values=c.step_values,
        trace=c.trace,
        justification=c.justification,
        table_version=c.table_version,
        table_revision=c.table_revision,
        table_verified=c.table_verified,
        status=c.status,
        created_at=c.created_at,
        created_by=c.created_by,
        created_by_name=c.created_by_name,
        approved_at=c.approved_at,
        approved_by_name=c.approved_by_name,
        approval_comment=c.approval_comment,
        unverified_acknowledged=c.unverified_acknowledged,
        superseded_at=c.superseded_at,
        table_changed=current is None or current.definition_hash != c.table_hash,
    )


def _reproduces(c: Classification) -> bool:
    try:
        again = compute(c.table_snapshot, c.inputs)
    except InputError:
        return False
    return (
        definition_hash(c.table_snapshot) == c.table_hash
        and again.result == c.result
        and [(x.key, x.value, x.row_id) for x in again.trace]
        == [(x["key"], x["value"], x["row_id"]) for x in c.trace]
    )


def _detail(c: Classification, current: RefClassificationTable | None) -> ClassificationDetail:
    return ClassificationDetail(
        **_out(c, current).model_dump(),
        table_snapshot=c.table_snapshot,
        table_source=(c.trace[0].get("source") if c.trace else None) or {},
        reproducible=_reproduces(c),
    )


@router.post(
    "/objects/{object_id}/classifications",
    response_model=ClassificationDetail,
    status_code=201,
)
def create_classification(
    object_id: uuid.UUID,
    body: ClassificationIn,
    request: Request,
    user: Classifier,
    session: DbSession,
) -> ClassificationDetail:
    """Сохраняет расчёт черновиком. Прежние черновики объекта заменяются."""
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    t = _table_for(session, obj)
    out = _compute(t.definition, body.inputs)
    now = utcnow()
    c = Classification(
        object_id=obj.id,
        project_id=obj.project_id,
        regime=t.regime,
        inputs=dict(body.inputs),
        result=out.result,
        result_label=out.result_label,
        step_values=out.values,
        trace=_with_table_source([x.as_dict() for x in out.trace], t.source),
        justification=(body.justification or "").strip() or None,
        table_version=t.version,
        table_revision=t.revision,
        table_hash=t.definition_hash,
        table_snapshot=t.definition,
        table_verified=t.verified_at is not None,
        status="draft",
        created_at=now,
        created_by=user.id,
        created_by_name=user.display_name,
        unverified_acknowledged=False,
    )
    session.add(c)
    session.flush()
    drafts = session.scalars(
        select(Classification).where(
            Classification.object_id == obj.id,
            Classification.status == "draft",
            Classification.id != c.id,
        )
    ).all()
    for d in drafts:
        d.status = "superseded"
        d.superseded_at = now
        d.superseded_by = c.id
    audit.record(
        session,
        action="classification.create",
        actor=user,
        entity="classification",
        entity_id=c.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "object_id": str(obj.id),
            "regime": c.regime,
            "result": c.result,
            "inputs": c.inputs,
            "rows": [x["row_id"] for x in c.trace if x.get("row_id")],
            "table_version": c.table_version,
            "table_revision": c.table_revision,
            "replaced_drafts": [str(d.id) for d in drafts],
        },
    )
    session.commit()
    return _detail(c, t)


@router.get("/objects/{object_id}/classifications", response_model=list[ClassificationOut])
def list_classifications(
    object_id: uuid.UUID, user: Viewer, session: DbSession, response: Response
) -> list[ClassificationOut]:
    obj = get_object_for(session, object_id, user)
    rows = session.scalars(
        select(Classification)
        .where(Classification.object_id == obj.id)
        .order_by(Classification.created_at.desc())
    ).all()
    tables = {t.regime: t for t in session.scalars(select(RefClassificationTable))}
    response.headers["X-Total-Count"] = str(len(rows))
    return [_out(c, tables.get(c.regime)) for c in rows]


def _get_classification(session: Session, cid: uuid.UUID, user: User) -> Classification:
    c = session.get(Classification, cid)
    if c is None:
        raise HTTPException(404, detail="Классификация не найдена")
    try:
        get_object_for(session, c.object_id, user)
    except HTTPException as e:
        raise HTTPException(404, detail="Классификация не найдена") from e
    return c


@router.get("/classifications/{classification_id}", response_model=ClassificationDetail)
def get_classification(
    classification_id: uuid.UUID, user: Viewer, session: DbSession
) -> ClassificationDetail:
    c = _get_classification(session, classification_id, user)
    return _detail(c, session.get(RefClassificationTable, c.regime))


@router.post("/classifications/{classification_id}/approve", response_model=ClassificationDetail)
def approve_classification(
    classification_id: uuid.UUID,
    body: ApproveIn,
    request: Request,
    user: Approver,
    session: DbSession,
) -> ClassificationDetail:
    c = _get_classification(session, classification_id, user)
    obj = session.get(AssessedObject, c.object_id)
    assert obj is not None  # noqa: S101 — внешний ключ
    _editable(session, obj)
    ip = client_ip(request)

    def deny(status: int, detail: str, reason: str) -> HTTPException:
        audit.record_now(
            session,
            action="classification.approve",
            actor=user,
            entity="classification",
            entity_id=c.id,
            project_id=c.project_id,
            result="denied",
            ip=ip,
            details={"reason": reason},
        )
        return HTTPException(status, detail=detail)

    if c.status != "draft":
        raise HTTPException(409, detail="Утвердить можно только черновик")
    try:
        ensure_not_own_work(user.id, c.created_by)
    except SelfApprovalError as e:
        raise deny(403, "Нельзя утвердить собственный расчёт", "self_approval") from e
    if obj.regime != c.regime:
        raise HTTPException(409, detail="Режим объекта изменился после расчёта — пересчитайте")
    current = session.get(RefClassificationTable, c.regime)
    if current is None or current.definition_hash != c.table_hash:
        raise HTTPException(
            409, detail="Таблица классификации изменилась после расчёта — пересчитайте"
        )
    unverified = current.verified_at is None
    if unverified and not body.acknowledge_unverified:
        raise HTTPException(
            409,
            detail="Таблица не сверена методистом: подтвердите, что утверждаете по несверенной",
            headers={"X-Error-Code": "unverified_table"},
        )
    if not _reproduces(c):
        raise HTTPException(409, detail="Расчёт не воспроизводится по сохранённой таблице")

    now = utcnow()
    previous = session.scalars(
        select(Classification).where(
            Classification.object_id == c.object_id,
            Classification.status == "approved",
        )
    ).all()
    for p in previous:
        p.status = "superseded"
        p.superseded_at = now
        p.superseded_by = c.id
    c.status = "approved"
    c.approved_at = now
    c.approved_by = user.id
    c.approved_by_name = user.display_name
    c.approval_comment = (body.comment or "").strip() or None
    c.unverified_acknowledged = unverified
    audit.record(
        session,
        action="classification.approve",
        actor=user,
        entity="classification",
        entity_id=c.id,
        project_id=c.project_id,
        ip=ip,
        details={
            "object_id": str(c.object_id),
            "regime": c.regime,
            "result": c.result,
            "table_version": c.table_version,
            "table_revision": c.table_revision,
            "unverified_acknowledged": c.unverified_acknowledged,
            "replaced": [str(p.id) for p in previous],
            "comment": c.approval_comment,
        },
    )
    session.commit()
    return _detail(c, current)
