"""Набор мер объекта: базовый набор по утверждённому классу, адаптация, утверждение.

- Базовый набор — меры профиля режима (117 → fstec-117 …), у которых в levels[]
  есть утверждённый класс объекта. Пересборка сначала показывает план (что войдёт,
  что уйдёт), затем применяется.
- Адаптация: исключение базовой меры с обоснованием, компенсация другими мерами
  набора с обоснованием, дополнение мерой профиля с обоснованием. Каждая правка
  попадает в текущую версию адаптации; правка утверждённой открывает новую версию.
- Утверждение: право approve, не своя работа (автор версии и все правившие),
  набор совпадает с базовым по текущему классу, несверенные меры — только с явным
  подтверждением. Снимок адаптации сохраняется в версии.
- Процент реализации пересчитывается на каждый запрос (app/domain/measures.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import CurrentUser, DbSession, client_ip, require
from app.api.objects import _editable, get_object_for
from app.core.config import get_settings
from app.core.rbac import Perm, SelfApprovalError, ensure_not_own_work, perms_for
from app.db.models import (
    Adaptation,
    AssessedObject,
    Classification,
    ObjectMeasure,
    Project,
    RefGroup,
    RefMeasure,
    RefProfile,
    User,
    utcnow,
)
from app.domain.measures import (
    AdaptationError,
    Current,
    Item,
    Plan,
    RefItem,
    check_compensation,
    compensated_by,
    compute_stats,
    effective_status,
    plan,
)

router = APIRouter(tags=["measures"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Adapter = Annotated[User, Depends(require(Perm.ADAPTATION_EDIT))]
Approver = Annotated[User, Depends(require(Perm.APPROVE))]

REGIME_PROFILE = {"117": "fstec-117", "21": "fstec-21", "239": "fstec-239"}

Status = Literal["implemented", "partial", "not_implemented", "not_applicable", "unassessed"]
AdaptationKind = Literal["none", "excluded", "compensated"]


# ---------- Схемы ----------


class MeasureOut(BaseModel):
    id: uuid.UUID
    profile_id: str
    measure_id: str
    group_code: str
    title: str
    origin: str
    adaptation: str
    adaptation_reason: str | None
    compensating_ids: list[str]
    # Какие меры набора опираются на эту как на компенсирующую.
    compensates: list[str]
    status: str
    # Статус для процента: у компенсированной — по компенсирующим; None — вне процента.
    effective_status: str | None
    method: str
    checks: list[str]
    levels: list[str]
    in_reference: bool
    verified: bool
    owner_id: uuid.UUID | None
    owner_name: str | None
    comment: str | None
    adapted_at: datetime | None
    adapted_by_name: str | None
    status_at: datetime | None
    status_by_name: str | None
    updated_at: datetime


class StatsBucket(BaseModel):
    total: int
    implemented: int
    partial: int
    not_implemented: int
    unassessed: int
    excluded: int
    not_applicable: int
    compensated: int
    score: float
    percent: float | None


class StatsOut(BaseModel):
    total: StatsBucket
    auto: StatsBucket
    manual: StatsBucket


class AdaptationOut(BaseModel):
    id: uuid.UUID
    version: int
    classification_id: uuid.UUID | None
    profile_id: str
    level: str
    level_label: str
    status: str
    created_at: datetime
    created_by_name: str | None
    edits: int
    updated_at: datetime
    editor_ids: list[uuid.UUID]
    approved_at: datetime | None
    approved_by_name: str | None
    approval_comment: str | None
    unverified_acknowledged: bool
    superseded_at: datetime | None
    counts: dict[str, int] | None = None


class ClassRef(BaseModel):
    id: uuid.UUID
    result: str
    result_label: str
    status: str


class PlanItem(BaseModel):
    measure_id: str
    title: str
    group_code: str
    assessed: bool = False


class PlanOut(BaseModel):
    classification: ClassRef
    profile_id: str
    level: str
    add: list[PlanItem]
    remove: list[PlanItem]
    promote: list[PlanItem]
    reset: list[PlanItem]
    foreign: list[str]
    unchanged: int
    empty: bool
    # Изменится ли что-то при применении (план или новая классификация).
    changes: bool


class GroupBrief(BaseModel):
    code: str
    title: str
    total: int


class MeasureSetOut(BaseModel):
    # no_regime | no_profile | no_class | not_built | built
    state: str
    profile_id: str | None
    profile_short: str | None
    level_label: str | None
    classification: ClassRef | None
    adaptation: AdaptationOut | None
    # Класс утверждён заново после сборки — набор нужно пересобрать.
    class_changed: bool
    # Набор отличается от базового по текущему классу (правка справочника, новый класс).
    rebuild_needed: bool
    plan_counts: dict[str, int] | None
    stats: StatsOut | None
    partial_weight: float
    groups: list[GroupBrief]
    counts: dict[str, int]
    unverified: int
    # Утвердить сейчас нельзя — почему (для подсказки в интерфейсе).
    approve_blockers: list[str]


class RebuildIn(BaseModel):
    dry_run: bool = True


class AddIn(BaseModel):
    measure_id: str = Field(min_length=1, max_length=32)
    reason: str = Field(min_length=1, max_length=4000, description="Обоснование дополнения")


class MeasurePatch(BaseModel):
    adaptation: AdaptationKind | None = None
    adaptation_reason: str | None = Field(default=None, max_length=4000)
    compensating_ids: list[str] | None = Field(default=None, max_length=50)
    status: Status | None = None
    owner_id: uuid.UUID | None = None
    comment: str | None = Field(default=None, max_length=4000)


class ApproveIn(BaseModel):
    comment: str | None = Field(default=None, max_length=2000)
    acknowledge_unverified: bool = False
    # Утверждаемая версия — защита от гонки с правкой.
    version: int | None = Field(default=None, ge=1)


_ADAPTATION_FIELDS = {"adaptation", "adaptation_reason", "compensating_ids"}
_ASSESSMENT_FIELDS = {"status", "owner_id", "comment"}


# ---------- Общие функции ----------


def _profile_for(session: Session, obj: AssessedObject) -> RefProfile | None:
    pid = REGIME_PROFILE.get(obj.regime or "")
    return session.get(RefProfile, pid) if pid else None


def _approved_class(session: Session, obj: AssessedObject) -> Classification | None:
    if obj.regime is None:
        return None
    return session.scalars(
        select(Classification)
        .where(
            Classification.object_id == obj.id,
            Classification.regime == obj.regime,
            Classification.status == "approved",
        )
        .order_by(Classification.approved_at.desc())
    ).first()


def _class_ref(c: Classification) -> ClassRef:
    return ClassRef(id=c.id, result=c.result, result_label=c.result_label, status=c.status)


def _refs(session: Session, profile_id: str) -> list[RefMeasure]:
    groups = {
        g.code: g.position
        for g in session.scalars(select(RefGroup).where(RefGroup.profile_id == profile_id))
    }
    rows = session.scalars(select(RefMeasure).where(RefMeasure.profile_id == profile_id)).all()
    return sorted(rows, key=lambda m: (groups.get(m.group_code, 999), m.position))


def _ref_items(refs: list[RefMeasure]) -> list[RefItem]:
    return [RefItem(m.id, m.group_code, m.title, tuple(m.levels or ())) for m in refs]


def _measures(session: Session, obj: AssessedObject) -> list[ObjectMeasure]:
    return list(
        session.scalars(
            select(ObjectMeasure)
            .where(ObjectMeasure.object_id == obj.id)
            .order_by(ObjectMeasure.position, ObjectMeasure.measure_id)
        )
    )


def _assessed(m: ObjectMeasure) -> bool:
    return m.status != "unassessed" or bool(m.comment) or m.owner_id is not None


def _current(measures: list[ObjectMeasure]) -> list[Current]:
    return [
        Current(
            m.measure_id,
            m.profile_id,
            m.origin,
            m.adaptation,
            tuple(m.compensating_ids or ()),
            _assessed(m),
        )
        for m in measures
    ]


def _items(measures: list[ObjectMeasure]) -> list[Item]:
    return [
        Item(m.measure_id, m.method, m.status, m.adaptation, tuple(m.compensating_ids or ()))
        for m in measures
    ]


def _method(ref: RefMeasure) -> str:
    return "auto" if ref.checks else "manual"


def _latest_adaptation(session: Session, obj: AssessedObject) -> Adaptation | None:
    return session.scalars(
        select(Adaptation).where(Adaptation.object_id == obj.id).order_by(Adaptation.version.desc())
    ).first()


def _adaptation_out(a: Adaptation, counts: dict[str, int] | None = None) -> AdaptationOut:
    return AdaptationOut(
        id=a.id,
        version=a.version,
        classification_id=a.classification_id,
        profile_id=a.profile_id,
        level=a.level,
        level_label=a.level_label,
        status=a.status,
        created_at=a.created_at,
        created_by_name=a.created_by_name,
        edits=a.edits,
        updated_at=a.updated_at,
        editor_ids=[uuid.UUID(x) for x in a.editors or []],
        approved_at=a.approved_at,
        approved_by_name=a.approved_by_name,
        approval_comment=a.approval_comment,
        unverified_acknowledged=a.unverified_acknowledged,
        superseded_at=a.superseded_at,
        counts=counts,
    )


def _snapshot_counts(snapshot: list[dict[str, Any]] | None) -> dict[str, int] | None:
    if snapshot is None:
        return None
    return {
        "total": len(snapshot),
        "excluded": sum(1 for s in snapshot if s["adaptation"] == "excluded"),
        "compensated": sum(1 for s in snapshot if s["adaptation"] == "compensated"),
        "added": sum(1 for s in snapshot if s["origin"] == "added"),
    }


def _new_version(
    session: Session,
    obj: AssessedObject,
    user: User,
    *,
    prev: Adaptation | None,
    classification: Classification | None,
    profile_id: str,
    level: str,
    level_label: str,
) -> Adaptation:
    now = utcnow()
    if prev is not None and prev.status != "superseded":
        prev.status = "superseded"
        prev.superseded_at = now
    a = Adaptation(
        object_id=obj.id,
        project_id=obj.project_id,
        version=(prev.version + 1) if prev else 1,
        classification_id=classification.id if classification else None,
        profile_id=profile_id,
        level=level,
        level_label=level_label,
        status="draft",
        created_at=now,
        created_by=user.id,
        created_by_name=user.display_name,
        editors=[str(user.id)],
        edits=0,
        updated_at=now,
        unverified_acknowledged=False,
    )
    session.add(a)
    session.flush()
    return a


def _touch_adaptation(session: Session, obj: AssessedObject, user: User) -> Adaptation:
    """Версия адаптации для правки: черновик или новая версия поверх утверждённой."""
    a = _latest_adaptation(session, obj)
    if a is None:
        raise HTTPException(409, detail="Набор мер ещё не сформирован")
    if a.status != "draft":
        prev = a
        a = _new_version(
            session,
            obj,
            user,
            prev=prev,
            classification=session.get(Classification, prev.classification_id)
            if prev.classification_id
            else None,
            profile_id=prev.profile_id,
            level=prev.level,
            level_label=prev.level_label,
        )
    if str(user.id) not in a.editors:
        a.editors = [*a.editors, str(user.id)]
    a.edits += 1
    a.updated_at = utcnow()
    return a


def _get_measure(session: Session, mid: uuid.UUID, user: User) -> ObjectMeasure:
    m = session.get(ObjectMeasure, mid)
    if m is None:
        raise HTTPException(404, detail="Мера не найдена")
    try:
        get_object_for(session, m.object_id, user)
    except HTTPException as e:
        raise HTTPException(404, detail="Мера не найдена") from e
    return m


def _measure_out(
    m: ObjectMeasure,
    refs: dict[str, RefMeasure],
    items: list[Item],
    names: dict[uuid.UUID, str],
) -> MeasureOut:
    ref = refs.get(m.measure_id)
    if ref is not None and ref.profile_id != m.profile_id:
        ref = None
    by_id = {i.measure_id: i for i in items}
    item = by_id.get(m.measure_id) or Item(m.measure_id, m.method, m.status, m.adaptation)
    return MeasureOut(
        id=m.id,
        profile_id=m.profile_id,
        measure_id=m.measure_id,
        group_code=m.group_code,
        title=ref.title if ref else m.title,
        origin=m.origin,
        adaptation=m.adaptation,
        adaptation_reason=m.adaptation_reason,
        compensating_ids=list(m.compensating_ids or []),
        compensates=compensated_by(m.measure_id, items),
        status=m.status,
        effective_status=effective_status(item, by_id),
        method=m.method,
        checks=list(ref.checks) if ref else [],
        levels=list(ref.levels) if ref else [],
        in_reference=ref is not None,
        verified=bool(ref and ref.verified_at is not None),
        owner_id=m.owner_id,
        owner_name=names.get(m.owner_id) if m.owner_id else None,
        comment=m.comment,
        adapted_at=m.adapted_at,
        adapted_by_name=m.adapted_by_name,
        status_at=m.status_at,
        status_by_name=m.status_by_name,
        updated_at=m.updated_at,
    )


def _names(session: Session, measures: list[ObjectMeasure]) -> dict[uuid.UUID, str]:
    ids = {m.owner_id for m in measures if m.owner_id}
    if not ids:
        return {}
    return {u.id: u.display_name for u in session.scalars(select(User).where(User.id.in_(ids)))}


def _refs_by_id(session: Session, obj: AssessedObject) -> dict[str, RefMeasure]:
    profile = _profile_for(session, obj)
    if profile is None:
        return {}
    return {m.id: m for m in _refs(session, profile.id)}


def _plan_for(
    session: Session, obj: AssessedObject, measures: list[ObjectMeasure]
) -> tuple[Plan, Classification, RefProfile, list[RefMeasure]]:
    """План пересборки по утверждённому классу; 409, если собрать нельзя."""
    if obj.regime is None:
        raise HTTPException(409, detail="У объекта не выбран нормативный режим")
    profile = _profile_for(session, obj)
    if profile is None:
        raise HTTPException(409, detail="Профиль мер для режима не загружен в справочник")
    cls = _approved_class(session, obj)
    if cls is None:
        raise HTTPException(
            409, detail="Сначала утвердите классификацию: базовый набор берётся по классу"
        )
    if cls.result not in (profile.levels or []):
        raise HTTPException(
            409,
            detail=f"{cls.result_label}: для этого результата базовый набор мер не установлен",
        )
    refs = _refs(session, profile.id)
    return plan(_ref_items(refs), cls.result, profile.id, _current(measures)), cls, profile, refs


def _plan_out(
    p: Plan,
    cls: Classification,
    profile: RefProfile,
    refs: list[RefMeasure],
    measures: list[ObjectMeasure],
    adaptation: Adaptation | None,
) -> PlanOut:
    by_ref = {m.id: m for m in refs}
    mine = {m.measure_id: m for m in measures if m.profile_id == profile.id}

    def item(mid: str) -> PlanItem:
        r = by_ref.get(mid)
        m = mine.get(mid)
        return PlanItem(
            measure_id=mid,
            title=r.title if r else (m.title if m else mid),
            group_code=r.group_code if r else (m.group_code if m else ""),
            assessed=bool(m and _assessed(m)),
        )

    return PlanOut(
        classification=_class_ref(cls),
        profile_id=profile.id,
        level=cls.result,
        add=[item(x) for x in p.add],
        remove=[item(x) for x in p.remove],
        promote=[item(x) for x in p.promote],
        reset=[item(x) for x in p.reset],
        foreign=p.foreign,
        unchanged=p.unchanged,
        empty=p.empty,
        changes=not p.empty or adaptation is None or adaptation.classification_id != cls.id,
    )


def _snapshot(measures: list[ObjectMeasure]) -> list[dict[str, Any]]:
    return [
        {
            "measure_id": m.measure_id,
            "origin": m.origin,
            "adaptation": m.adaptation,
            "reason": m.adaptation_reason,
            "compensating": list(m.compensating_ids or []),
        }
        for m in measures
    ]


def _blockers(
    session: Session,
    obj: AssessedObject,
    a: Adaptation | None,
    measures: list[ObjectMeasure],
    class_changed: bool,
    rebuild_needed: bool,
) -> list[str]:
    out: list[str] = []
    if a is None:
        return ["Набор мер не сформирован"]
    if a.status != "draft":
        out.append("Нет изменений для утверждения")
    if class_changed:
        out.append("Класс объекта утверждён заново — пересоберите набор")
    elif rebuild_needed:
        out.append("Набор отличается от базового по текущему классу — пересоберите")
    if not measures:
        out.append("В наборе нет мер")
    return out


# ---------- Эндпоинты ----------


@router.get("/objects/{object_id}/measure-set", response_model=MeasureSetOut)
def measure_set(object_id: uuid.UUID, user: Viewer, session: DbSession) -> MeasureSetOut:
    obj = get_object_for(session, object_id, user)
    settings = get_settings()
    profile = _profile_for(session, obj)
    cls = _approved_class(session, obj)
    a = _latest_adaptation(session, obj)
    measures = _measures(session, obj)
    refs = {m.id: m for m in _refs(session, profile.id)} if profile else {}
    groups_ref = (
        {
            g.code: g.title
            for g in session.scalars(select(RefGroup).where(RefGroup.profile_id == profile.id))
        }
        if profile
        else {}
    )

    if obj.regime is None:
        state = "no_regime"
    elif profile is None:
        state = "no_profile"
    elif a is None and cls is None:
        state = "no_class"
    elif a is None:
        state = "not_built"
    else:
        state = "built"

    class_changed = bool(a and cls and a.classification_id != cls.id)
    rebuild_needed = False
    plan_counts = None
    if a is not None and profile is not None and cls is not None and cls.result in profile.levels:
        p = plan(_ref_items(list(refs.values())), cls.result, profile.id, _current(measures))
        rebuild_needed = not p.empty
        plan_counts = {
            "add": len(p.add),
            "remove": len(p.remove),
            "promote": len(p.promote),
            "reset": len(p.reset),
            "foreign": len(p.foreign),
        }

    groups: dict[str, int] = {}
    for m in measures:
        groups[m.group_code] = groups.get(m.group_code, 0) + 1
    stats = (
        StatsOut.model_validate(compute_stats(_items(measures), settings.partial_weight).as_dict())
        if measures
        else None
    )
    return MeasureSetOut(
        state=state,
        profile_id=profile.id if profile else None,
        profile_short=profile.short if profile else None,
        level_label=profile.level_label if profile else None,
        classification=_class_ref(cls) if cls else None,
        adaptation=_adaptation_out(a) if a else None,
        class_changed=class_changed,
        rebuild_needed=rebuild_needed,
        plan_counts=plan_counts,
        stats=stats,
        partial_weight=settings.partial_weight,
        groups=[
            GroupBrief(code=code, title=groups_ref.get(code, code), total=n)
            for code, n in groups.items()
        ],
        counts={
            "total": len(measures),
            "baseline": sum(1 for m in measures if m.origin == "baseline"),
            "added": sum(1 for m in measures if m.origin == "added"),
            "excluded": sum(1 for m in measures if m.adaptation == "excluded"),
            "compensated": sum(1 for m in measures if m.adaptation == "compensated"),
        },
        unverified=sum(
            1
            for m in measures
            if m.profile_id == (profile.id if profile else None)
            and not (refs.get(m.measure_id) and refs[m.measure_id].verified_at)
        ),
        approve_blockers=_blockers(session, obj, a, measures, class_changed, rebuild_needed),
    )


@router.get("/objects/{object_id}/measures", response_model=list[MeasureOut])
def list_measures(
    object_id: uuid.UUID,
    user: Viewer,
    session: DbSession,
    response: Response,
    group: str | None = None,
    status: Status | None = None,
    method: Literal["auto", "manual", "mixed"] | None = None,
    adaptation: Literal["none", "excluded", "compensated", "added", "any"] | None = None,
    needs_review: bool | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: int = Query(default=500, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> list[MeasureOut]:
    obj = get_object_for(session, object_id, user)
    measures = _measures(session, obj)
    refs = _refs_by_id(session, obj)
    items = _items(measures)
    names = _names(session, measures)
    out = [_measure_out(m, refs, items, names) for m in measures]

    def keep(m: MeasureOut) -> bool:
        if group and m.group_code != group:
            return False
        if status and m.status != status:
            return False
        if method and m.method != method:
            return False
        if adaptation == "added" and m.origin != "added":
            return False
        if adaptation == "any" and m.adaptation == "none" and m.origin != "added":
            return False
        if adaptation in ("none", "excluded", "compensated") and m.adaptation != adaptation:
            return False
        if needs_review is not None and m.verified == needs_review:
            return False
        if q:
            needle = q.casefold()
            if needle not in m.measure_id.casefold() and needle not in m.title.casefold():
                return False
        return True

    filtered = [m for m in out if keep(m)]
    response.headers["X-Total-Count"] = str(len(filtered))
    return filtered[offset : offset + limit]


@router.post("/objects/{object_id}/measures/rebuild", response_model=PlanOut)
def rebuild(
    object_id: uuid.UUID, body: RebuildIn, request: Request, user: Adapter, session: DbSession
) -> PlanOut:
    """Базовый набор по утверждённому классу. dry_run=true — только план."""
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    measures = _measures(session, obj)
    p, cls, profile, refs = _plan_for(session, obj, measures)
    a = _latest_adaptation(session, obj)
    out = _plan_out(p, cls, profile, refs, measures, a)
    if body.dry_run or not out.changes:
        return out

    now = utcnow()
    by_ref = {m.id: m for m in refs}
    mine = {m.measure_id: m for m in measures if m.profile_id == profile.id}
    removed = set(p.remove)
    dropped: list[dict[str, Any]] = []
    for m in measures:
        if m.profile_id != profile.id or m.measure_id in removed:
            dropped.append(
                {"measure_id": m.measure_id, "profile_id": m.profile_id, "status": m.status}
            )
            session.delete(m)
    for mid in p.promote:
        m = mine[mid]
        m.origin = "baseline"
        m.updated_at = now
        m.updated_by = user.id
    for m in mine.values():
        if m.measure_id in removed or not m.compensating_ids:
            continue
        left = [x for x in m.compensating_ids if x not in removed]
        if left != m.compensating_ids:
            m.compensating_ids = left
            if not left:
                m.adaptation = "none"
                if m.origin == "baseline":
                    m.adaptation_reason = None
            m.updated_at = now
            m.updated_by = user.id
    for mid in p.add:
        r = by_ref[mid]
        session.add(
            ObjectMeasure(
                object_id=obj.id,
                project_id=obj.project_id,
                profile_id=profile.id,
                measure_id=r.id,
                group_code=r.group_code,
                title=r.title,
                position=0,
                origin="baseline",
                adaptation="none",
                compensating_ids=[],
                status="unassessed",
                method=_method(r),
                created_at=now,
                created_by=user.id,
                updated_at=now,
                updated_by=user.id,
            )
        )
    session.flush()
    _renumber(session, obj, refs)
    new = _new_version(
        session,
        obj,
        user,
        prev=a,
        classification=cls,
        profile_id=profile.id,
        level=cls.result,
        level_label=cls.result_label,
    )
    audit.record(
        session,
        action="measures.rebuild",
        actor=user,
        entity="object",
        entity_id=obj.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "classification_id": str(cls.id),
            "level": cls.result,
            "profile": profile.id,
            "added": p.add,
            "removed": dropped,
            "promoted": p.promote,
            "reset": p.reset,
            "adaptation_version": new.version,
        },
    )
    session.commit()
    return out


def _renumber(session: Session, obj: AssessedObject, refs: list[RefMeasure]) -> None:
    pos = {m.id: i for i, m in enumerate(refs)}
    for m in _measures(session, obj):
        m.position = pos.get(m.measure_id, len(pos))


@router.post("/objects/{object_id}/measures", response_model=MeasureOut, status_code=201)
def add_measure(
    object_id: uuid.UUID, body: AddIn, request: Request, user: Adapter, session: DbSession
) -> MeasureOut:
    """Дополнение набора мерой профиля с обоснованием."""
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    profile = _profile_for(session, obj)
    if profile is None:
        raise HTTPException(409, detail="Профиль мер для режима не загружен в справочник")
    measures = _measures(session, obj)
    if not measures and _latest_adaptation(session, obj) is None:
        raise HTTPException(409, detail="Сначала сформируйте базовый набор")
    ref = session.get(RefMeasure, (profile.id, body.measure_id))
    if ref is None:
        raise HTTPException(422, detail=f"Меры {body.measure_id} нет в профиле {profile.short}")
    if any(m.measure_id == ref.id and m.profile_id == profile.id for m in measures):
        raise HTTPException(409, detail=f"Мера {ref.id} уже в наборе")
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(422, detail="Нужно обоснование дополнения")
    a = _touch_adaptation(session, obj, user)
    now = utcnow()
    m = ObjectMeasure(
        object_id=obj.id,
        project_id=obj.project_id,
        profile_id=profile.id,
        measure_id=ref.id,
        group_code=ref.group_code,
        title=ref.title,
        position=0,
        origin="added",
        adaptation="none",
        adaptation_reason=reason,
        compensating_ids=[],
        status="unassessed",
        method=_method(ref),
        created_at=now,
        created_by=user.id,
        updated_at=now,
        updated_by=user.id,
        adapted_at=now,
        adapted_by_name=user.display_name,
    )
    session.add(m)
    session.flush()
    _renumber(session, obj, _refs(session, profile.id))
    audit.record(
        session,
        action="measures.add",
        actor=user,
        entity="object_measure",
        entity_id=m.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "object_id": str(obj.id),
            "measure_id": ref.id,
            "reason": reason,
            "adaptation_version": a.version,
        },
    )
    session.commit()
    measures = _measures(session, obj)
    return _measure_out(m, _refs_by_id(session, obj), _items(measures), _names(session, [m]))


@router.delete("/object-measures/{measure_id}", status_code=204)
def remove_added(
    measure_id: uuid.UUID, request: Request, user: Adapter, session: DbSession
) -> Response:
    """Убрать дополненную меру. Базовую не удаляют — её исключают с обоснованием."""
    m = _get_measure(session, measure_id, user)
    obj = session.get(AssessedObject, m.object_id)
    assert obj is not None  # noqa: S101 — внешний ключ
    _editable(session, obj)
    if m.origin != "added":
        raise HTTPException(
            409, detail="Меру базового набора не удаляют — исключите её с обоснованием"
        )
    users = compensated_by(m.measure_id, _items(_measures(session, obj)))
    if users:
        raise HTTPException(
            409, detail=f"Мера компенсирует {', '.join(users)} — сначала уберите её оттуда"
        )
    a = _touch_adaptation(session, obj, user)
    audit.record(
        session,
        action="measures.remove",
        actor=user,
        entity="object_measure",
        entity_id=m.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "object_id": str(obj.id),
            "measure_id": m.measure_id,
            "status": m.status,
            "adaptation_version": a.version,
        },
    )
    session.delete(m)
    session.commit()
    return Response(status_code=204)


@router.patch("/object-measures/{measure_id}", response_model=MeasureOut)
def update_measure(
    measure_id: uuid.UUID,
    body: MeasurePatch,
    request: Request,
    user: CurrentUser,
    session: DbSession,
) -> MeasureOut:
    """Адаптация (право adaptation.edit) и оценка: статус, ответственный, комментарий
    (право assessment.edit)."""
    m = _get_measure(session, measure_id, user)
    obj = session.get(AssessedObject, m.object_id)
    assert obj is not None  # noqa: S101 — внешний ключ
    fields = body.model_fields_set
    have = perms_for(user.roles)
    need: set[Perm] = set()
    if fields & _ADAPTATION_FIELDS:
        need.add(Perm.ADAPTATION_EDIT)
    if fields & _ASSESSMENT_FIELDS:
        need.add(Perm.ASSESSMENT_EDIT)
    missing = need - have
    if missing or Perm.VIEW not in have:
        audit.record_now(
            session,
            action="access.denied",
            actor=user,
            result="denied",
            ip=client_ip(request),
            details={
                "path": request.url.path,
                "method": request.method,
                "missing": sorted(str(p) for p in missing),
            },
        )
        raise HTTPException(403, detail="Недостаточно прав")
    _editable(session, obj)
    now = utcnow()
    changes: dict[str, Any] = {}

    if fields & _ADAPTATION_FIELDS:
        changes.update(_apply_adaptation(session, obj, m, body, user))
        if changes:
            a = _touch_adaptation(session, obj, user)
            changes["adaptation_version"] = a.version
            m.adapted_at = now
            m.adapted_by_name = user.display_name

    assess: dict[str, Any] = {}
    if "status" in fields and body.status is not None and body.status != m.status:
        assess["status"] = [m.status, body.status]
        m.status = body.status
        m.status_at = now
        m.status_by_name = user.display_name
    if "owner_id" in fields and body.owner_id != m.owner_id:
        if body.owner_id is not None:
            project = session.get(Project, obj.project_id)
            assert project is not None  # noqa: S101 — внешний ключ
            if body.owner_id not in {pm.user_id for pm in project.members}:
                raise HTTPException(422, detail="Ответственный должен быть участником проекта")
        assess["owner_id"] = str(body.owner_id) if body.owner_id else None
        m.owner_id = body.owner_id
    if "comment" in fields:
        comment = (body.comment or "").strip() or None
        if comment != m.comment:
            assess["comment"] = True
            m.comment = comment
    changes.update(assess)

    if changes:
        m.updated_at = now
        m.updated_by = user.id
        audit.record(
            session,
            action="measures.adapt" if "adaptation_version" in changes else "measures.assess",
            actor=user,
            entity="object_measure",
            entity_id=m.id,
            project_id=obj.project_id,
            ip=client_ip(request),
            details={"object_id": str(obj.id), "measure_id": m.measure_id, **changes},
        )
        session.commit()
    measures = _measures(session, obj)
    return _measure_out(m, _refs_by_id(session, obj), _items(measures), _names(session, [m]))


def _apply_adaptation(
    session: Session, obj: AssessedObject, m: ObjectMeasure, body: MeasurePatch, user: User
) -> dict[str, Any]:
    fields = body.model_fields_set
    kind = body.adaptation if "adaptation" in fields and body.adaptation else m.adaptation
    reason = (
        (body.adaptation_reason or "").strip() or None
        if "adaptation_reason" in fields
        else m.adaptation_reason
    )
    compensating = (
        [x.strip() for x in body.compensating_ids or [] if x.strip()]
        if "compensating_ids" in fields
        else list(m.compensating_ids or [])
    )
    measures = _measures(session, obj)
    items = {i.measure_id: i for i in _items(measures)}

    if kind == "excluded" and m.origin != "baseline":
        raise HTTPException(
            409, detail="Исключают только меры базового набора; дополненную меру можно убрать"
        )
    if kind != "none":
        if not reason:
            raise HTTPException(
                422,
                detail="Нужно обоснование исключения"
                if kind == "excluded"
                else "Нужно обоснование компенсации",
            )
        users = compensated_by(m.measure_id, items.values())
        if users:
            raise HTTPException(
                409,
                detail=f"Мера компенсирует {', '.join(users)} — сначала уберите её оттуда",
            )
    if kind == "compensated":
        try:
            check_compensation(m.measure_id, compensating, items)
        except AdaptationError as e:
            raise HTTPException(422, detail=str(e)) from e
    else:
        compensating = []
    if kind == "none" and m.origin == "baseline":
        reason = None
    if kind == "none" and m.origin == "added" and not reason:
        raise HTTPException(422, detail="Нужно обоснование дополнения")

    before = (m.adaptation, m.adaptation_reason, list(m.compensating_ids or []))
    after = (kind, reason, compensating)
    if before == after:
        return {}
    m.adaptation, m.adaptation_reason, m.compensating_ids = kind, reason, compensating
    return {
        "adaptation": [before[0], kind],
        "reason": reason,
        "compensating": compensating,
    }


@router.get("/objects/{object_id}/adaptations", response_model=list[AdaptationOut])
def list_adaptations(object_id: uuid.UUID, user: Viewer, session: DbSession) -> list[AdaptationOut]:
    obj = get_object_for(session, object_id, user)
    rows = session.scalars(
        select(Adaptation).where(Adaptation.object_id == obj.id).order_by(Adaptation.version.desc())
    )
    return [_adaptation_out(a, _snapshot_counts(a.snapshot)) for a in rows]


@router.post("/objects/{object_id}/adaptation/approve", response_model=AdaptationOut)
def approve_adaptation(
    object_id: uuid.UUID, body: ApproveIn, request: Request, user: Approver, session: DbSession
) -> AdaptationOut:
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    a = _latest_adaptation(session, obj)
    ip = client_ip(request)
    if a is None:
        raise HTTPException(409, detail="Набор мер ещё не сформирован")
    if a.status != "draft":
        raise HTTPException(409, detail="Нет изменений для утверждения")
    if body.version is not None and body.version != a.version:
        raise HTTPException(
            409, detail="Адаптация изменилась, пока вы её смотрели. Обновите страницу"
        )
    try:
        ensure_not_own_work(user.id, a.created_by, *(uuid.UUID(x) for x in a.editors or []))
    except SelfApprovalError as e:
        audit.record_now(
            session,
            action="adaptation.approve",
            actor=user,
            entity="adaptation",
            entity_id=a.id,
            project_id=obj.project_id,
            result="denied",
            ip=ip,
            details={"reason": "self_approval"},
        )
        raise HTTPException(403, detail="Нельзя утвердить адаптацию, которую вы меняли") from e
    measures = _measures(session, obj)
    if not measures:
        raise HTTPException(409, detail="В наборе нет мер")
    p, cls, _, refs = _plan_for(session, obj, measures)
    if a.classification_id != cls.id:
        raise HTTPException(409, detail="Класс объекта утверждён заново — пересоберите набор")
    if not p.empty:
        raise HTTPException(
            409, detail="Набор отличается от базового по текущему классу — пересоберите"
        )
    by_ref = {r.id: r for r in refs}
    unverified = [
        m.measure_id
        for m in measures
        if by_ref.get(m.measure_id) is None or by_ref[m.measure_id].verified_at is None
    ]
    if unverified and not body.acknowledge_unverified:
        raise HTTPException(
            409,
            detail=(
                f"Не сверено методистом: {len(unverified)} мер набора. "
                "Подтвердите, что утверждаете по несверенному справочнику"
            ),
            headers={"X-Error-Code": "unverified_measures"},
        )
    now = utcnow()
    for prev in session.scalars(
        select(Adaptation).where(Adaptation.object_id == obj.id, Adaptation.status == "approved")
    ):
        prev.status = "superseded"
        prev.superseded_at = now
    a.status = "approved"
    a.approved_at = now
    a.approved_by = user.id
    a.approved_by_name = user.display_name
    a.approval_comment = (body.comment or "").strip() or None
    a.unverified_acknowledged = bool(unverified)
    a.snapshot = _snapshot(measures)
    counts = _snapshot_counts(a.snapshot)
    audit.record(
        session,
        action="adaptation.approve",
        actor=user,
        entity="adaptation",
        entity_id=a.id,
        project_id=obj.project_id,
        ip=ip,
        details={
            "object_id": str(obj.id),
            "version": a.version,
            "level": a.level,
            "counts": counts,
            "unverified": len(unverified),
            "comment": a.approval_comment,
        },
    )
    session.commit()
    return _adaptation_out(a, counts)
