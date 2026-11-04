"""Справочники: профили мер, меры, проверки «Сканера», история правок, сверка."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select

from app import audit
from app.api.deps import CurrentUser, DbSession, client_ip, require
from app.core.rbac import Perm, SelfApprovalError, ensure_not_own_work
from app.db.models import (
    RefCheck,
    RefGroup,
    RefMeasure,
    RefProfile,
    RefRevision,
    User,
    utcnow,
)
from app.refs.loader import measure_snapshot

router = APIRouter(prefix="/refs", tags=["refs"])
Editor = Annotated[User, Depends(require(Perm.REFS_MANAGE))]
Verifier = Annotated[User, Depends(require(Perm.REFS_VERIFY))]


class GroupOut(BaseModel):
    code: str
    title: str
    total: int
    unverified: int


class ProfileOut(BaseModel):
    id: str
    title: str
    short: str
    document: str | None
    url: str | None
    level_label: str | None
    levels: list[str]
    default_level: str | None
    dynamic: str | None
    imported_at: datetime
    scanner_synced_at: datetime | None
    total: int
    unverified: int
    groups: list[GroupOut]


class MeasureOut(BaseModel):
    profile_id: str
    id: str
    group_code: str
    title: str
    text: str | None
    levels: list[str]
    checks: list[str]
    kind: str
    source: dict[str, Any]
    origin: str
    verified: bool
    verified_by_name: str | None
    verified_at: datetime | None
    revision: int
    updated_at: datetime


class CheckOut(BaseModel):
    id: str
    title: str
    platform: str
    remediation: str | None
    doc: str | None


class RevisionOut(BaseModel):
    revision: int
    changed_by_name: str | None
    changed_at: datetime
    comment: str | None
    data: dict[str, Any]


class MeasureDetail(MeasureOut):
    check_details: list[CheckOut]
    revisions: list[RevisionOut]


class SourceIn(BaseModel):
    document: str = Field(min_length=1, max_length=500)
    clause: str | None = Field(default=None, max_length=100)
    appendix: str | None = Field(default=None, max_length=100)
    url: str | None = Field(default=None, max_length=500)
    note: str | None = Field(default=None, max_length=1000)


class MeasurePatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=500)
    text: str | None = Field(default=None, max_length=10000)
    levels: list[str] | None = None
    checks: list[str] | None = None
    source: SourceIn | None = None
    comment: str = Field(min_length=1, max_length=1000, description="Основание правки")


def _out(m: RefMeasure) -> MeasureOut:
    return MeasureOut(
        profile_id=m.profile_id,
        id=m.id,
        group_code=m.group_code,
        title=m.title,
        text=m.text,
        levels=m.levels,
        checks=m.checks,
        kind=m.kind,
        source=m.source,
        origin=m.origin,
        verified=m.verified_at is not None,
        verified_by_name=m.verified_by_name,
        verified_at=m.verified_at,
        revision=m.revision,
        updated_at=m.updated_at,
    )


def _get_measure(session, profile_id: str, measure_id: str) -> RefMeasure:
    m = session.get(RefMeasure, (profile_id, measure_id))
    if m is None:
        raise HTTPException(404, detail="Мера не найдена")
    return m


@router.get("/profiles", response_model=list[ProfileOut])
def list_profiles(_: CurrentUser, session: DbSession) -> list[ProfileOut]:
    counts: dict[tuple[str, str], tuple[int, int]] = {}
    rows = session.execute(
        select(
            RefMeasure.profile_id,
            RefMeasure.group_code,
            func.count(),
            func.count().filter(RefMeasure.verified_at.is_(None)),
        ).group_by(RefMeasure.profile_id, RefMeasure.group_code)
    )
    for pid, code, total, unverified in rows:
        counts[(pid, code)] = (total, unverified)
    groups: dict[str, list[GroupOut]] = {}
    for g in session.scalars(select(RefGroup).order_by(RefGroup.position)):
        t, u = counts.get((g.profile_id, g.code), (0, 0))
        groups.setdefault(g.profile_id, []).append(
            GroupOut(code=g.code, title=g.title, total=t, unverified=u)
        )
    out = []
    for p in session.scalars(select(RefProfile).order_by(RefProfile.position, RefProfile.id)):
        gs = groups.get(p.id, [])
        out.append(
            ProfileOut(
                id=p.id,
                title=p.title,
                short=p.short,
                document=p.document,
                url=p.url,
                level_label=p.level_label,
                levels=p.levels,
                default_level=p.default_level,
                dynamic=p.dynamic,
                imported_at=p.imported_at,
                scanner_synced_at=p.scanner_synced_at,
                groups=gs,
                total=sum(g.total for g in gs),
                unverified=sum(g.unverified for g in gs),
            )
        )
    return out


@router.get("/measures", response_model=list[MeasureOut])
def list_measures(
    _: CurrentUser,
    session: DbSession,
    response: Response,
    profile: str,
    group: str | None = None,
    kind: Annotated[str | None, Query(pattern=r"^(technical|organizational)$")] = None,
    verified: bool | None = None,
    level: str | None = None,
    q: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[MeasureOut]:
    stmt = select(RefMeasure).where(RefMeasure.profile_id == profile)
    if group:
        stmt = stmt.where(RefMeasure.group_code == group)
    if verified is not None:
        stmt = stmt.where(
            RefMeasure.verified_at.is_not(None) if verified else RefMeasure.verified_at.is_(None)
        )
    if q:
        stmt = stmt.where(
            or_(
                func.lower(RefMeasure.title).contains(q.lower()),
                RefMeasure.id.startswith(q.upper()),
            )
        )
    rows = list(
        session.scalars(
            stmt.join(
                RefGroup,
                (RefGroup.profile_id == RefMeasure.profile_id)
                & (RefGroup.code == RefMeasure.group_code),
            ).order_by(RefGroup.position, RefMeasure.position)
        )
    )
    # JSON-поля фильтруем в Python: справочник небольшой (сотни записей на профиль).
    if kind:
        rows = [m for m in rows if m.kind == kind]
    if level:
        rows = [m for m in rows if level in m.levels]
    response.headers["X-Total-Count"] = str(len(rows))
    return [_out(m) for m in rows[offset : offset + limit]]


@router.get("/measures/{profile_id}/{measure_id}", response_model=MeasureDetail)
def get_measure(
    profile_id: str, measure_id: str, _: CurrentUser, session: DbSession
) -> MeasureDetail:
    m = _get_measure(session, profile_id, measure_id)
    checks = {c.id: c for c in session.scalars(select(RefCheck).where(RefCheck.id.in_(m.checks)))}
    revisions = session.scalars(
        select(RefRevision)
        .where(RefRevision.entity == "measure", RefRevision.entity_key == f"{profile_id}:{m.id}")
        .order_by(RefRevision.id.desc())
    )
    return MeasureDetail(
        **_out(m).model_dump(),
        check_details=[
            CheckOut(
                id=cid, title=c.title, platform=c.platform, remediation=c.remediation, doc=c.doc
            )
            if (c := checks.get(cid))
            else CheckOut(
                id=cid,
                title="Проверка не найдена в каталоге",
                platform="any",
                remediation=None,
                doc=None,
            )
            for cid in m.checks
        ],
        revisions=[
            RevisionOut(
                revision=r.revision,
                changed_by_name=r.changed_by_name,
                changed_at=r.changed_at,
                comment=r.comment,
                data=r.data,
            )
            for r in revisions
        ],
    )


@router.patch("/measures/{profile_id}/{measure_id}", response_model=MeasureOut)
def update_measure(
    profile_id: str,
    measure_id: str,
    body: MeasurePatch,
    request: Request,
    user: Editor,
    session: DbSession,
) -> MeasureOut:
    m = _get_measure(session, profile_id, measure_id)
    profile = session.get(RefProfile, profile_id)
    data = body.model_dump(exclude_unset=True, exclude={"comment"})
    if "levels" in data and data["levels"] is not None:
        unknown = set(data["levels"]) - set(profile.levels if profile else [])
        if unknown:
            raise HTTPException(422, detail=f"Неизвестный уровень: {', '.join(sorted(unknown))}")
    if data.get("checks"):
        known = set(session.scalars(select(RefCheck.id).where(RefCheck.id.in_(data["checks"]))))
        if unknown := set(data["checks"]) - known:
            raise HTTPException(422, detail=f"Неизвестная проверка: {', '.join(sorted(unknown))}")
    if "title" in data and not data["title"]:
        raise HTTPException(422, detail="Укажите наименование меры")
    changed = {k: v for k, v in data.items() if getattr(m, k) != v}
    if not changed:
        return _out(m)

    session.add(
        RefRevision(
            entity="measure",
            entity_key=f"{profile_id}:{m.id}",
            revision=m.revision,
            data=measure_snapshot(m),
            changed_by=user.id,
            changed_by_name=user.display_name,
            comment=body.comment,
        )
    )
    for k, v in changed.items():
        setattr(m, k, v)
    m.origin = "local"
    m.revision += 1
    m.updated_at = utcnow()
    m.updated_by = user.id
    # Изменённая запись снова требует сверки.
    m.verified_by = m.verified_by_name = m.verified_at = None
    audit.record(
        session,
        action="refs.measure.update",
        actor=user,
        entity="measure",
        entity_id=f"{profile_id}:{m.id}",
        ip=client_ip(request),
        details={"fields": sorted(changed), "revision": m.revision, "comment": body.comment},
    )
    session.commit()
    return _out(m)


class VerifyIn(BaseModel):
    revision: int = Field(ge=1, description="Сверяемая ревизия — защита от гонки с правкой")


@router.post("/measures/{profile_id}/{measure_id}/verify", response_model=MeasureOut)
def verify_measure(
    profile_id: str,
    measure_id: str,
    body: VerifyIn,
    request: Request,
    user: Verifier,
    session: DbSession,
) -> MeasureOut:
    m = _get_measure(session, profile_id, measure_id)
    if body.revision != m.revision:
        raise HTTPException(409, detail="Запись изменилась, пока вы её смотрели. Обновите страницу")
    try:
        ensure_not_own_work(user.id, m.updated_by)
    except SelfApprovalError as e:
        raise HTTPException(403, detail="Нельзя сверить собственную правку") from e
    m.verified_by = user.id
    m.verified_by_name = user.display_name
    m.verified_at = utcnow()
    audit.record(
        session,
        action="refs.measure.verify",
        actor=user,
        entity="measure",
        entity_id=f"{profile_id}:{m.id}",
        ip=client_ip(request),
        details={"revision": m.revision},
    )
    session.commit()
    return _out(m)


@router.get("/checks", response_model=list[CheckOut])
def list_checks(_: CurrentUser, session: DbSession) -> list[RefCheck]:
    return list(session.scalars(select(RefCheck).order_by(RefCheck.id)))
