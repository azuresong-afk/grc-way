"""Справочник Методики оценки критичности уязвимостей 2025: просмотр, правка, сверка, расчёт.

Методика хранится и сверяется целиком, как таблица классификации: правка —
новая ревизия и снятие отметки о сверке; сверить собственную правку нельзя.
Правка, после которой контрольные примеры приложения перестают
воспроизводиться, отклоняется.

POST …/calculate считает V по текущей ревизии и ничего не сохраняет: это
калькулятор на экране справочника. Оценки уязвимостей объекта — задача 2.8.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import CurrentUser, DbSession, client_ip, require
from app.core.rbac import Perm, SelfApprovalError, ensure_not_own_work
from app.db.models import RefRevision, RefVulnMethodology, User, utcnow
from app.domain.vuln_criticality import (
    InputError,
    MethodologyError,
    compute,
    definition_hash,
    validate,
)
from app.refs.loader import vuln_snapshot

router = APIRouter(tags=["refs"])
RefEditor = Annotated[User, Depends(require(Perm.REFS_MANAGE))]
RefVerifier = Annotated[User, Depends(require(Perm.REFS_VERIFY))]


class SourceIn(BaseModel):
    document: str = Field(min_length=1, max_length=500)
    clause: str | None = Field(default=None, max_length=300)
    appendix: str | None = Field(default=None, max_length=100)
    url: str | None = Field(default=None, max_length=500)
    note: str | None = Field(default=None, max_length=2000)


class MethodologyBrief(BaseModel):
    id: str
    title: str
    version: str
    revision: int
    origin: str
    source: dict[str, Any]
    verified: bool
    verified_by_name: str | None
    verified_at: datetime | None
    updated_at: datetime


class RevisionOut(BaseModel):
    revision: int
    changed_by_name: str | None
    changed_at: datetime
    comment: str | None
    version: str | None


class ExampleOut(BaseModel):
    code: str
    title: str
    inputs: dict[str, Any]
    expected: dict[str, Any]
    outcome: dict[str, Any]
    reproduced: bool


class MethodologyOut(MethodologyBrief):
    definition: dict[str, Any]
    definition_hash: str
    examples: list[ExampleOut]
    revisions: list[RevisionOut]


class MethodologyPatch(BaseModel):
    definition: dict[str, Any] | None = None
    source: SourceIn | None = None
    version: str | None = Field(default=None, min_length=1, max_length=64)
    comment: str = Field(min_length=1, max_length=1000, description="Основание правки")


class VerifyIn(BaseModel):
    revision: int = Field(ge=1, description="Сверяемая ревизия — защита от гонки с правкой")


class CalculateIn(BaseModel):
    inputs: dict[str, Any] = Field(max_length=50)


class CalculateOut(BaseModel):
    methodology_id: str
    version: str
    revision: int
    verified: bool
    outcome: dict[str, Any]


def _get(session: Session, mid: str) -> RefVulnMethodology:
    m = session.get(RefVulnMethodology, mid)
    if m is None:
        raise HTTPException(404, detail="Методика не загружена")
    return m


def _brief(m: RefVulnMethodology) -> MethodologyBrief:
    return MethodologyBrief(
        id=m.id,
        title=m.title,
        version=m.version,
        revision=m.revision,
        origin=m.origin,
        source=m.source,
        verified=m.verified_at is not None,
        verified_by_name=m.verified_by_name,
        verified_at=m.verified_at,
        updated_at=m.updated_at,
    )


def _examples(definition: dict[str, Any]) -> list[ExampleOut]:
    out = []
    for ex in definition.get("examples") or []:
        result = compute(definition, ex["inputs"]).as_dict()
        want = ex.get("expected") or {}
        got = {
            "v": result["v"],
            "level": result["level"]["code"],
            "i_infr": result["groups"]["infr"],
        }
        reproduced = all(
            str(got.get(k)) == str(v)
            if k == "level"
            else Decimal(str(got.get(k))) == Decimal(str(v))
            for k, v in want.items()
        )
        out.append(
            ExampleOut(
                code=ex["code"],
                title=ex.get("title") or ex["code"],
                inputs=ex["inputs"],
                expected=want,
                outcome=result,
                reproduced=reproduced,
            )
        )
    return out


def _out(session: Session, m: RefVulnMethodology) -> MethodologyOut:
    revisions = session.scalars(
        select(RefRevision)
        .where(RefRevision.entity == "vuln_methodology", RefRevision.entity_key == m.id)
        .order_by(RefRevision.id.desc())
    )
    return MethodologyOut(
        **_brief(m).model_dump(),
        definition=m.definition,
        definition_hash=m.definition_hash,
        examples=_examples(m.definition),
        revisions=[
            RevisionOut(
                revision=r.revision,
                changed_by_name=r.changed_by_name,
                changed_at=r.changed_at,
                comment=r.comment,
                version=(r.data or {}).get("version"),
            )
            for r in revisions
        ],
    )


@router.get("/refs/vuln-criticality", response_model=list[MethodologyBrief])
def list_methodologies(_: CurrentUser, session: DbSession) -> list[MethodologyBrief]:
    rows = session.scalars(select(RefVulnMethodology).order_by(RefVulnMethodology.id.desc()))
    return [_brief(m) for m in rows]


@router.get("/refs/vuln-criticality/{mid}", response_model=MethodologyOut)
def get_methodology(mid: str, _: CurrentUser, session: DbSession) -> MethodologyOut:
    return _out(session, _get(session, mid))


@router.patch("/refs/vuln-criticality/{mid}", response_model=MethodologyOut)
def update_methodology(
    mid: str, body: MethodologyPatch, request: Request, user: RefEditor, session: DbSession
) -> MethodologyOut:
    m = _get(session, mid)
    changes: dict[str, Any] = {}
    if body.definition is not None and body.definition != m.definition:
        try:
            validate(body.definition)
        except MethodologyError as e:
            raise HTTPException(422, detail=str(e)) from e
        changes["definition"] = body.definition
    if body.source is not None:
        src = body.source.model_dump(exclude_none=True)
        if src != m.source:
            changes["source"] = src
    if body.version is not None and body.version != m.version:
        changes["version"] = body.version
    if not changes:
        return _out(session, m)

    session.add(
        RefRevision(
            entity="vuln_methodology",
            entity_key=m.id,
            revision=m.revision,
            data=vuln_snapshot(m),
            changed_by=user.id,
            changed_by_name=user.display_name,
            comment=body.comment,
        )
    )
    for k, v in changes.items():
        setattr(m, k, v)
    m.definition_hash = definition_hash(m.definition)
    m.origin = "local"
    m.revision += 1
    m.updated_at = utcnow()
    m.updated_by = user.id
    m.verified_by = m.verified_by_name = m.verified_at = None
    audit.record(
        session,
        action="refs.vuln_methodology.update",
        actor=user,
        entity="vuln_methodology",
        entity_id=m.id,
        ip=client_ip(request),
        details={"fields": sorted(changes), "revision": m.revision, "comment": body.comment},
    )
    session.commit()
    return _out(session, m)


@router.post("/refs/vuln-criticality/{mid}/verify", response_model=MethodologyOut)
def verify_methodology(
    mid: str, body: VerifyIn, request: Request, user: RefVerifier, session: DbSession
) -> MethodologyOut:
    m = _get(session, mid)
    if body.revision != m.revision:
        raise HTTPException(
            409, detail="Методика изменилась, пока вы её смотрели. Обновите страницу"
        )
    try:
        ensure_not_own_work(user.id, m.updated_by)
    except SelfApprovalError as e:
        raise HTTPException(403, detail="Нельзя сверить собственную правку") from e
    m.verified_by = user.id
    m.verified_by_name = user.display_name
    m.verified_at = utcnow()
    audit.record(
        session,
        action="refs.vuln_methodology.verify",
        actor=user,
        entity="vuln_methodology",
        entity_id=m.id,
        ip=client_ip(request),
        details={"revision": m.revision, "version": m.version},
    )
    session.commit()
    return _out(session, m)


@router.post("/refs/vuln-criticality/{mid}/calculate", response_model=CalculateOut)
def calculate(mid: str, body: CalculateIn, _: CurrentUser, session: DbSession) -> CalculateOut:
    m = _get(session, mid)
    try:
        outcome = compute(m.definition, body.inputs)
    except InputError as e:
        raise HTTPException(422, detail=str(e)) from e
    return CalculateOut(
        methodology_id=m.id,
        version=m.version,
        revision=m.revision,
        verified=m.verified_at is not None,
        outcome=outcome.as_dict(),
    )
