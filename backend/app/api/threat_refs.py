"""Справочник Методики оценки угроз 2021: просмотр, правка, добавление, сверка.

Правила те же, что у мер и таблиц классификации: правка и добавление — право
refs.manage, создают новую ревизию (прежнее состояние — в ref_revisions) и
снимают отметку о сверке; сверка — право refs.verify, не своей правки и ровно
той ревизии, которую видел методист.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import CurrentUser, DbSession, client_ip, require
from app.core.rbac import Perm, SelfApprovalError, ensure_not_own_work
from app.db.models import RefRevision, RefThreatItem, User, utcnow
from app.domain.threat_refs import KINDS, ThreatRefError, validate_item
from app.refs.loader import threat_snapshot

router = APIRouter(prefix="/refs/threats", tags=["refs"])
Editor = Annotated[User, Depends(require(Perm.REFS_MANAGE))]
Verifier = Annotated[User, Depends(require(Perm.REFS_VERIFY))]

# Добавлять в интерфейсе можно только записи с нумерацией внутри родителя или
# дополняемые перечни; виды последствий, уровни Н1–Н4 и тактики заданы Методикой.
ADDABLE = ("consequence", "intruder", "technique")


class SourceIn(BaseModel):
    document: str = Field(min_length=1, max_length=500)
    clause: str | None = Field(default=None, max_length=300)
    appendix: str | None = Field(default=None, max_length=100)
    url: str | None = Field(default=None, max_length=500)
    note: str | None = Field(default=None, max_length=2000)


class ItemOut(BaseModel):
    code: str
    kind: str
    parent_code: str | None
    position: int
    title: str
    description: str | None
    attrs: dict[str, Any]
    source: dict[str, Any]
    origin: str
    revision: int
    verified: bool
    verified_by_name: str | None
    verified_at: datetime | None
    updated_at: datetime


class KindCount(BaseModel):
    total: int = 0
    unverified: int = 0


class ThreatRefsOut(BaseModel):
    document: dict[str, Any] | None
    total: int
    unverified: int
    kinds: dict[str, KindCount]
    items: list[ItemOut]


class RevisionOut(BaseModel):
    revision: int
    changed_by_name: str | None
    changed_at: datetime
    comment: str | None
    data: dict[str, Any]


class ItemDetail(ItemOut):
    revisions: list[RevisionOut]


class ItemPatch(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=1000)
    description: str | None = Field(default=None, max_length=4000)
    attrs: dict[str, Any] | None = None
    source: SourceIn | None = None
    comment: str = Field(min_length=1, max_length=1000, description="Основание правки")


class ItemCreate(BaseModel):
    kind: Literal["consequence", "intruder", "technique"]
    code: str = Field(min_length=1, max_length=32)
    parent_code: str | None = Field(default=None, max_length=32)
    title: str = Field(min_length=1, max_length=1000)
    description: str | None = Field(default=None, max_length=4000)
    attrs: dict[str, Any] = Field(default_factory=dict)
    source: SourceIn
    comment: str = Field(min_length=1, max_length=1000, description="Основание добавления")


class VerifyIn(BaseModel):
    revision: int = Field(ge=1, description="Сверяемая ревизия — защита от гонки с правкой")


class BulkVerifyItem(BaseModel):
    code: str
    revision: int = Field(ge=1)


class BulkVerifyIn(BaseModel):
    items: list[BulkVerifyItem] = Field(min_length=1, max_length=1000)


class BulkVerifyOut(BaseModel):
    verified: list[str]
    # Код → причина, по которой запись не сверена.
    skipped: dict[str, str]


def _out(t: RefThreatItem) -> ItemOut:
    return ItemOut(
        code=t.code,
        kind=t.kind,
        parent_code=t.parent_code,
        position=t.position,
        title=t.title,
        description=t.description,
        attrs=t.attrs or {},
        source=t.source or {},
        origin=t.origin,
        revision=t.revision,
        verified=t.verified_at is not None,
        verified_by_name=t.verified_by_name,
        verified_at=t.verified_at,
        updated_at=t.updated_at,
    )


def _all(session: Session) -> list[RefThreatItem]:
    rows = session.scalars(select(RefThreatItem)).all()
    order = {k: i for i, k in enumerate(KINDS)}
    return sorted(rows, key=lambda t: (order.get(t.kind, 99), t.parent_code or "", t.position))


def _kinds_by_code(session: Session) -> dict[str, str]:
    rows = session.execute(select(RefThreatItem.code, RefThreatItem.kind)).all()
    return {code: kind for code, kind in rows}


def _get(session: Session, code: str) -> RefThreatItem:
    t = session.get(RefThreatItem, code)
    if t is None:
        raise HTTPException(404, detail="Запись справочника не найдена")
    return t


def _detail(session: Session, t: RefThreatItem) -> ItemDetail:
    revisions = session.scalars(
        select(RefRevision)
        .where(RefRevision.entity == "threat_item", RefRevision.entity_key == t.code)
        .order_by(RefRevision.id.desc())
    )
    return ItemDetail(
        **_out(t).model_dump(),
        revisions=[
            RevisionOut(
                revision=r.revision,
                changed_by_name=r.changed_by_name,
                changed_at=r.changed_at,
                comment=r.comment,
                data=r.data or {},
            )
            for r in revisions
        ],
    )


@router.get("", response_model=ThreatRefsOut)
def list_items(_: CurrentUser, session: DbSession) -> ThreatRefsOut:
    items = [_out(t) for t in _all(session)]
    kinds = {k: KindCount() for k in KINDS}
    for i in items:
        kinds[i.kind].total += 1
        kinds[i.kind].unverified += not i.verified
    documents = Counter(i.source.get("document") for i in items if i.source.get("document"))
    document = None
    if documents:
        name = documents.most_common(1)[0][0]
        first = next(i.source for i in items if i.source.get("document") == name)
        document = {k: first.get(k) for k in ("document", "url") if first.get(k)}
    return ThreatRefsOut(
        document=document,
        total=len(items),
        unverified=sum(not i.verified for i in items),
        kinds=kinds,
        items=items,
    )


@router.get("/{code}", response_model=ItemDetail)
def get_item(code: str, _: CurrentUser, session: DbSession) -> ItemDetail:
    return _detail(session, _get(session, code))


@router.post("", response_model=ItemDetail, status_code=201)
def create_item(body: ItemCreate, request: Request, user: Editor, session: DbSession) -> ItemDetail:
    if body.kind not in ADDABLE:
        raise HTTPException(422, detail="Этот вид записей задан Методикой и не добавляется")
    if session.get(RefThreatItem, body.code) is not None:
        raise HTTPException(409, detail=f"Запись с кодом {body.code} уже есть")
    siblings = session.scalars(
        select(RefThreatItem.position).where(
            RefThreatItem.kind == body.kind, RefThreatItem.parent_code == body.parent_code
        )
        if body.parent_code
        else select(RefThreatItem.position).where(RefThreatItem.kind == body.kind)
    ).all()
    item = {
        "code": body.code,
        "kind": body.kind,
        "parent_code": body.parent_code,
        "title": body.title.strip(),
        "description": (body.description or "").strip() or None,
        "attrs": body.attrs,
        "source": body.source.model_dump(exclude_none=True),
    }
    try:
        validate_item(item, _kinds_by_code(session))
    except ThreatRefError as e:
        raise HTTPException(422, detail=str(e)) from e
    t = RefThreatItem(
        **item,
        position=max(siblings, default=0) + 1,
        origin="local",
        revision=1,
        file_hash=None,
        updated_at=utcnow(),
        updated_by=user.id,
    )
    session.add(t)
    audit.record(
        session,
        action="refs.threat.create",
        actor=user,
        entity="threat_item",
        entity_id=t.code,
        ip=client_ip(request),
        details={"kind": t.kind, "parent": t.parent_code, "comment": body.comment},
    )
    session.commit()
    return _detail(session, t)


@router.patch("/{code}", response_model=ItemDetail)
def update_item(
    code: str, body: ItemPatch, request: Request, user: Editor, session: DbSession
) -> ItemDetail:
    t = _get(session, code)
    data = body.model_dump(exclude_unset=True, exclude={"comment"})
    if "source" in data and body.source is not None:
        data["source"] = body.source.model_dump(exclude_none=True)
    if "description" in data:
        data["description"] = (data["description"] or "").strip() or None
    if data.get("title"):
        data["title"] = data["title"].strip()
    changed = {k: v for k, v in data.items() if v is not None and getattr(t, k) != v}
    if "description" in data and data["description"] is None and t.description is not None:
        changed["description"] = None
    if not changed:
        return _detail(session, t)
    candidate = {**threat_snapshot(t), "code": t.code, **changed}
    try:
        validate_item(candidate, _kinds_by_code(session))
    except ThreatRefError as e:
        raise HTTPException(422, detail=str(e)) from e

    session.add(
        RefRevision(
            entity="threat_item",
            entity_key=t.code,
            revision=t.revision,
            data=threat_snapshot(t),
            changed_by=user.id,
            changed_by_name=user.display_name,
            comment=body.comment,
        )
    )
    for k, v in changed.items():
        setattr(t, k, v)
    t.origin = "local"
    t.revision += 1
    t.updated_at = utcnow()
    t.updated_by = user.id
    # Изменённая запись снова требует сверки.
    t.verified_by = t.verified_by_name = t.verified_at = None
    audit.record(
        session,
        action="refs.threat.update",
        actor=user,
        entity="threat_item",
        entity_id=t.code,
        ip=client_ip(request),
        details={"fields": sorted(changed), "revision": t.revision, "comment": body.comment},
    )
    session.commit()
    return _detail(session, t)


def _verify(t: RefThreatItem, revision: int, user: User) -> str | None:
    """Отмечает сверку; возвращает причину отказа или None."""
    if revision != t.revision:
        return "Запись изменилась, пока вы её смотрели. Обновите страницу"
    try:
        ensure_not_own_work(user.id, t.updated_by)
    except SelfApprovalError:
        return "Нельзя сверить собственную правку"
    if t.verified_at is None:
        t.verified_by = user.id
        t.verified_by_name = user.display_name
        t.verified_at = utcnow()
    return None


@router.post("/verify", response_model=BulkVerifyOut)
def verify_many(
    body: BulkVerifyIn, request: Request, user: Verifier, session: DbSession
) -> BulkVerifyOut:
    """Сверка раздела: методист сверил все показанные записи с текстом."""
    verified: list[str] = []
    skipped: dict[str, str] = {}
    for it in body.items:
        t = session.get(RefThreatItem, it.code)
        if t is None:
            skipped[it.code] = "Запись не найдена"
        elif reason := _verify(t, it.revision, user):
            skipped[it.code] = reason
        else:
            verified.append(t.code)
    if verified:
        audit.record(
            session,
            action="refs.threat.verify",
            actor=user,
            entity="threat_item",
            ip=client_ip(request),
            details={"codes": verified, "skipped": sorted(skipped)},
        )
    session.commit()
    return BulkVerifyOut(verified=verified, skipped=skipped)


@router.post("/{code}/verify", response_model=ItemDetail)
def verify_item(
    code: str, body: VerifyIn, request: Request, user: Verifier, session: DbSession
) -> ItemDetail:
    t = _get(session, code)
    if reason := _verify(t, body.revision, user):
        raise HTTPException(409 if "изменилась" in reason else 403, detail=reason)
    audit.record(
        session,
        action="refs.threat.verify",
        actor=user,
        entity="threat_item",
        entity_id=t.code,
        ip=client_ip(request),
        details={"codes": [t.code], "revision": t.revision},
    )
    session.commit()
    return _detail(session, t)
