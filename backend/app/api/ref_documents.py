"""Справочник нормативных документов: список, карточка, правка, сверка.

Документ, который не применяется, остаётся в справочнике: видно, чем он заменён
и на каком основании (например, Методика критичности уязвимостей 2022 г. —
п. 6 Методики 2025 г.).
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import CurrentUser, DbSession, client_ip, require
from app.core.rbac import Perm, SelfApprovalError, ensure_not_own_work
from app.db.models import RefDocument, RefRevision, User, utcnow
from app.domain.ref_documents import FIELDS, DocumentError, validate_doc
from app.refs.loader import document_snapshot

router = APIRouter(tags=["refs"])
RefEditor = Annotated[User, Depends(require(Perm.REFS_MANAGE))]
RefVerifier = Annotated[User, Depends(require(Perm.REFS_VERIFY))]


class SourceIn(BaseModel):
    document: str = Field(min_length=1, max_length=500)
    clause: str | None = Field(default=None, max_length=300)
    appendix: str | None = Field(default=None, max_length=100)
    url: str | None = Field(default=None, max_length=500)
    note: str | None = Field(default=None, max_length=2000)


class DocumentOut(BaseModel):
    code: str
    short: str
    title: str
    issuer: str | None
    issued: date | None
    number: str | None
    url: str | None
    status: str
    replaced_by: str | None
    # Документы, которые этот документ заменил.
    replaces: list[str]
    source: dict[str, Any]
    origin: str
    verified: bool
    verified_by_name: str | None
    verified_at: datetime | None
    revision: int
    updated_at: datetime


class RevisionOut(BaseModel):
    revision: int
    changed_by_name: str | None
    changed_at: datetime
    comment: str | None
    data: dict[str, Any]


class DocumentDetail(DocumentOut):
    revisions: list[RevisionOut]


class DocumentPatch(BaseModel):
    short: str | None = Field(default=None, min_length=1, max_length=200)
    title: str | None = Field(default=None, min_length=1, max_length=1000)
    issuer: str | None = Field(default=None, max_length=200)
    issued: date | None = None
    number: str | None = Field(default=None, max_length=32)
    url: str | None = Field(default=None, max_length=500)
    status: str | None = None
    replaced_by: str | None = Field(default=None, max_length=64)
    source: SourceIn | None = None
    comment: str = Field(min_length=1, max_length=1000, description="Основание правки")


class VerifyIn(BaseModel):
    revision: int = Field(ge=1)


def _get(session: Session, code: str) -> RefDocument:
    d = session.get(RefDocument, code)
    if d is None:
        raise HTTPException(404, detail="Документ не найден")
    return d


def _out(d: RefDocument, replaces: list[str]) -> DocumentOut:
    return DocumentOut(
        **{k: getattr(d, k) for k in FIELDS if k != "position"},
        code=d.code,
        replaces=replaces,
        origin=d.origin,
        verified=d.verified_at is not None,
        verified_by_name=d.verified_by_name,
        verified_at=d.verified_at,
        revision=d.revision,
        updated_at=d.updated_at,
    )


def _replaces(session: Session, code: str) -> list[str]:
    return list(
        session.scalars(
            select(RefDocument.code)
            .where(RefDocument.replaced_by == code)
            .order_by(RefDocument.position)
        )
    )


def _detail(session: Session, d: RefDocument) -> DocumentDetail:
    revisions = session.scalars(
        select(RefRevision)
        .where(RefRevision.entity == "document", RefRevision.entity_key == d.code)
        .order_by(RefRevision.id.desc())
    )
    return DocumentDetail(
        **_out(d, _replaces(session, d.code)).model_dump(),
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


@router.get("/refs/documents", response_model=list[DocumentOut])
def list_documents(_: CurrentUser, session: DbSession) -> list[DocumentOut]:
    rows = list(
        session.scalars(select(RefDocument).order_by(RefDocument.position, RefDocument.code))
    )
    replaces: dict[str, list[str]] = {}
    for d in rows:
        if d.replaced_by:
            replaces.setdefault(d.replaced_by, []).append(d.code)
    return [_out(d, replaces.get(d.code, [])) for d in rows]


@router.get("/refs/documents/{code}", response_model=DocumentDetail)
def get_document(code: str, _: CurrentUser, session: DbSession) -> DocumentDetail:
    return _detail(session, _get(session, code))


@router.patch("/refs/documents/{code}", response_model=DocumentDetail)
def update_document(
    code: str, body: DocumentPatch, request: Request, user: RefEditor, session: DbSession
) -> DocumentDetail:
    d = _get(session, code)
    sent = body.model_dump(exclude_unset=True, exclude={"comment"})
    if "source" in sent and body.source is not None:
        sent["source"] = body.source.model_dump(exclude_none=True)
    # Пустая строка в необязательном поле — «очистить».
    for k in ("issuer", "number", "url", "replaced_by"):
        if sent.get(k) == "":
            sent[k] = None
    changes = {k: v for k, v in sent.items() if getattr(d, k) != v}
    if not changes:
        return _detail(session, d)
    wanted = {k: getattr(d, k) for k in FIELDS} | changes | {"code": d.code}
    codes = set(session.scalars(select(RefDocument.code)))
    try:
        validate_doc(wanted, codes)
    except DocumentError as e:
        raise HTTPException(422, detail=str(e)) from e
    session.add(
        RefRevision(
            entity="document",
            entity_key=d.code,
            revision=d.revision,
            data=document_snapshot(d),
            changed_by=user.id,
            changed_by_name=user.display_name,
            comment=body.comment,
        )
    )
    for k, v in changes.items():
        setattr(d, k, v)
    d.origin = "local"
    d.revision += 1
    d.updated_at = utcnow()
    d.updated_by = user.id
    d.verified_by = d.verified_by_name = d.verified_at = None
    audit.record(
        session,
        action="refs.document.update",
        actor=user,
        entity="document",
        entity_id=d.code,
        ip=client_ip(request),
        details={"fields": sorted(changes), "revision": d.revision, "comment": body.comment},
    )
    session.commit()
    return _detail(session, d)


@router.post("/refs/documents/{code}/verify", response_model=DocumentDetail)
def verify_document(
    code: str, body: VerifyIn, request: Request, user: RefVerifier, session: DbSession
) -> DocumentDetail:
    d = _get(session, code)
    if body.revision != d.revision:
        raise HTTPException(409, detail="Запись изменилась, пока вы её смотрели. Обновите страницу")
    try:
        ensure_not_own_work(user.id, d.updated_by)
    except SelfApprovalError as e:
        raise HTTPException(403, detail="Нельзя сверить собственную правку") from e
    d.verified_by = user.id
    d.verified_by_name = user.display_name
    d.verified_at = utcnow()
    audit.record(
        session,
        action="refs.document.verify",
        actor=user,
        entity="document",
        entity_id=d.code,
        ip=client_ip(request),
        details={"revision": d.revision},
    )
    session.commit()
    return _detail(session, d)
