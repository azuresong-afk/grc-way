"""Документы комплекта объекта (задача 3.1): карта данных, формирование, скачивание.

- `GET /objects/{id}/documents` — документы каталога, применимые к объекту, с
  картой полей по текущим данным и сформированными версиями.
- `GET /objects/{id}/documents/types/{code}` — подробная карта «из каких данных
  собран / какие поля пустые» по текущим данным.
- `POST /objects/{id}/documents {type}` — новая версия (право `documents.edit`);
  те же данные — та же версия, без дубля.
- `GET /documents/{id}` — версия с картой полей на момент формирования.
- `GET /documents/{id}/file?format=docx|pdf` — скачивание.

Проекты (черновики) видят методист, эксперт и утверждающий. Наблюдатель
(представитель заказчика) видит только утверждённые документы — они появятся
с согласованием в задаче 3.3.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select, true
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.objects import _editable, get_object_for
from app.core.config import get_settings
from app.core.rbac import Perm, perms_for
from app.db.models import AssessedObject, GeneratedDocument, User
from app.docs_gen import fieldmap, pdf
from app.domain import documents as svc

router = APIRouter(tags=["documents"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Editor = Annotated[User, Depends(require(Perm.DOCUMENTS_EDIT))]

MIME = {
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "pdf": "application/pdf",
}
# Кто видит проекты документов (не только утверждённые).
_DRAFT_PERMS = {Perm.DOCUMENTS_EDIT, Perm.ASSESSMENT_EDIT, Perm.APPROVE}


def sees_drafts(user: User) -> bool:
    return bool(perms_for(user.roles) & _DRAFT_PERMS)


# ---------- Схемы ----------


class FieldOut(BaseModel):
    key: str
    title: str
    source: str
    tab: str
    required: bool
    state: str
    value: str | None
    total: int | None = None
    missing: int | None = None
    missing_examples: list[str] | None = None


class Counts(BaseModel):
    total: int
    empty: int
    required_empty: int


class DocBrief(BaseModel):
    id: uuid.UUID
    doc_type: str
    title: str
    version: int
    status: str
    status_title: str
    watermark: bool
    watermark_reasons: list[str]
    counts: Counts
    docx_size: int
    pdf_size: int | None
    pdf_error: str | None
    created_at: datetime
    created_by_name: str | None


class DocOut(DocBrief):
    template_name: str
    context_hash: str
    fields: list[FieldOut]
    unverified: list[dict[str, str]]


class TypeOut(BaseModel):
    code: str
    title: str
    description: str
    template: str
    template_found: bool
    counts: Counts
    watermark_reasons: list[str]
    # Данные изменились после последней версии (или версий ещё нет).
    changed: bool
    latest: DocBrief | None
    versions: list[DocBrief]


class TypeDetail(TypeOut):
    fields: list[FieldOut]
    unverified: list[dict[str, str]]


class DocumentsOut(BaseModel):
    types: list[TypeOut]
    pdf_available: bool
    can_edit: bool
    sees_drafts: bool


class GenerateIn(BaseModel):
    type: str


class GenerateOut(DocOut):
    created: bool


# ---------- Вспомогательное ----------


def _counts(fields: list[dict[str, Any]] | list[fieldmap.FieldState]) -> Counts:
    states = [f if isinstance(f, fieldmap.FieldState) else fieldmap.FieldState(**f) for f in fields]
    return Counts(**fieldmap.counts(states))


def _brief(d: GeneratedDocument) -> DocBrief:
    return DocBrief(
        id=d.id,
        doc_type=d.doc_type,
        title=d.title,
        version=d.version,
        status=d.status,
        status_title=svc.STATUS_TITLES.get(d.status, d.status),
        watermark=d.watermark,
        watermark_reasons=d.watermark_reasons or [],
        counts=_counts(d.field_map or []),
        docx_size=d.docx_size,
        pdf_size=d.pdf_size,
        pdf_error=d.pdf_error,
        created_at=d.created_at,
        created_by_name=d.created_by_name,
    )


def _out(d: GeneratedDocument) -> DocOut:
    return DocOut(
        **_brief(d).model_dump(),
        template_name=d.template_name,
        context_hash=d.context_hash,
        fields=[FieldOut(**f) for f in d.field_map or []],
        unverified=d.unverified or [],
    )


def _visible(user: User):
    """Условие: какие версии видит пользователь."""
    if sees_drafts(user):
        return true()
    return GeneratedDocument.status == "approved"


def _versions(session: Session, obj: AssessedObject, user: User) -> dict[str, list[DocBrief]]:
    out: dict[str, list[DocBrief]] = {}
    rows = session.scalars(
        select(GeneratedDocument)
        .where(GeneratedDocument.object_id == obj.id, _visible(user))
        .order_by(GeneratedDocument.doc_type, GeneratedDocument.version.desc())
    )
    for d in rows:
        out.setdefault(d.doc_type, []).append(_brief(d))
    return out


def _type_out(
    session: Session, obj: AssessedObject, pv: svc.Preview, versions: list[DocBrief]
) -> dict[str, Any]:
    last = svc.latest(session, obj.id, pv.doc.code)
    return {
        "code": pv.doc.code,
        "title": pv.doc.title,
        "description": pv.doc.description,
        "template": pv.doc.template,
        "template_found": pv.template_sha256 is not None,
        "counts": _counts(pv.states),
        "watermark_reasons": pv.watermark_reasons,
        "changed": last is None or last.context_hash != pv.context_hash,
        "latest": versions[0] if versions else None,
        "versions": versions,
    }


def _applicable(obj: AssessedObject, code: str | None = None) -> list:
    types = [d for d in svc.doc_types().values() if d.applies_to(obj.regime)]
    if code is not None:
        types = [d for d in types if d.code == code]
        if not types:
            raise HTTPException(404, detail="Документ не применяется к этому объекту")
    return types


def _get_doc(session: Session, doc_id: uuid.UUID, user: User) -> GeneratedDocument:
    d = session.get(GeneratedDocument, doc_id)
    if d is None or (d.status != "approved" and not sees_drafts(user)):
        raise HTTPException(404, detail="Документ не найден")
    try:
        get_object_for(session, d.object_id, user)
    except HTTPException as e:
        raise HTTPException(404, detail="Документ не найден") from e
    return d


# ---------- Эндпоинты ----------


@router.get("/objects/{object_id}/documents")
def list_documents(object_id: uuid.UUID, user: Viewer, session: DbSession) -> DocumentsOut:
    obj = get_object_for(session, object_id, user)
    versions = _versions(session, obj, user)
    types = []
    for doc in _applicable(obj):
        pv = svc.preview(session, obj, doc)
        types.append(TypeOut(**_type_out(session, obj, pv, versions.get(doc.code, []))))
    return DocumentsOut(
        types=types,
        pdf_available=pdf.converter_path(get_settings().pdf_converter) is not None,
        can_edit=Perm.DOCUMENTS_EDIT in perms_for(user.roles),
        sees_drafts=sees_drafts(user),
    )


@router.get("/objects/{object_id}/documents/types/{code}")
def document_type(object_id: uuid.UUID, code: str, user: Viewer, session: DbSession) -> TypeDetail:
    obj = get_object_for(session, object_id, user)
    doc = _applicable(obj, code)[0]
    pv = svc.preview(session, obj, doc)
    versions = _versions(session, obj, user).get(code, [])
    return TypeDetail(
        **_type_out(session, obj, pv, versions),
        fields=[FieldOut(**f) for f in fieldmap.map_out(pv.states)],
        unverified=pv.unverified,
    )


@router.post("/objects/{object_id}/documents", status_code=201)
def generate_document(
    object_id: uuid.UUID, body: GenerateIn, request: Request, user: Editor, session: DbSession
) -> GenerateOut:
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    doc = _applicable(obj, body.type)[0]
    try:
        row, created = svc.generate(session, obj, doc, user)
    except svc.DocumentError as e:
        raise HTTPException(e.status, detail=str(e), headers={"X-Error-Code": e.code}) from e
    if created:
        audit.record(
            session,
            action="documents.generate",
            actor=user,
            entity="document",
            entity_id=row.id,
            project_id=obj.project_id,
            ip=client_ip(request),
            details={
                "object_id": str(obj.id),
                "type": row.doc_type,
                "version": row.version,
                "context_hash": row.context_hash,
                "pdf": row.pdf_sha256 is not None,
                "empty_fields": _counts(row.field_map).empty,
            },
        )
    session.commit()
    return GenerateOut(**_out(row).model_dump(), created=created)


@router.get("/documents/{doc_id}")
def get_document(doc_id: uuid.UUID, user: Viewer, session: DbSession) -> DocOut:
    return _out(_get_doc(session, doc_id, user))


def _file_name(session: Session, d: GeneratedDocument, fmt: str) -> str:
    obj = session.get(AssessedObject, d.object_id)
    name = f"{d.title} — {obj.name if obj else ''} — v{d.version}"
    name = "".join(ch for ch in name if ch not in '\\/:*?"<>|').strip()[:180]
    return f"{name}.{fmt}"


@router.get("/documents/{doc_id}/file")
def download_document(
    doc_id: uuid.UUID,
    request: Request,
    user: Viewer,
    session: DbSession,
    format: Annotated[Literal["docx", "pdf"], Query()] = "docx",
) -> FileResponse:
    d = _get_doc(session, doc_id, user)
    sha = d.docx_sha256 if format == "docx" else d.pdf_sha256
    if sha is None:
        raise HTTPException(404, detail=d.pdf_error or "PDF для этой версии нет")
    path = get_settings().documents_dir / sha
    if not path.is_file():
        raise HTTPException(
            410,
            detail="Документ есть в базе, но файла нет в хранилище — восстановите том из копии",
            headers={"X-Error-Code": "file_missing"},
        )
    audit.record_now(
        session,
        action="documents.download",
        actor=user,
        entity="document",
        entity_id=d.id,
        project_id=d.project_id,
        ip=client_ip(request),
        details={"type": d.doc_type, "version": d.version, "format": format},
    )
    name = _file_name(session, d, format)
    ascii_name = name.encode("ascii", "replace").decode().replace('"', "_").replace("?", "_")
    return FileResponse(
        path,
        media_type=MIME[format],
        headers={
            "Content-Disposition": (
                f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}"
            ),
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "private, no-store",
        },
    )
