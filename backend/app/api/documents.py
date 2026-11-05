"""Документы комплекта объекта (задача 3.1): карта данных, формирование, скачивание.

- `GET /objects/{id}/documents` — документы каталога, применимые к объекту, с
  картой полей по текущим данным и сформированными версиями.
- `GET /objects/{id}/documents/types/{code}` — подробная карта «из каких данных
  собран / какие поля пустые» по текущим данным.
- `POST /objects/{id}/documents {type}` — новая версия (право `documents.edit`);
  те же данные — та же версия, без дубля.
- `GET /documents/{id}` — версия с картой полей на момент формирования.
- `GET /documents/{id}/file?format=docx|pdf` — скачивание.
- (3.2) `PUT /objects/{id}/documents/settings {font}` — шрифт комплекта объекта
  (PT Astra Serif или Inter) для встроенных шаблонов.
- (3.2) Свой шаблон документа — общий для всех проектов: `GET /document-templates`,
  `GET /document-templates/{code}/builtin` (встроенный — основа для своего),
  `POST /document-templates/{code}` (multipart: file, comment), `POST
  /document-templates/{code}/reset` (вернуть встроенный),
  `GET /document-templates/files/{id}` — загруженный файл.

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
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select, true
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.objects import _editable, get_object_for
from app.core.config import get_settings
from app.core.rbac import Perm, perms_for
from app.db.models import AssessedObject, DocumentTemplate, GeneratedDocument, User
from app.docs_gen import context, fieldmap, pdf, render
from app.domain import documents as svc
from app.domain.evidence_files import clean_name

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
    template_name: str
    template_custom: bool
    font: str | None
    font_title: str | None


class DocOut(DocBrief):
    context_hash: str
    fields: list[FieldOut]
    unverified: list[dict[str, str]]


class TemplateRef(BaseModel):
    """Действующий шаблон документа: встроенный или свой."""

    custom: bool
    name: str
    id: uuid.UUID | None = None
    uploaded_at: datetime | None = None
    uploaded_by_name: str | None = None
    comment: str | None = None


class TypeOut(BaseModel):
    code: str
    title: str
    description: str
    template: str
    template_found: bool
    template_ref: TemplateRef
    # Шрифт, которым соберётся документ; None — свой шаблон (шрифты его).
    font: str | None
    counts: Counts
    watermark_reasons: list[str]
    # Данные изменились после последней версии (или версий ещё нет).
    changed: bool
    latest: DocBrief | None
    versions: list[DocBrief]


class TypeDetail(TypeOut):
    fields: list[FieldOut]
    unverified: list[dict[str, str]]


class FontOut(BaseModel):
    code: str
    title: str


class DocumentsOut(BaseModel):
    types: list[TypeOut]
    pdf_available: bool
    can_edit: bool
    sees_drafts: bool
    font: str
    fonts: list[FontOut]


class SettingsIn(BaseModel):
    font: Literal["astra", "inter"]


class SettingsOut(BaseModel):
    font: str


class TemplateOut(BaseModel):
    id: uuid.UUID
    doc_type: str
    name: str
    size: int
    variables: list[str]
    active: bool
    comment: str | None
    uploaded_at: datetime
    uploaded_by_name: str | None
    deactivated_at: datetime | None
    deactivated_by_name: str | None


class TemplateTypeOut(BaseModel):
    code: str
    title: str
    builtin: str
    active: TemplateOut | None
    history: list[TemplateOut]


class TemplatesOut(BaseModel):
    types: list[TemplateTypeOut]
    can_manage: bool
    allowed_names: list[str]


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
        template_name=d.template_name,
        template_custom=d.template_id is not None,
        font=d.font,
        font_title=render.FONTS.get(d.font or ""),
    )


def _out(d: GeneratedDocument) -> DocOut:
    return DocOut(
        **_brief(d).model_dump(),
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
    custom = pv.template.custom
    return {
        "code": pv.doc.code,
        "title": pv.title,
        "description": pv.doc.description,
        "template": pv.template.name,
        "template_found": pv.template_sha256 is not None,
        "template_ref": TemplateRef(
            custom=custom is not None,
            name=pv.template.name,
            id=custom.id if custom else None,
            uploaded_at=custom.uploaded_at if custom else None,
            uploaded_by_name=custom.uploaded_by_name if custom else None,
            comment=custom.comment if custom else None,
        ),
        "font": pv.font,
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
    ctx = context.build(session, obj)  # один раз на все документы комплекта
    types = []
    for doc in _applicable(obj):
        pv = svc.preview(session, obj, doc, full_context=ctx)
        types.append(TypeOut(**_type_out(session, obj, pv, versions.get(doc.code, []))))
    return DocumentsOut(
        types=types,
        pdf_available=pdf.converter_path(get_settings().pdf_converter) is not None,
        can_edit=Perm.DOCUMENTS_EDIT in perms_for(user.roles),
        sees_drafts=sees_drafts(user),
        font=svc.object_font(obj),
        fonts=[FontOut(code=k, title=v) for k, v in render.FONTS.items()],
    )


@router.put("/objects/{object_id}/documents/settings")
def document_settings(
    object_id: uuid.UUID, body: SettingsIn, request: Request, user: Editor, session: DbSession
) -> SettingsOut:
    """Шрифт комплекта объекта; документы со встроенным шаблоном станут «изменёнными»."""
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    before = svc.object_font(obj)
    if before != body.font:
        obj.doc_font = body.font
        audit.record(
            session,
            action="documents.settings",
            actor=user,
            entity="object",
            entity_id=obj.id,
            project_id=obj.project_id,
            ip=client_ip(request),
            details={"font": {"from": before, "to": body.font}},
        )
        session.commit()
    return SettingsOut(font=body.font)


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


# ---------- Свой шаблон документа (задача 3.2) ----------

_DOCX = MIME["docx"]


def _template_out(t: DocumentTemplate) -> TemplateOut:
    return TemplateOut(
        id=t.id,
        doc_type=t.doc_type,
        name=t.name,
        size=t.size,
        variables=list(t.variables or []),
        active=t.active,
        comment=t.comment,
        uploaded_at=t.uploaded_at,
        uploaded_by_name=t.uploaded_by_name,
        deactivated_at=t.deactivated_at,
        deactivated_by_name=t.deactivated_by_name,
    )


def _doc_type(code: str):
    try:
        return svc.get_type(code)
    except svc.DocumentError as e:
        raise HTTPException(e.status, detail=str(e)) from e


def _attachment(path, name: str) -> FileResponse:
    ascii_name = name.encode("ascii", "replace").decode().replace('"', "_").replace("?", "_")
    return FileResponse(
        path,
        media_type=_DOCX,
        headers={
            "Content-Disposition": (
                f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}"
            ),
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "private, no-store",
        },
    )


@router.get("/document-templates")
def list_templates(user: Viewer, session: DbSession) -> TemplatesOut:
    rows = list(
        session.scalars(select(DocumentTemplate).order_by(DocumentTemplate.uploaded_at.desc()))
    )
    by_type: dict[str, list[DocumentTemplate]] = {}
    for t in rows:
        by_type.setdefault(t.doc_type, []).append(t)
    types = []
    for doc in svc.doc_types().values():
        hist = by_type.get(doc.code, [])
        active = next((t for t in hist if t.active), None)
        types.append(
            TemplateTypeOut(
                code=doc.code,
                title=doc.title,
                builtin=doc.template,
                active=_template_out(active) if active else None,
                history=[_template_out(t) for t in hist],
            )
        )
    return TemplatesOut(
        types=types,
        can_manage=Perm.DOCUMENTS_EDIT in perms_for(user.roles),
        allowed_names=sorted(svc.allowed_names()),
    )


@router.get("/document-templates/{code}/builtin")
def download_builtin(code: str, user: Editor) -> FileResponse:
    """Встроенный шаблон — основа для своего (поля Jinja уже расставлены)."""
    doc = _doc_type(code)
    path = svc.builtin_path(doc)
    if not path.is_file():
        raise HTTPException(404, detail=f"Шаблон {doc.template} не найден")
    return _attachment(path, f"Шаблон — {doc.title}.docx")


@router.get("/document-templates/files/{template_id}")
def download_custom(template_id: uuid.UUID, user: Editor, session: DbSession) -> FileResponse:
    t = session.get(DocumentTemplate, template_id)
    if t is None:
        raise HTTPException(404, detail="Шаблон не найден")
    path = svc.custom_dir() / t.sha256
    if not path.is_file():
        raise HTTPException(
            410,
            detail="Шаблон есть в базе, но файла нет в хранилище — восстановите том из копии",
            headers={"X-Error-Code": "file_missing"},
        )
    return _attachment(path, t.name)


@router.post("/document-templates/{code}", status_code=201)
async def upload_template(
    code: str, request: Request, user: Editor, session: DbSession
) -> TemplateOut:
    """Свой шаблон (multipart: file — DOCX, comment — необязательно). Сразу действует
    для всех проектов; прежний свой шаблон остаётся в истории."""
    doc = _doc_type(code)
    if not request.headers.get("content-type", "").startswith("multipart/form-data"):
        raise HTTPException(422, detail="Приложите шаблон DOCX (multipart/form-data, поле file)")
    form = await request.form(max_files=1, max_fields=5)
    got = form.get("file")
    if not isinstance(got, UploadFile):
        raise HTTPException(422, detail="Приложите шаблон DOCX (поле file)")
    comment = form.get("comment")
    comment = comment.strip()[:1000] or None if isinstance(comment, str) else None
    data = await got.read(svc.MAX_TEMPLATE_BYTES + 1)
    name = clean_name(got.filename or "") or "template.docx"
    return await run_in_threadpool(
        _store_template, doc, data, name, comment, user, session, client_ip(request)
    )


def _store_template(
    doc, data: bytes, name: str, comment: str | None, user: User, session: Session, ip
) -> TemplateOut:
    if not name.lower().endswith(".docx"):
        raise HTTPException(422, detail="Нужен шаблон в формате DOCX")
    try:
        row = svc.upload_template(session, doc, data, name, user, comment)
    except svc.DocumentError as e:
        audit.record_now(
            session,
            action="documents.template.rejected",
            actor=user,
            result="error",
            ip=ip,
            details={"type": doc.code, "name": name, "reason": str(e)[:300]},
        )
        raise HTTPException(e.status, detail=str(e), headers={"X-Error-Code": e.code}) from e
    audit.record(
        session,
        action="documents.template.upload",
        actor=user,
        entity="document_template",
        entity_id=row.id,
        ip=ip,
        details={"type": doc.code, "name": name, "sha256": row.sha256, "size": row.size},
    )
    session.commit()
    return _template_out(row)


@router.post("/document-templates/{code}/reset")
def reset_template(code: str, request: Request, user: Editor, session: DbSession) -> TemplatesOut:
    """Вернуть встроенный шаблон документа."""
    doc = _doc_type(code)
    prev = svc.reset_template(session, doc, user)
    if prev is not None:
        audit.record(
            session,
            action="documents.template.reset",
            actor=user,
            entity="document_template",
            entity_id=prev.id,
            ip=client_ip(request),
            details={"type": doc.code, "name": prev.name},
        )
        session.commit()
    return list_templates(user, session)
