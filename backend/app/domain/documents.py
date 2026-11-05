"""Формирование документов комплекта (задача 3.1).

Порядок: контекст из данных объекта → карта полей → заглушки на месте пустых
полей → docxtpl → водяной знак «Проект» → DOCX в том → PDF через LibreOffice.

- Тот же контекст и шаблон, что у последней версии, — новая версия не
  создаётся (возвращается последняя).
- Водяной знак ставится, пока документ не утверждён (утверждение — задача 3.3)
  и пока в нём есть записи справочников, не сверенные методистом (раздел 2
  дорожной карты); причины сохраняются в записи документа.
- PDF не обязателен: если LibreOffice нет или он не справился, версия
  сохраняется с DOCX и причиной, почему нет PDF.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import AssessedObject, GeneratedDocument, User
from app.docs_gen import catalog, context, fieldmap, pdf, render

STATUS_TITLES = {"draft": "Проект", "review": "На согласовании", "approved": "Утверждён"}
REASON_DRAFT = "Документ не утверждён"
REASON_UNVERIFIED = "Использованы записи справочников, не сверенные методистом"


class DocumentError(ValueError):
    """Документ не сформирован; текст — для пользователя."""

    def __init__(self, detail: str, code: str = "document_error", status: int = 409) -> None:
        super().__init__(detail)
        self.code = code
        self.status = status


@dataclass
class Preview:
    doc: catalog.DocType
    context: dict[str, Any]
    states: list[fieldmap.FieldState]
    unverified: list[dict[str, str]]
    watermark_reasons: list[str]
    template_sha256: str | None
    context_hash: str | None


def doc_types() -> dict[str, catalog.DocType]:
    return catalog.load(get_settings().reference_dir)


def get_type(code: str) -> catalog.DocType:
    doc = doc_types().get(code)
    if doc is None:
        raise DocumentError("Такого документа нет в каталоге", "document_unknown", 404)
    return doc


def template_path(doc: catalog.DocType) -> Path:
    return get_settings().templates_dir / doc.template


def watermark_reasons(status: str, unverified: list[dict[str, str]]) -> list[str]:
    out = []
    if status != "approved":
        out.append(REASON_DRAFT)
    if unverified:
        out.append(REASON_UNVERIFIED)
    return out


def preview(
    session: Session, obj: AssessedObject, doc: catalog.DocType, *, today: date | None = None
) -> Preview:
    """Карта «из каких данных собран» по текущим данным, без формирования."""
    ctx = context.build(session, obj, today=today)
    tpl = template_path(doc)
    tpl_sha = catalog.file_sha256(tpl) if tpl.is_file() else None
    return Preview(
        doc=doc,
        context=ctx,
        states=fieldmap.field_map(ctx, doc),
        unverified=ctx["unverified"],
        watermark_reasons=watermark_reasons("draft", ctx["unverified"]),
        template_sha256=tpl_sha,
        context_hash=context.context_hash(ctx, tpl_sha) if tpl_sha else None,
    )


def latest(session: Session, object_id: Any, doc_type: str) -> GeneratedDocument | None:
    return session.scalars(
        select(GeneratedDocument)
        .where(GeneratedDocument.object_id == object_id, GeneratedDocument.doc_type == doc_type)
        .order_by(GeneratedDocument.version.desc())
        .limit(1)
    ).first()


def put_file(data: bytes, directory: Path) -> str:
    """Кладёт содержимое в том под именем sha256 (атомарно); возвращает sha256."""
    sha = hashlib.sha256(data).hexdigest()
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / sha
    if target.exists():
        return sha
    fd, tmp = tempfile.mkstemp(prefix=".doc-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        os.chmod(tmp, 0o640)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return sha


def _pdf(docx: bytes) -> tuple[bytes | None, str | None]:
    s = get_settings()
    soffice = pdf.converter_path(s.pdf_converter)
    if soffice is None:
        return None, "PDF не сформирован: LibreOffice (soffice) не установлен или выключен"
    try:
        return pdf.convert(docx, soffice=soffice, timeout=s.pdf_timeout_seconds), None
    except pdf.PdfError as e:
        return None, f"PDF не сформирован: {e}"[:1000]


def generate(
    session: Session,
    obj: AssessedObject,
    doc: catalog.DocType,
    user: User,
    *,
    today: date | None = None,
) -> tuple[GeneratedDocument, bool]:
    """Новая версия документа; (документ, создан ли новый)."""
    today = today or date.today()
    pv = preview(session, obj, doc, today=today)
    if pv.template_sha256 is None or pv.context_hash is None:
        raise DocumentError(
            f"Шаблон {doc.template} не найден — проверьте каталог templates/docx",
            "template_missing",
        )
    last = latest(session, obj.id, doc.code)
    if last is not None and last.context_hash == pv.context_hash:
        return last, False

    version = (
        session.scalar(
            select(func.max(GeneratedDocument.version)).where(
                GeneratedDocument.object_id == obj.id, GeneratedDocument.doc_type == doc.code
            )
        )
        or 0
    ) + 1
    status = "draft"
    reasons = watermark_reasons(status, pv.unverified)
    tpl_ctx = fieldmap.fill_placeholders(pv.context, doc)
    tpl_ctx["doc"] = {
        "title": doc.title,
        "version": version,
        "generated": today.strftime("%d.%m.%Y"),
        "status_title": STATUS_TITLES[status],
    }
    try:
        docx = render.render(template_path(doc), tpl_ctx, watermark=bool(reasons))
    except render.RenderError as e:
        raise DocumentError(str(e), "template_error") from e
    pdf_bytes, pdf_error = _pdf(docx)

    directory = get_settings().documents_dir
    row = GeneratedDocument(
        object_id=obj.id,
        project_id=obj.project_id,
        doc_type=doc.code,
        title=doc.title,
        version=version,
        status=status,
        template_name=doc.template,
        template_sha256=pv.template_sha256,
        context_hash=pv.context_hash,
        context=pv.context,
        field_map=fieldmap.map_out(pv.states),
        unverified=pv.unverified,
        watermark=bool(reasons),
        watermark_reasons=reasons,
        docx_sha256=put_file(docx, directory),
        docx_size=len(docx),
        pdf_sha256=put_file(pdf_bytes, directory) if pdf_bytes else None,
        pdf_size=len(pdf_bytes) if pdf_bytes else None,
        pdf_error=pdf_error,
        created_by=user.id,
        created_by_name=user.display_name,
    )
    session.add(row)
    session.flush()
    return row, True
