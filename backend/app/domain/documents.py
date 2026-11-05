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
- (3.2) Документ берёт из контекста только разделы, которые использует его
  шаблон: от них считается хэш и по ним — несверенные записи. Шаблон —
  встроенный (templates/docx, шрифт объекта: PT Astra Serif или Inter) или
  свой, загруженный пользователем (document_templates; шрифты — его).
- (3.3) Согласование: проект → на согласовании → утверждён; прежняя
  утверждённая версия — «заменён». Отправить и утвердить можно только
  последнюю версию; новая версия возвращает версию «на согласовании» в
  проекты. Утверждение пересобирает документ из сохранённого контекста по тому
  же шаблону — без отметки «Проект» и с датой и именем утвердившего; если в
  документе есть несверенные записи справочников, утвердить можно только с
  явным подтверждением, и водяной знак остаётся.
"""

from __future__ import annotations

import hashlib
import io
import os
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, date
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import (
    AssessedObject,
    DocumentReview,
    DocumentTemplate,
    GeneratedDocument,
    User,
    utcnow,
)
from app.docs_gen import catalog, context, fieldmap, pdf, render

STATUS_TITLES = {
    "draft": "Проект",
    "review": "На согласовании",
    "approved": "Утверждён",
    "superseded": "Заменён",
}
# Статусы, которые видит наблюдатель (представитель заказчика).
PUBLISHED = ("approved", "superseded")
REASON_DRAFT = "Документ не утверждён"
REASON_UNVERIFIED = "Использованы записи справочников, не сверенные методистом"


class DocumentError(ValueError):
    """Документ не сформирован; текст — для пользователя."""

    def __init__(self, detail: str, code: str = "document_error", status: int = 409) -> None:
        super().__init__(detail)
        self.code = code
        self.status = status


@dataclass
class Template:
    """Чем собирается документ: встроенный шаблон или свой."""

    path: Path
    name: str
    custom: DocumentTemplate | None = None

    @property
    def found(self) -> bool:
        return self.path.is_file()


@dataclass
class Preview:
    doc: catalog.DocType
    title: str
    context: dict[str, Any]
    states: list[fieldmap.FieldState]
    unverified: list[dict[str, str]]
    watermark_reasons: list[str]
    template: Template
    font: str | None
    template_sha256: str | None
    context_hash: str | None


def doc_types() -> dict[str, catalog.DocType]:
    return catalog.load(get_settings().reference_dir)


def get_type(code: str) -> catalog.DocType:
    doc = doc_types().get(code)
    if doc is None:
        raise DocumentError("Такого документа нет в каталоге", "document_unknown", 404)
    return doc


def builtin_path(doc: catalog.DocType) -> Path:
    return get_settings().templates_dir / doc.template


def template_path(doc: catalog.DocType) -> Path:
    """Встроенный шаблон (совместимость с 3.1)."""
    return builtin_path(doc)


def custom_dir() -> Path:
    return get_settings().documents_dir / "templates"


def active_custom(session: Session, code: str) -> DocumentTemplate | None:
    return session.scalars(
        select(DocumentTemplate).where(
            DocumentTemplate.doc_type == code, DocumentTemplate.active.is_(True)
        )
    ).first()


def resolve_template(session: Session, doc: catalog.DocType) -> Template:
    custom = active_custom(session, doc.code)
    if custom is not None:
        return Template(custom_dir() / custom.sha256, custom.name, custom)
    return Template(builtin_path(doc), doc.template)


def object_font(obj: AssessedObject) -> str:
    return obj.doc_font if obj.doc_font in render.FONTS else render.DEFAULT_FONT


def watermark_reasons(status: str, unverified: list[dict[str, str]]) -> list[str]:
    out = []
    if status not in PUBLISHED:
        out.append(REASON_DRAFT)
    if unverified:
        out.append(REASON_UNVERIFIED)
    return out


def _used(tpl: Template, sha: str) -> frozenset[str] | None:
    try:
        return render.template_variables(tpl.path, sha)
    except render.RenderError:
        return None


def doc_context(
    ctx: dict[str, Any], used: frozenset[str] | None
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Разделы контекста, которые выводит шаблон, и несверенные записи по ним."""
    if used is None:
        return ctx, list(ctx.get("unverified") or [])
    part = {k: v for k, v in ctx.items() if k in used and k != "unverified"}
    unverified = [
        u for u in ctx.get("unverified") or [] if u.get("section") in used or not u.get("section")
    ]
    part["unverified"] = unverified
    return part, unverified


def preview(
    session: Session,
    obj: AssessedObject,
    doc: catalog.DocType,
    *,
    today: date | None = None,
    full_context: dict[str, Any] | None = None,
) -> Preview:
    """Карта «из каких данных собран» по текущим данным, без формирования.

    full_context — уже собранный контекст объекта (список документов строит его
    один раз для всех).
    """
    ctx = full_context if full_context is not None else context.build(session, obj, today=today)
    tpl = resolve_template(session, doc)
    tpl_sha = catalog.file_sha256(tpl.path) if tpl.found else None
    font = None if tpl.custom else object_font(obj)
    part, unverified = doc_context(ctx, _used(tpl, tpl_sha) if tpl_sha else None)
    return Preview(
        doc=doc,
        title=doc.title_for(obj.regime),
        context=part,
        states=fieldmap.field_map(ctx, doc),
        unverified=unverified,
        watermark_reasons=watermark_reasons("draft", unverified),
        template=tpl,
        font=font,
        template_sha256=tpl_sha,
        context_hash=(context.context_hash({**part, "_font": font}, tpl_sha) if tpl_sha else None),
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
        where = "том документов" if pv.template.custom else "каталог templates/docx"
        raise DocumentError(
            f"Шаблон {pv.template.name} не найден — проверьте {where}", "template_missing"
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
    tpl_ctx["doc"] = doc_meta(pv.title, version, today, status)
    try:
        docx = render.render(pv.template.path, tpl_ctx, watermark=bool(reasons), font=pv.font)
    except render.RenderError as e:
        raise DocumentError(str(e), "template_error") from e
    pdf_bytes, pdf_error = _pdf(docx)

    directory = get_settings().documents_dir
    row = GeneratedDocument(
        object_id=obj.id,
        project_id=obj.project_id,
        doc_type=doc.code,
        title=pv.title,
        version=version,
        status=status,
        template_name=pv.template.name,
        template_id=pv.template.custom.id if pv.template.custom else None,
        font=pv.font,
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
    # Версия «на согласовании» устарела: возвращается в проекты.
    if last is not None and last.status == "review":
        _move(
            session,
            last,
            "return",
            "draft",
            user,
            f"Сформирована версия {version} — согласуется последняя версия",
        )
    return row, True


def doc_meta(
    title: str,
    version: int,
    generated: date,
    status: str,
    approved: date | None = None,
    approved_by: str | None = None,
) -> dict[str, Any]:
    """Раздел doc шаблона: заголовок, версия, дата, статус, кто утвердил."""
    return {
        "title": title,
        "version": version,
        "generated": generated.strftime("%d.%m.%Y"),
        "status_title": STATUS_TITLES[status],
        "approved": approved.strftime("%d.%m.%Y") if approved else None,
        "approved_by": approved_by,
    }


# ---------- Свой шаблон ----------

# Ограничения загружаемого шаблона: DOCX — zip; распакованный объём ограничен,
# чтобы «zip-бомба» не заняла память при разборе.
MAX_TEMPLATE_BYTES = 10 * 1024 * 1024
MAX_TEMPLATE_UNPACKED = 64 * 1024 * 1024
# Что, кроме разделов контекста, шаблон может использовать.
EXTRA_NAMES = frozenset({"doc", "empty"})


def allowed_names() -> frozenset[str]:
    return frozenset(context.CONTEXT_KEYS) | EXTRA_NAMES


def check_template(data: bytes, name: str) -> list[str]:
    """Проверка загруженного DOCX; возвращает имена верхнего уровня, которые он использует."""
    if not data:
        raise DocumentError("Файл пустой", "template_invalid", 422)
    if len(data) > MAX_TEMPLATE_BYTES:
        raise DocumentError(
            f"Шаблон больше {MAX_TEMPLATE_BYTES // (1024 * 1024)} МБ", "template_invalid", 413
        )
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            names = {i.filename for i in infos}
            if "word/document.xml" not in names or "[Content_Types].xml" not in names:
                raise DocumentError(
                    "Это не документ Word (DOCX): нет word/document.xml", "template_invalid", 422
                )
            if any(i.flag_bits & 0x1 for i in infos):
                raise DocumentError("Шаблон зашифрован — снимите пароль", "template_invalid", 422)
            if sum(i.file_size for i in infos) > MAX_TEMPLATE_UNPACKED:
                raise DocumentError(
                    "Шаблон слишком большой в распакованном виде", "template_invalid", 413
                )
            if any(n.lower().endswith(".bin") and "vbaproject" in n.lower() for n in names):
                raise DocumentError(
                    "Шаблон с макросами не принимается — сохраните как DOCX",
                    "template_invalid",
                    422,
                )
    except zipfile.BadZipFile as e:
        raise DocumentError("Это не документ Word (DOCX)", "template_invalid", 422) from e
    with tempfile.TemporaryDirectory(prefix="grc-tpl-") as tmp:
        path = Path(tmp) / "template.docx"
        path.write_bytes(data)
        try:
            used = render.template_variables(path)
        except render.RenderError as e:
            raise DocumentError(
                str(e).replace("template.docx", name), "template_invalid", 422
            ) from e
        except Exception as e:  # повреждённый DOCX: python-docx бросает разное
            raise DocumentError(
                f"Шаблон не читается как DOCX: {type(e).__name__}", "template_invalid", 422
            ) from e
    unknown = sorted(used - allowed_names())
    if unknown:
        raise DocumentError(
            "В шаблоне неизвестные поля: "
            + ", ".join(unknown[:10])
            + ". Доступные разделы перечислены в docs/document-templates.md",
            "template_invalid",
            422,
        )
    return sorted(used)


def upload_template(
    session: Session,
    doc: catalog.DocType,
    data: bytes,
    name: str,
    user: User,
    comment: str | None = None,
) -> DocumentTemplate:
    """Свой шаблон документа становится действующим; прежний — в истории."""
    variables = check_template(data, name)
    sha = put_file(data, custom_dir())
    now = utcnow()
    prev = active_custom(session, doc.code)
    if prev is not None:
        prev.active = False
        prev.deactivated_at = now
        prev.deactivated_by_name = user.display_name
        session.flush()
    row = DocumentTemplate(
        doc_type=doc.code,
        name=name,
        sha256=sha,
        size=len(data),
        variables=variables,
        active=True,
        comment=comment,
        uploaded_at=now,
        uploaded_by=user.id,
        uploaded_by_name=user.display_name,
    )
    session.add(row)
    session.flush()
    return row


def reset_template(session: Session, doc: catalog.DocType, user: User) -> DocumentTemplate | None:
    """Вернуть встроенный шаблон; возвращает снятый свой шаблон (или None)."""
    prev = active_custom(session, doc.code)
    if prev is None:
        return None
    prev.active = False
    prev.deactivated_at = utcnow()
    prev.deactivated_by_name = user.display_name
    session.flush()
    return prev


# ---------- Согласование (задача 3.3) ----------


def _move(
    session: Session,
    d: GeneratedDocument,
    action: str,
    to: str,
    user: User | None,
    comment: str | None = None,
) -> DocumentReview:
    ev = DocumentReview(
        document_id=d.id,
        action=action,
        from_status=d.status,
        to_status=to,
        comment=comment,
        actor_id=user.id if user else None,
        actor_name=user.display_name if user else None,
        at=utcnow(),
    )
    d.status = to
    session.add(ev)
    session.flush()
    return ev


def reviews(session: Session, doc_id: Any) -> list[DocumentReview]:
    return list(
        session.scalars(
            select(DocumentReview)
            .where(DocumentReview.document_id == doc_id)
            .order_by(DocumentReview.at, DocumentReview.id)
        )
    )


def _ensure_latest(session: Session, d: GeneratedDocument, what: str) -> None:
    last = latest(session, d.object_id, d.doc_type)
    if last is not None and last.id != d.id:
        raise DocumentError(
            f"{what} можно только последнюю версию — есть версия {last.version}",
            "not_latest",
        )


def _clean(comment: str | None) -> str | None:
    return (comment or "").strip()[:2000] or None


def submit(
    session: Session, d: GeneratedDocument, user: User, comment: str | None = None
) -> DocumentReview:
    """Проект → на согласовании."""
    if d.status != "draft":
        raise DocumentError("На согласование отправляется только проект", "bad_status")
    _ensure_latest(session, d, "Отправить на согласование")
    d.submitted_at = utcnow()
    d.submitted_by = user.id
    d.submitted_by_name = user.display_name
    return _move(session, d, "submit", "review", user, _clean(comment))


def return_to_draft(
    session: Session, d: GeneratedDocument, user: User, comment: str | None
) -> DocumentReview:
    """На согласовании → проект (вернуть на доработку или отозвать); причина обязательна."""
    if d.status != "review":
        raise DocumentError("Вернуть можно только документ на согласовании", "bad_status")
    reason = _clean(comment)
    if not reason:
        raise DocumentError("Укажите, что нужно доработать", "comment_required", 422)
    return _move(session, d, "return", "draft", user, reason)


def approval_blockers(d: GeneratedDocument, user: User) -> str | None:
    """Почему этот пользователь не может утвердить версию (самоутверждение)."""
    if d.created_by is not None and d.created_by == user.id:
        return "Вы сформировали эту версию — утверждает другой сотрудник"
    if d.submitted_by is not None and d.submitted_by == user.id:
        return "Вы отправили эту версию на согласование — утверждает другой сотрудник"
    return None


def _template_for(session: Session, d: GeneratedDocument, doc: catalog.DocType) -> Path:
    """Тот же шаблон, по которому собрана версия; иначе — ошибка."""
    if d.template_id is not None:
        tpl = session.get(DocumentTemplate, d.template_id)
        path = custom_dir() / (tpl.sha256 if tpl else d.template_sha256)
    else:
        path = builtin_path(doc)
    if not path.is_file() or catalog.file_sha256(path) != d.template_sha256:
        raise DocumentError(
            "Шаблон, по которому собрана версия, с тех пор изменился — сформируйте новую "
            "версию и отправьте её на согласование",
            "template_changed",
        )
    return path


def _local_date(ts: Any) -> date:
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=UTC)
    return ts.astimezone().date()


def approve(
    session: Session,
    d: GeneratedDocument,
    user: User,
    *,
    comment: str | None = None,
    acknowledge_unverified: bool = False,
    today: date | None = None,
) -> list[GeneratedDocument]:
    """На согласовании → утверждён; возвращает заменённые прежние утверждённые версии.

    Самоутверждение проверяет вызывающий (approval_blockers) — и база (CHECK).
    """
    if d.status != "review":
        raise DocumentError("Утвердить можно только документ на согласовании", "bad_status")
    _ensure_latest(session, d, "Утвердить")
    if d.unverified and not acknowledge_unverified:
        raise DocumentError(
            f"В документе записи справочников, не сверенные методистом ({len(d.unverified)}): "
            "подтвердите, что утверждаете с ними — водяной знак «Проект» останется",
            "unverified_refs",
        )
    doc = get_type(d.doc_type)
    path = _template_for(session, d, doc)
    today = today or date.today()
    reasons = watermark_reasons("approved", d.unverified or [])
    tpl_ctx = fieldmap.fill_placeholders(d.context, doc)
    tpl_ctx["doc"] = doc_meta(
        d.title,
        d.version,
        _local_date(d.created_at),
        "approved",
        approved=today,
        approved_by=user.display_name,
    )
    try:
        docx = render.render(path, tpl_ctx, watermark=bool(reasons), font=d.font)
    except render.RenderError as e:
        raise DocumentError(str(e), "template_error") from e
    pdf_bytes, pdf_error = _pdf(docx)

    now = utcnow()
    replaced = list(
        session.scalars(
            select(GeneratedDocument).where(
                GeneratedDocument.object_id == d.object_id,
                GeneratedDocument.doc_type == d.doc_type,
                GeneratedDocument.status == "approved",
                GeneratedDocument.id != d.id,
            )
        )
    )
    for p in replaced:
        p.superseded_at = now
        _move(session, p, "supersede", "superseded", user, f"Утверждена версия {d.version}")

    directory = get_settings().documents_dir
    d.draft_docx_sha256 = d.docx_sha256
    d.draft_pdf_sha256 = d.pdf_sha256
    d.docx_sha256 = put_file(docx, directory)
    d.docx_size = len(docx)
    d.pdf_sha256 = put_file(pdf_bytes, directory) if pdf_bytes else None
    d.pdf_size = len(pdf_bytes) if pdf_bytes else None
    d.pdf_error = pdf_error
    d.watermark = bool(reasons)
    d.watermark_reasons = reasons
    d.approved_at = now
    d.approved_by = user.id
    d.approved_by_name = user.display_name
    d.approval_comment = _clean(comment)
    d.unverified_acknowledged = bool(d.unverified)
    _move(session, d, "approve", "approved", user, d.approval_comment)
    return replaced


def read_file(sha: str) -> bytes:
    return (get_settings().documents_dir / sha).read_bytes()
