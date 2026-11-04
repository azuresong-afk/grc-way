"""Доказательства мер: список, ручные доказательства, отзыв, скачивание файлов (задача 1.10).

- Ручные доказательства: файл (документ, скриншот, конфигурация, протокол),
  интервью, осмотр. Добавляет эксперт (право evidence.upload).
- Файл принимается по белому списку типов с проверкой сигнатуры и размера
  (app/domain/evidence_files.py), хранится в томе под sha256, отдаётся только
  на скачивание: Content-Disposition: attachment, nosniff, CSP sandbox.
- Ручное доказательство не удаляется — его отзывают с причиной; отозванное
  остаётся в истории. Если на него опиралось подтверждение меры, подтверждение
  снимается.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any, Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, ValidationError, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.objects import _editable, get_object_for
from app.api.projects import get_project_for
from app.api.snapshots import SnapshotBrief, _brief, _latest_snapshot
from app.core.config import get_settings
from app.core.rbac import Perm
from app.db.models import (
    AssessedObject,
    Evidence,
    EvidenceFile,
    ObjectMeasure,
    ScannerSnapshot,
    User,
    utcnow,
)
from app.domain import confirmation
from app.domain.evidence_files import EvidenceFileError, clean_name, store

router = APIRouter(tags=["evidence"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Uploader = Annotated[User, Depends(require(Perm.EVIDENCE_UPLOAD))]

ManualKind = Literal["file", "interview", "inspection"]
FileCategory = Literal["document", "screenshot", "config", "protocol", "other"]
_CHUNK = 1 << 20


# ---------- Схемы ----------


class FileOut(BaseModel):
    id: uuid.UUID
    name: str
    ext: str
    mime: str
    size: int
    sha256: str


class EvidenceOut(BaseModel):
    id: uuid.UUID
    kind: str
    status: str | None
    summary: str
    data: dict[str, Any]
    snapshot: SnapshotBrief | None
    file: FileOut | None = None
    created_at: datetime
    created_by_name: str | None
    withdrawn_at: datetime | None = None
    withdrawn_by_name: str | None = None
    withdraw_reason: str | None = None
    # Опирается ли на него текущее подтверждение меры.
    in_confirmation: bool = False


class ManualIn(BaseModel):
    kind: ManualKind
    summary: str = Field(min_length=1, max_length=1000, description="Что подтверждает")
    held_on: date | None = None
    participants: str | None = Field(default=None, max_length=1000)
    place: str | None = Field(default=None, max_length=300)
    details: str | None = Field(default=None, max_length=8000)
    category: FileCategory | None = None

    @model_validator(mode="after")
    def _rules(self) -> ManualIn:
        self.summary = self.summary.strip()
        if not self.summary:
            raise ValueError("Опишите, что подтверждает доказательство")
        for f in ("participants", "place", "details"):
            v = getattr(self, f)
            setattr(self, f, (v or "").strip() or None)
        if self.kind in ("interview", "inspection") and self.held_on is None:
            raise ValueError("Укажите дату интервью или осмотра")
        if self.kind == "interview" and not self.participants:
            raise ValueError("Укажите, кого опрашивали")
        if self.held_on and self.held_on > date.today():
            raise ValueError("Дата не может быть в будущем")
        if self.kind == "file" and self.category is None:
            self.category = "document"
        if self.kind != "file":
            self.category = None
        return self


class WithdrawIn(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


# ---------- Общие функции ----------


def _get_measure(session: Session, mid: uuid.UUID, user: User) -> tuple[ObjectMeasure, Any]:
    m = session.get(ObjectMeasure, mid)
    if m is None:
        raise HTTPException(404, detail="Мера не найдена")
    try:
        obj = get_object_for(session, m.object_id, user)
    except HTTPException as e:
        raise HTTPException(404, detail="Мера не найдена") from e
    return m, obj


def _get_evidence(session: Session, eid: uuid.UUID, user: User) -> Evidence:
    e = session.get(Evidence, eid)
    if e is None:
        raise HTTPException(404, detail="Доказательство не найдено")
    try:
        get_object_for(session, e.object_id, user)
    except HTTPException as err:
        raise HTTPException(404, detail="Доказательство не найдено") from err
    return e


def _file_out(f: EvidenceFile) -> FileOut:
    return FileOut(id=f.id, name=f.name, ext=f.ext, mime=f.mime, size=f.size, sha256=f.sha256)


def evidence_out(session: Session, rows: list[Evidence], obj: AssessedObject) -> list[EvidenceOut]:
    latest = _latest_snapshot(session, obj)
    current = latest.id if latest else None
    snap_ids = {e.snapshot_id for e in rows if e.snapshot_id}
    snap_q = select(ScannerSnapshot).where(ScannerSnapshot.id.in_(snap_ids))
    snaps = {s.id: s for s in session.scalars(snap_q)} if snap_ids else {}
    file_ids = {e.file_id for e in rows if e.file_id}
    file_q = select(EvidenceFile).where(EvidenceFile.id.in_(file_ids))
    files = {f.id: f for f in session.scalars(file_q)} if file_ids else {}
    confirmed: set[str] = set()
    for mid in {e.object_measure_id for e in rows}:
        m = session.get(ObjectMeasure, mid)
        if m is not None and m.confirmed_at is not None:
            confirmed |= set(m.confirmed_evidence or [])
    return [
        EvidenceOut(
            id=e.id,
            kind=e.kind,
            status=e.status,
            summary=e.summary,
            data=e.data or {},
            snapshot=_brief(snaps[e.snapshot_id], current) if e.snapshot_id in snaps else None,
            file=_file_out(files[e.file_id]) if e.file_id in files else None,
            created_at=e.created_at,
            created_by_name=e.created_by_name,
            withdrawn_at=e.withdrawn_at,
            withdrawn_by_name=e.withdrawn_by_name,
            withdraw_reason=e.withdraw_reason,
            in_confirmation=str(e.id) in confirmed,
        )
        for e in rows
    ]


def confirmation_basis(
    session: Session, m: ObjectMeasure, obj: AssessedObject
) -> confirmation.Basis:
    """Действующие ручные доказательства меры и её доказательство из текущего снимка."""
    manual = session.scalars(
        select(Evidence.id).where(
            Evidence.object_measure_id == m.id,
            Evidence.kind.in_(confirmation.MANUAL_KINDS),
            Evidence.withdrawn_at.is_(None),
        )
    ).all()
    latest = _latest_snapshot(session, obj)
    scanner_id = None
    if latest is not None and m.auto_snapshot_id == latest.id:
        scanner_id = session.scalar(
            select(Evidence.id).where(
                Evidence.object_measure_id == m.id,
                Evidence.snapshot_id == latest.id,
                Evidence.kind == "scanner",
            )
        )
    return confirmation.Basis(
        tuple(str(i) for i in manual), str(scanner_id) if scanner_id else None
    )


def _validation_detail(e: ValidationError) -> str:
    err = e.errors()[0]
    msg = str(err.get("msg", "")).removeprefix("Value error, ")
    field = ".".join(str(x) for x in err.get("loc", ()))
    return msg if err.get("type") == "value_error" else f"Поле {field}: {msg}"


# ---------- Эндпоинты ----------


@router.get("/object-measures/{measure_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(measure_id: uuid.UUID, user: Viewer, session: DbSession) -> list[EvidenceOut]:
    m, obj = _get_measure(session, measure_id, user)
    rows = list(
        session.scalars(
            select(Evidence)
            .where(Evidence.object_measure_id == m.id)
            .order_by(Evidence.created_at.desc())
        )
    )
    return evidence_out(session, rows, obj)


@router.get("/evidence/{evidence_id}", response_model=EvidenceOut)
def get_evidence(evidence_id: uuid.UUID, user: Viewer, session: DbSession) -> EvidenceOut:
    e = _get_evidence(session, evidence_id, user)
    obj = session.get(AssessedObject, e.object_id)
    assert obj is not None  # noqa: S101 — внешний ключ
    return evidence_out(session, [e], obj)[0]


@router.post("/object-measures/{measure_id}/evidence", response_model=EvidenceOut, status_code=201)
async def add_evidence(
    measure_id: uuid.UUID, request: Request, user: Uploader, session: DbSession
) -> EvidenceOut:
    """Ручное доказательство: JSON (интервью, осмотр) или multipart с полем file (файл)."""
    ctype = request.headers.get("content-type", "")
    upload: UploadFile | None = None
    try:
        if ctype.startswith("multipart/form-data"):
            form = await request.form(max_files=1, max_fields=20)
            raw: dict[str, Any] = {k: v for k, v in form.items() if isinstance(v, str) and v != ""}
            raw.setdefault("kind", "file")
            got = form.get("file")
            upload = got if isinstance(got, UploadFile) else None
        else:
            raw = await request.json()
            if not isinstance(raw, dict):
                raise HTTPException(422, detail="Ожидается объект JSON")
        body = ManualIn.model_validate(raw)
    except ValidationError as e:
        raise HTTPException(422, detail=_validation_detail(e)) from e
    except ValueError as e:
        raise HTTPException(422, detail="Тело запроса не разобрано") from e
    if body.kind == "file" and upload is None:
        raise HTTPException(422, detail="Приложите файл (поле file, multipart/form-data)")
    if body.kind != "file" and upload is not None:
        raise HTTPException(422, detail="Файл прикладывается как доказательство вида «файл»")
    return await run_in_threadpool(
        _add_evidence, measure_id, body, upload, user, session, client_ip(request)
    )


def _add_evidence(
    measure_id: uuid.UUID,
    body: ManualIn,
    upload: UploadFile | None,
    user: User,
    session: Session,
    ip: str | None,
) -> EvidenceOut:
    m, obj = _get_measure(session, measure_id, user)
    _editable(session, obj)
    now = utcnow()
    data: dict[str, Any] = {
        k: v
        for k, v in {
            "held_on": body.held_on.isoformat() if body.held_on else None,
            "participants": body.participants,
            "place": body.place,
            "details": body.details,
            "category": body.category,
        }.items()
        if v is not None
    }
    file_row: EvidenceFile | None = None
    if upload is not None:
        settings = get_settings()
        name = clean_name(upload.filename or "")

        def chunks():
            while chunk := upload.file.read(_CHUNK):
                yield chunk

        try:
            stored = store(
                chunks(), name, settings.evidence_dir, settings.evidence_max_mb * 1024 * 1024
            )
        except EvidenceFileError as e:
            audit.record_now(
                session,
                action="evidence.rejected",
                actor=user,
                entity="object_measure",
                entity_id=m.id,
                project_id=obj.project_id,
                result="error",
                ip=ip,
                details={"name": name, "code": e.code, "reason": str(e)},
            )
            status = 413 if e.code == "file_too_large" else 422
            raise HTTPException(status, detail=str(e), headers={"X-Error-Code": e.code}) from e
        file_row = EvidenceFile(
            project_id=obj.project_id,
            sha256=stored.sha256,
            name=name,
            ext=stored.ext,
            mime=stored.mime,
            size=stored.size,
            created_at=now,
            created_by=user.id,
            created_by_name=user.display_name,
        )
        session.add(file_row)
        session.flush()
    e = Evidence(
        object_measure_id=m.id,
        object_id=obj.id,
        project_id=obj.project_id,
        measure_id=m.measure_id,
        kind=body.kind,
        status=None,
        summary=body.summary,
        data=data,
        file_id=file_row.id if file_row else None,
        created_at=now,
        created_by=user.id,
        created_by_name=user.display_name,
    )
    session.add(e)
    m.updated_at = now
    session.flush()
    details: dict[str, Any] = {
        "object_id": str(obj.id),
        "measure_id": m.measure_id,
        "kind": body.kind,
    }
    if file_row is not None:
        details["file"] = {"name": file_row.name, "sha256": file_row.sha256, "size": file_row.size}
    audit.record(
        session,
        action="evidence.add",
        actor=user,
        entity="evidence",
        entity_id=e.id,
        project_id=obj.project_id,
        ip=ip,
        details=details,
    )
    session.commit()
    return evidence_out(session, [e], obj)[0]


@router.post("/evidence/{evidence_id}/withdraw", response_model=EvidenceOut)
def withdraw_evidence(
    evidence_id: uuid.UUID,
    body: WithdrawIn,
    request: Request,
    user: Uploader,
    session: DbSession,
) -> EvidenceOut:
    e = _get_evidence(session, evidence_id, user)
    obj = session.get(AssessedObject, e.object_id)
    assert obj is not None  # noqa: S101 — внешний ключ
    _editable(session, obj)
    if e.kind == "scanner":
        raise HTTPException(409, detail="Результат «Сканера» не отзывается: снимок неизменяем")
    if e.withdrawn_at is not None:
        raise HTTPException(409, detail="Доказательство уже отозвано")
    reason = body.reason.strip()
    if not reason:
        raise HTTPException(422, detail="Укажите причину отзыва")
    now = utcnow()
    e.withdrawn_at = now
    e.withdrawn_by_name = user.display_name
    e.withdraw_reason = reason
    m = session.get(ObjectMeasure, e.object_measure_id)
    assert m is not None  # noqa: S101 — внешний ключ
    reset = str(e.id) in (m.confirmed_evidence or []) and confirmation.clear(m)
    m.updated_at = now
    audit.record(
        session,
        action="evidence.withdraw",
        actor=user,
        entity="evidence",
        entity_id=e.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "object_id": str(obj.id),
            "measure_id": e.measure_id,
            "kind": e.kind,
            "reason": reason,
            "confirmation_reset": reset,
        },
    )
    session.commit()
    return evidence_out(session, [e], obj)[0]


@router.get("/files/{file_id}")
def download_file(
    file_id: uuid.UUID, request: Request, user: Viewer, session: DbSession
) -> FileResponse:
    f = session.get(EvidenceFile, file_id)
    if f is None:
        raise HTTPException(404, detail="Файл не найден")
    try:
        get_project_for(session, f.project_id, user)
    except HTTPException as err:
        raise HTTPException(404, detail="Файл не найден") from err
    path = get_settings().evidence_dir / f.sha256
    if not path.is_file():
        raise HTTPException(
            410,
            detail="Файл есть в базе, но отсутствует в хранилище — восстановите том из копии",
            headers={"X-Error-Code": "file_missing"},
        )
    audit.record_now(
        session,
        action="files.download",
        actor=user,
        entity="file",
        entity_id=f.id,
        project_id=f.project_id,
        ip=client_ip(request),
        details={"name": f.name, "sha256": f.sha256},
    )
    ascii_name = f.name.encode("ascii", "replace").decode().replace('"', "_").replace("?", "_")
    return FileResponse(
        path,
        media_type=f.mime,
        headers={
            "Content-Disposition": (
                f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(f.name)}"
            ),
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "private, no-store",
        },
    )
