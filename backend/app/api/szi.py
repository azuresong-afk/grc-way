"""СЗИ (задача 2.5): реестр сертифицированных СЗИ и СЗИ объектов.

- Реестр (`/szi-registry…`) — общий справочник, как БДУ: загрузка CSV/XLSX →
  сравнение → применение (право `refs.manage`), просмотр — всем вошедшим.
- СЗИ объекта (`/objects/{id}/szi`, `/object-szi/{id}`) — часть описания объекта
  (право `objects.edit`): наименование, вид, сертификат, какие меры закрывает.
  Срок действия и состояние сертификата берутся из реестра, если номер в нём
  есть, иначе — введённые вручную. Предупреждения: истёк, истекает в ближайшие
  `GRC_SZI_EXPIRY_DAYS` дней, приостановлен или прекращён, исключён из реестра,
  нет в реестре, срок не указан.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from app import audit
from app.api.deps import CurrentUser, DbSession, client_ip, require
from app.api.objects import _editable, get_object_for
from app.core.config import get_settings
from app.core.rbac import Perm
from app.db.models import AssessedObject, ObjectMeasure, ObjectSzi, SziCert, SziImport, User, utcnow
from app.domain import szi
from app.domain.evidence_files import EvidenceFileError, clean_name, extension, store
from app.integrations.bdu.xlsx import XlsxError

router = APIRouter(tags=["szi"])
RegistryEditor = Annotated[User, Depends(require(Perm.REFS_MANAGE))]
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Editor = Annotated[User, Depends(require(Perm.OBJECTS_EDIT))]
_CHUNK = 1 << 20


# ---------- Схемы: реестр ----------


class RegistryStatus(BaseModel):
    version: date | None
    version_source: str | None
    applied_at: datetime | None
    applied_by_name: str | None
    active: int
    withdrawn: int
    # Действующие записи реестра, срок которых уже истёк (для справки).
    expired: int
    # Действующие записи, срок которых истекает в ближайшие expiry_days дней.
    expiring: int
    pending_id: uuid.UUID | None
    expiry_days: int


class ImportBrief(BaseModel):
    id: uuid.UUID
    file_name: str
    file_size: int
    file_ext: str
    export_version: date | None
    version_source: str
    version_source_title: str
    status: str
    summary: dict[str, Any]
    warnings: list[dict[str, str]]
    created_at: datetime
    created_by_name: str | None
    applied_at: datetime | None
    applied_by_name: str | None
    applied: dict[str, Any] | None


class ImportOut(ImportBrief):
    items: list[dict[str, Any]]
    field_titles: dict[str, str]


class ApplyIn(BaseModel):
    ack_warnings: bool = False


class CertBrief(BaseModel):
    cert_number: str
    name: str
    registered_on: date | None
    valid_to: date | None
    valid_to_raw: str | None
    trust_level: int | None
    profiles: list[str]
    cert_status: str
    support_until: date | None
    applicant: str | None
    changed_version: date | None
    withdrawn_at: datetime | None


class CertOut(CertBrief):
    requirements: str | None
    scheme: str | None
    lab: str | None
    cert_body: str | None
    applicant_details: str | None
    support_raw: str | None
    note: str | None
    first_version: date | None


# ---------- Схемы: СЗИ объекта ----------


def _strip(v: Any) -> Any:
    if isinstance(v, str):
        v = v.strip()
        return v or None
    return v


class SziIn(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    kind: str = "other"
    vendor: str | None = Field(default=None, max_length=300)
    version: str | None = Field(default=None, max_length=100)
    cert_number: str | None = Field(default=None, max_length=40)
    cert_valid_to: date | None = None
    trust_level: int | None = Field(default=None, ge=1, le=6)
    protection_class: str | None = Field(default=None, max_length=200)
    placement: str | None = Field(default=None, max_length=2000)
    measure_ids: list[str] = Field(default_factory=list, max_length=200)
    comment: str | None = Field(default=None, max_length=2000)

    _clean = field_validator(
        "name", "vendor", "version", "cert_number", "protection_class", "placement", "comment",
        mode="before",
    )(_strip)  # fmt: skip

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in szi.KINDS:
            raise ValueError("неизвестный вид СЗИ")
        return v


class SziPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=300)
    kind: str | None = None
    vendor: str | None = Field(default=None, max_length=300)
    version: str | None = Field(default=None, max_length=100)
    cert_number: str | None = Field(default=None, max_length=40)
    cert_valid_to: date | None = None
    trust_level: int | None = Field(default=None, ge=1, le=6)
    protection_class: str | None = Field(default=None, max_length=200)
    placement: str | None = Field(default=None, max_length=2000)
    measure_ids: list[str] | None = Field(default=None, max_length=200)
    comment: str | None = Field(default=None, max_length=2000)

    _clean = field_validator(
        "name", "vendor", "version", "cert_number", "protection_class", "placement", "comment",
        mode="before",
    )(_strip)  # fmt: skip

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str | None) -> str | None:
        if v is not None and v not in szi.KINDS:
            raise ValueError("неизвестный вид СЗИ")
        return v


class MeasureLink(BaseModel):
    measure_id: str
    title: str | None
    # in_set — мера в наборе объекта; excluded — исключена при адаптации;
    # missing — меры нет в наборе (набор пересобран или мера убрана).
    state: str


class RegistryRef(BaseModel):
    cert_number: str
    name: str
    valid_to: date | None
    trust_level: int | None
    profiles: list[str]
    cert_status: str
    support_until: date | None
    withdrawn: bool


class SziOut(BaseModel):
    id: uuid.UUID
    object_id: uuid.UUID
    name: str
    kind: str
    kind_title: str
    vendor: str | None
    version: str | None
    cert_number: str | None
    cert_valid_to: date | None
    trust_level: int | None
    protection_class: str | None
    placement: str | None
    measure_ids: list[str]
    measures: list[MeasureLink]
    comment: str | None
    # Состояние сертификата с учётом реестра.
    state: str
    state_title: str
    level: str
    valid_to: date | None
    valid_to_source: str | None
    days_left: int | None
    registry_match: str
    effective_trust_level: int | None
    support_ended: bool
    notes: list[str]
    registry: RegistryRef | None
    created_at: datetime
    created_by_name: str | None
    updated_at: datetime
    updated_by_name: str | None


class SziCounts(BaseModel):
    total: int
    # Сертификат недействителен: истёк, приостановлен/прекращён, исключён из реестра.
    bad: int
    expiring: int
    # Нет в реестре или срок не указан.
    check: int
    uncertified: int


class SziListOut(BaseModel):
    items: list[SziOut]
    counts: SziCounts
    expiry_days: int
    registry_version: date | None
    registry_loaded: bool
    kinds: dict[str, str]
    states: dict[str, list[str]]


# ---------- Реестр: загрузки ----------


def _brief(r: SziImport) -> ImportBrief:
    return ImportBrief(
        id=r.id,
        file_name=r.file_name,
        file_size=r.file_size,
        file_ext=r.file_ext,
        export_version=r.export_version,
        version_source=r.version_source,
        version_source_title=szi.VERSION_SOURCES.get(r.version_source, r.version_source),
        status=r.status,
        summary=r.summary,
        warnings=r.warnings,
        created_at=r.created_at,
        created_by_name=r.created_by_name,
        applied_at=r.applied_at,
        applied_by_name=r.applied_by_name,
        applied=r.applied,
    )


def _out(r: SziImport) -> ImportOut:
    return ImportOut(**_brief(r).model_dump(), items=r.items, field_titles=szi.FIELD_TITLES)


@router.get("/szi-registry/status", response_model=RegistryStatus)
def registry_status(_: CurrentUser, session: DbSession) -> RegistryStatus:
    cur = szi.current_version(session)
    counts = dict(
        session.execute(
            select(SziCert.withdrawn_at.is_(None), func.count()).group_by(
                SziCert.withdrawn_at.is_(None)
            )
        ).all()
    )
    today = date.today()
    days = get_settings().szi_expiry_days
    active = SziCert.withdrawn_at.is_(None)
    expired = session.scalar(select(func.count()).where(active, SziCert.valid_to < today))
    expiring = session.scalar(
        select(func.count()).where(
            active,
            SziCert.valid_to >= today,
            SziCert.valid_to <= today + timedelta(days=days),
        )
    )
    pending = session.scalar(
        select(SziImport.id)
        .where(SziImport.status == "pending")
        .order_by(SziImport.created_at.desc())
        .limit(1)
    )
    return RegistryStatus(
        version=cur.export_version if cur else None,
        version_source=cur.version_source if cur else None,
        applied_at=cur.applied_at if cur else None,
        applied_by_name=cur.applied_by_name if cur else None,
        active=counts.get(True, 0),
        withdrawn=counts.get(False, 0),
        expired=expired or 0,
        expiring=expiring or 0,
        pending_id=pending,
        expiry_days=days,
    )


def _reject(session: Session, user: User, ip: str | None, name: str, code: str, text: str):
    audit.record_now(
        session,
        action="szi.import.rejected",
        actor=user,
        result="error",
        ip=ip,
        details={"name": name, "code": code, "reason": text},
    )


@router.post("/szi-registry/imports", response_model=ImportOut, status_code=201)
async def upload(request: Request, user: RegistryEditor, session: DbSession) -> ImportOut:
    """Реестр СЗИ (multipart: file — .xlsx или .csv; export_version — дата реестра
    ГГГГ-ММ-ДД, если её нет в файле)."""
    if not request.headers.get("content-type", "").startswith("multipart/form-data"):
        raise HTTPException(422, detail="Приложите файл реестра (multipart/form-data, поле file)")
    form = await request.form(max_files=1, max_fields=10)
    got = form.get("file")
    if not isinstance(got, UploadFile):
        raise HTTPException(422, detail="Приложите файл реестра (поле file)")
    raw_version = form.get("export_version")
    version: date | None = None
    if isinstance(raw_version, str) and raw_version.strip():
        try:
            version = date.fromisoformat(raw_version.strip())
        except ValueError as e:
            raise HTTPException(422, detail="Дата реестра — в формате ГГГГ-ММ-ДД") from e
    return await run_in_threadpool(_upload, got, version, user, session, client_ip(request))


def _upload(
    upload: UploadFile, version: date | None, user: User, session: Session, ip: str | None
) -> ImportOut:
    settings = get_settings()
    name = clean_name(upload.filename or "")
    ext = extension(name)
    if ext not in ("csv", "xlsx"):
        _reject(session, user, ip, name, "file_type", "не CSV и не XLSX")
        raise HTTPException(422, detail="Нужен файл реестра СЗИ в формате XLSX или CSV")

    def chunks():
        while chunk := upload.file.read(_CHUNK):
            yield chunk

    try:
        stored = store(chunks(), name, settings.szi_dir, settings.szi_max_mb * 1024 * 1024)
    except EvidenceFileError as e:
        _reject(session, user, ip, name, e.code, str(e))
        code = 413 if e.code == "file_too_large" else 422
        raise HTTPException(code, detail=str(e), headers={"X-Error-Code": e.code}) from e
    try:
        parsed = szi.parse_file(stored.path, ext)
    except (szi.SziFormatError, XlsxError) as e:
        _reject(session, user, ip, name, "szi_format", str(e))
        raise HTTPException(422, detail=str(e), headers={"X-Error-Code": "szi_format"}) from e
    if version is not None:
        parsed.version, parsed.version_source = version, "user"
    diff = szi.compute_diff(session, parsed, file_sha256=stored.sha256)
    session.execute(
        update(SziImport).where(SziImport.status == "pending").values(status="superseded")
    )
    row = SziImport(
        file_name=name,
        file_sha256=stored.sha256,
        file_size=stored.size,
        file_ext=ext,
        export_version=parsed.version,
        version_source=parsed.version_source,
        status="pending",
        summary=diff["summary"],
        items=diff["items"],
        warnings=diff["warnings"],
        fingerprint=diff["fingerprint"],
        created_by=user.id,
        created_by_name=user.display_name,
    )
    session.add(row)
    session.flush()
    if not diff["summary"]["has_changes"] and not diff["warnings"]:
        row.status = "applied"
        row.applied_at, row.applied_by, row.applied_by_name = utcnow(), user.id, user.display_name
        row.applied = {"no_changes": True, **szi.ApplyResult().as_dict()}
    s = diff["summary"]
    audit.record(
        session,
        action="szi.import.diff",
        actor=user,
        entity="szi_import",
        entity_id=row.id,
        ip=ip,
        details={
            "file": name,
            "sha256": stored.sha256,
            "version": parsed.version.isoformat() if parsed.version else None,
            **{k: s[k] for k in ("in_file", "add", "update", "restore", "withdraw", "validity")},
            "warnings": [w["code"] for w in diff["warnings"]],
        },
    )
    session.commit()
    return _out(row)


@router.get("/szi-registry/imports", response_model=list[ImportBrief])
def list_imports(
    _: CurrentUser,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[ImportBrief]:
    q = select(SziImport).order_by(SziImport.created_at.desc()).limit(limit)
    return [_brief(r) for r in session.scalars(q)]


def _get_import(session: Session, import_id: uuid.UUID) -> SziImport:
    row = session.get(SziImport, import_id)
    if row is None:
        raise HTTPException(404, detail="Загрузка не найдена")
    return row


@router.get("/szi-registry/imports/{import_id}", response_model=ImportOut)
def get_import(import_id: uuid.UUID, _: CurrentUser, session: DbSession) -> ImportOut:
    return _out(_get_import(session, import_id))


@router.post("/szi-registry/imports/{import_id}/apply", response_model=ImportOut)
async def apply_import(
    import_id: uuid.UUID, body: ApplyIn, request: Request, user: RegistryEditor, session: DbSession
) -> ImportOut:
    return await run_in_threadpool(_apply, import_id, body, user, session, client_ip(request))


def _apply(
    import_id: uuid.UUID, body: ApplyIn, user: User, session: Session, ip: str | None
) -> ImportOut:
    row = _get_import(session, import_id)
    if row.status == "applied":
        raise HTTPException(409, detail="Этот реестр уже применён")
    if row.status != "pending":
        raise HTTPException(409, detail="Есть более новая загрузка реестра. Откройте её")
    if row.warnings and not body.ack_warnings:
        raise HTTPException(
            409,
            detail="Подтвердите, что предупреждения сравнения прочитаны",
            headers={"X-Error-Code": "ack_required"},
        )
    path = get_settings().szi_dir / row.file_sha256
    if not path.exists():
        raise HTTPException(410, detail="Файл реестра не найден в хранилище. Загрузите его снова")
    parsed = szi.parse_file(path, row.file_ext)
    current = szi.compute_diff(session, parsed)
    if current["fingerprint"] != row.fingerprint:
        raise HTTPException(
            409, detail="Реестр СЗИ изменился после сравнения. Загрузите файл заново"
        )
    res = szi.apply(session, parsed, row, version=row.export_version)
    row.status = "applied"
    row.applied_at = utcnow()
    row.applied_by, row.applied_by_name = user.id, user.display_name
    row.applied = res.as_dict()
    audit.record(
        session,
        action="szi.import.apply",
        actor=user,
        entity="szi_import",
        entity_id=row.id,
        ip=ip,
        details={
            "version": row.export_version.isoformat() if row.export_version else None,
            "ack_warnings": [w["code"] for w in row.warnings],
            **res.as_dict(),
        },
    )
    session.commit()
    return _out(row)


# ---------- Реестр: просмотр ----------


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("/szi-registry", response_model=list[CertBrief])
def list_certs(
    _: CurrentUser,
    session: DbSession,
    response: Response,
    q: Annotated[str | None, Query(max_length=200)] = None,
    validity: Annotated[str | None, Query(pattern="^(valid|expiring|expired)$")] = None,
    withdrawn: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[CertBrief]:
    stmt = select(SziCert)
    stmt = stmt.where(
        SziCert.withdrawn_at.is_not(None) if withdrawn else SziCert.withdrawn_at.is_(None)
    )
    if q and q.strip():
        s = q.strip()
        conds = [
            SziCert.name.ilike(_like(s), escape="\\"),
            SziCert.applicant.ilike(_like(s), escape="\\"),
            SziCert.requirements.ilike(_like(s), escape="\\"),
        ]
        if (n := szi.cert_number(s)) is not None:
            conds.append(SziCert.cert_number == n)
        stmt = stmt.where(or_(*conds))
    today = date.today()
    soon = today + timedelta(days=get_settings().szi_expiry_days)
    if validity == "expired":
        stmt = stmt.where(SziCert.valid_to < today)
    elif validity == "expiring":
        stmt = stmt.where(SziCert.valid_to >= today, SziCert.valid_to <= soon)
    elif validity == "valid":
        stmt = stmt.where(SziCert.valid_to > soon)
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    response.headers["X-Total-Count"] = str(total)
    order = [SziCert.valid_to] if validity in ("expiring", "expired") else []
    rows = session.scalars(
        stmt.order_by(*order, SziCert.registered_on.desc(), SziCert.cert_number.desc())
        .limit(limit)
        .offset(offset)
    )
    return [CertBrief.model_validate(r, from_attributes=True) for r in rows]


@router.get("/szi-registry/{number}", response_model=CertOut)
def get_cert(number: str, _: CurrentUser, session: DbSession) -> CertOut:
    key = szi.cert_number(number)
    row = session.get(SziCert, key) if key else None
    if row is None:
        raise HTTPException(404, detail="Сертификат не найден в реестре")
    return CertOut.model_validate(row, from_attributes=True)


# ---------- СЗИ объекта ----------


def _measure_index(session: Session, obj: AssessedObject) -> dict[str, ObjectMeasure]:
    return {
        m.measure_id: m
        for m in session.scalars(select(ObjectMeasure).where(ObjectMeasure.object_id == obj.id))
    }


def szi_states(
    session: Session, rows: list[ObjectSzi], *, today: date | None = None
) -> list[szi.CertState]:
    """Состояние сертификата каждого СЗИ (для вкладки, меры и сводки)."""
    today = today or date.today()
    days = get_settings().szi_expiry_days
    index = szi.registry_index(session, (r.cert_number for r in rows))
    loaded = bool(index) or (bool(rows) and szi.registry_loaded(session))
    return [
        szi.cert_state(
            number=r.cert_number,
            manual_valid_to=r.cert_valid_to,
            manual_trust=r.trust_level,
            entry=index.get(r.cert_number or ""),
            registry_loaded=loaded,
            today=today,
            expiry_days=days,
        )
        for r in rows
    ]


def count_states(states: list[szi.CertState]) -> SziCounts:
    return SziCounts(
        total=len(states),
        bad=sum(1 for s in states if s.level == "bad"),
        expiring=sum(1 for s in states if s.state == "expiring"),
        check=sum(1 for s in states if s.state in ("not_found", "no_date")),
        uncertified=sum(1 for s in states if s.state == "uncertified"),
    )


def _szi_out(
    r: ObjectSzi, st: szi.CertState, entry: SziCert | None, measures: dict[str, ObjectMeasure]
) -> SziOut:
    links = []
    for mid in r.measure_ids or []:
        m = measures.get(mid)
        if m is None:
            state = "missing"
        elif m.adaptation == "excluded":
            state = "excluded"
        else:
            state = "in_set"
        links.append(MeasureLink(measure_id=mid, title=m.title if m else None, state=state))
    return SziOut(
        id=r.id,
        object_id=r.object_id,
        name=r.name,
        kind=r.kind,
        kind_title=szi.KINDS.get(r.kind, r.kind),
        vendor=r.vendor,
        version=r.version,
        cert_number=r.cert_number,
        cert_valid_to=r.cert_valid_to,
        trust_level=r.trust_level,
        protection_class=r.protection_class,
        placement=r.placement,
        measure_ids=list(r.measure_ids or []),
        measures=links,
        comment=r.comment,
        state=st.state,
        state_title=szi.STATES[st.state][0],
        level=st.level,
        valid_to=st.valid_to,
        valid_to_source=st.valid_to_source,
        days_left=st.days_left,
        registry_match=st.registry,
        effective_trust_level=st.trust_level,
        support_ended=st.support_ended,
        notes=st.notes,
        registry=RegistryRef(
            cert_number=entry.cert_number,
            name=entry.name,
            valid_to=entry.valid_to,
            trust_level=entry.trust_level,
            profiles=list(entry.profiles or []),
            cert_status=entry.cert_status,
            support_until=entry.support_until,
            withdrawn=entry.withdrawn_at is not None,
        )
        if entry
        else None,
        created_at=r.created_at,
        created_by_name=r.created_by_name,
        updated_at=r.updated_at,
        updated_by_name=r.updated_by_name,
    )


_ORDER = {code: i for i, code in enumerate(szi.STATES)}


def _list_out(session: Session, obj: AssessedObject, rows: list[ObjectSzi]) -> list[SziOut]:
    states = szi_states(session, rows)
    index = szi.registry_index(session, (r.cert_number for r in rows))
    measures = _measure_index(session, obj)
    return [
        _szi_out(r, st, index.get(r.cert_number or ""), measures)
        for r, st in zip(rows, states, strict=True)
    ]


def _object_rows(session: Session, obj: AssessedObject) -> list[ObjectSzi]:
    return list(
        session.scalars(
            select(ObjectSzi).where(ObjectSzi.object_id == obj.id).order_by(ObjectSzi.name)
        )
    )


@router.get("/objects/{object_id}/szi", response_model=SziListOut)
def list_object_szi(
    object_id: uuid.UUID,
    user: Viewer,
    session: DbSession,
    measure_id: Annotated[str | None, Query(max_length=32)] = None,
) -> SziListOut:
    """СЗИ объекта; measure_id — только закрывающие эту меру (для шторки меры)."""
    obj = get_object_for(session, object_id, user)
    rows = _object_rows(session, obj)
    if measure_id:
        rows = [r for r in rows if measure_id in (r.measure_ids or [])]
    items = _list_out(session, obj, rows)
    items.sort(key=lambda i: (_ORDER[i.state], i.name.lower()))
    cur = szi.current_version(session)
    states = szi_states(session, rows)
    return SziListOut(
        items=items,
        counts=count_states(states),
        expiry_days=get_settings().szi_expiry_days,
        registry_version=cur.export_version if cur else None,
        registry_loaded=szi.registry_loaded(session),
        kinds=szi.KINDS,
        states={k: list(v) for k, v in szi.STATES.items()},
    )


def _get_szi(session: Session, szi_id: uuid.UUID, user: User) -> tuple[ObjectSzi, AssessedObject]:
    row = session.get(ObjectSzi, szi_id)
    if row is None:
        raise HTTPException(404, detail="СЗИ не найдено")
    try:
        obj = get_object_for(session, row.object_id, user)
    except HTTPException as e:
        raise HTTPException(404, detail="СЗИ не найдено") from e
    return row, obj


def _check_measures(
    session: Session, obj: AssessedObject, ids: list[str], keep: list[str]
) -> list[str]:
    """Коды мер без повторов. Новые должны быть в наборе объекта; уже привязанные,
    которых в наборе больше нет, можно оставить (их видно как «нет в наборе»)."""
    out = list(dict.fromkeys(i.strip() for i in ids if i and i.strip()))
    known = _measure_index(session, obj)
    unknown = [i for i in out if i not in known and i not in keep]
    if unknown:
        raise HTTPException(
            422,
            detail="Мер нет в наборе объекта: "
            + ", ".join(unknown[:10])
            + ("" if known else ". Сначала соберите набор мер"),
        )
    return out


def _cert(raw: str | None) -> str | None:
    if raw is None:
        return None
    n = szi.cert_number(raw)
    if n is None:
        raise HTTPException(422, detail="Номер сертификата не распознан: укажите номер из реестра")
    return n


def _fill_from_registry(session: Session, row: ObjectSzi) -> None:
    """Пустые поля нового СЗИ — из записи реестра (уровень доверия)."""
    if not row.cert_number:
        return
    entry = session.get(SziCert, row.cert_number)
    if entry is not None and row.trust_level is None:
        row.trust_level = entry.trust_level


def _audit_details(row: ObjectSzi) -> dict[str, Any]:
    return {
        "name": row.name,
        "kind": row.kind,
        "cert_number": row.cert_number,
        "measures": list(row.measure_ids or []),
    }


@router.post("/objects/{object_id}/szi", response_model=SziOut, status_code=201)
def create_szi(
    object_id: uuid.UUID, body: SziIn, request: Request, user: Editor, session: DbSession
) -> SziOut:
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    data = body.model_dump()
    data["cert_number"] = _cert(body.cert_number)
    data["measure_ids"] = _check_measures(session, obj, body.measure_ids, [])
    row = ObjectSzi(
        object_id=obj.id,
        project_id=obj.project_id,
        **data,
        created_by=user.id,
        created_by_name=user.display_name,
        updated_by=user.id,
        updated_by_name=user.display_name,
    )
    _fill_from_registry(session, row)
    session.add(row)
    session.flush()
    audit.record(
        session,
        action="szi.create",
        actor=user,
        entity="object_szi",
        entity_id=row.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={"object_id": str(obj.id), **_audit_details(row)},
    )
    session.commit()
    return _list_out(session, obj, [row])[0]


@router.patch("/object-szi/{szi_id}", response_model=SziOut)
def update_szi(
    szi_id: uuid.UUID, body: SziPatch, request: Request, user: Editor, session: DbSession
) -> SziOut:
    row, obj = _get_szi(session, szi_id, user)
    _editable(session, obj)
    changes = body.model_dump(exclude_unset=True)
    if "name" in changes and changes["name"] is None:
        raise HTTPException(422, detail="Укажите наименование СЗИ")
    if "kind" in changes and changes["kind"] is None:
        raise HTTPException(422, detail="Укажите вид СЗИ")
    if "cert_number" in changes:
        changes["cert_number"] = _cert(changes["cert_number"])
    if "measure_ids" in changes:
        changes["measure_ids"] = _check_measures(
            session, obj, changes["measure_ids"] or [], list(row.measure_ids or [])
        )
    diff: dict[str, list[Any]] = {}
    for k, v in changes.items():
        old = getattr(row, k)
        if old != v:
            diff[k] = [old.isoformat() if isinstance(old, date) else old,
                       v.isoformat() if isinstance(v, date) else v]  # fmt: skip
            setattr(row, k, v)
    if diff:
        row.updated_at, row.updated_by, row.updated_by_name = utcnow(), user.id, user.display_name
        audit.record(
            session,
            action="szi.update",
            actor=user,
            entity="object_szi",
            entity_id=row.id,
            project_id=obj.project_id,
            ip=client_ip(request),
            details={"object_id": str(obj.id), "name": row.name, "changes": diff},
        )
        session.commit()
    return _list_out(session, obj, [row])[0]


@router.delete("/object-szi/{szi_id}", status_code=204)
def delete_szi(szi_id: uuid.UUID, request: Request, user: Editor, session: DbSession) -> Response:
    row, obj = _get_szi(session, szi_id, user)
    _editable(session, obj)
    audit.record(
        session,
        action="szi.delete",
        actor=user,
        entity="object_szi",
        entity_id=row.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={"object_id": str(obj.id), **_audit_details(row)},
    )
    session.delete(row)
    session.commit()
    return Response(status_code=204)
