"""БДУ ФСТЭК: загрузка выгрузок (сравнение → применение) и просмотр угроз и уязвимостей."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session
from starlette.datastructures import UploadFile

from app import audit
from app.api.deps import CurrentUser, DbSession, client_ip, require
from app.api.object_vulns import refresh_for_bdu
from app.core.config import get_settings
from app.core.rbac import Perm
from app.db.models import BduImport, BduThreat, BduVuln, User, utcnow
from app.domain import bdu_import
from app.domain.bdu import (
    FIELD_TITLES,
    FILE_NAMES,
    KIND_TITLES,
    VERSION_SOURCES,
    BduFormatError,
    Kind,
    Parsed,
    e_level,
    parse_file,
    threat_code,
)
from app.domain.evidence_files import EvidenceFileError, clean_name, store
from app.integrations.bdu.xlsx import XlsxError

router = APIRouter(prefix="/bdu", tags=["bdu"])
Editor = Annotated[User, Depends(require(Perm.REFS_MANAGE))]
_CHUNK = 1 << 20


# ---------- Схемы ----------


class KindStatus(BaseModel):
    kind: str
    title: str
    file_name: str
    version: date | None
    version_source: str | None
    applied_at: datetime | None
    applied_by_name: str | None
    active: int
    withdrawn: int
    pending_id: uuid.UUID | None
    criticality_last: int | None = None


class StatusOut(BaseModel):
    threats: KindStatus
    vulns: KindStatus


class ImportBrief(BaseModel):
    id: uuid.UUID
    kind: str
    file_name: str
    file_size: int
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
    # Подтверждение, что предупреждения сравнения прочитаны.
    ack_warnings: bool = False


class ThreatOut(BaseModel):
    code: str
    number: int
    title: str
    description: str | None
    source: str | None
    target: str | None
    conf: bool | None
    integ: bool | None
    avail: bool | None
    published_on: date | None
    changed_on: date | None
    status: str | None
    first_version: date | None
    changed_version: date | None
    withdrawn_at: datetime | None


class VulnBrief(BaseModel):
    bdu_id: str
    title: str
    vendor: str | None
    product: str | None
    cvss3_vector: str | None
    cvss3_version: str | None
    cvss3_score: float | None
    cvss3_score_source: str | None
    exploit: str | None
    in_wild: str | None
    e_level: str
    status: str | None
    cve_ids: list[str]
    changed_version: date | None
    criticality_changed_at: datetime | None
    withdrawn_at: datetime | None


class VulnOut(VulnBrief):
    description: str | None
    product_version: str | None
    sw_type: str | None
    platform: str | None
    vuln_class: str | None
    identified_on: date | None
    published_on: date | None
    severity: str | None
    cvss_other: dict[str, Any] | None
    measures: str | None
    exploit_raw: str | None
    in_wild_raw: str | None
    fix_info: str | None
    links: str | None
    cwe_ids: list[str]
    other_ids: str | None
    other_info: str | None
    exploit_method: str | None
    fix_method: str | None
    first_version: date | None
    criticality_changes: dict[str, list] | None
    criticality_changed_version: date | None


# ---------- Загрузки ----------


def _brief(r: BduImport) -> ImportBrief:
    return ImportBrief(
        id=r.id,
        kind=r.kind,
        file_name=r.file_name,
        file_size=r.file_size,
        export_version=r.export_version,
        version_source=r.version_source,
        version_source_title=VERSION_SOURCES.get(r.version_source, r.version_source),
        status=r.status,
        summary=r.summary,
        warnings=r.warnings,
        created_at=r.created_at,
        created_by_name=r.created_by_name,
        applied_at=r.applied_at,
        applied_by_name=r.applied_by_name,
        applied=r.applied,
    )


def _out(r: BduImport) -> ImportOut:
    return ImportOut(**_brief(r).model_dump(), items=r.items, field_titles=FIELD_TITLES)


def _kind_status(session: Session, kind: Kind) -> KindStatus:
    m = bdu_import.model(kind)
    cur = bdu_import.current_version(session, kind)
    counts = dict(
        session.execute(
            select(m.withdrawn_at.is_(None), func.count()).group_by(m.withdrawn_at.is_(None))
        ).all()
    )
    pending = session.scalar(
        select(BduImport.id)
        .where(BduImport.kind == kind, BduImport.status == "pending")
        .order_by(BduImport.created_at.desc())
        .limit(1)
    )
    return KindStatus(
        kind=kind,
        title=KIND_TITLES[kind],
        file_name=FILE_NAMES[kind],
        version=cur.export_version if cur else None,
        version_source=cur.version_source if cur else None,
        applied_at=cur.applied_at if cur else None,
        applied_by_name=cur.applied_by_name if cur else None,
        active=counts.get(True, 0),
        withdrawn=counts.get(False, 0),
        pending_id=pending,
        criticality_last=(cur.applied or {}).get("criticality")
        if cur and kind == "vulns"
        else None,
    )


@router.get("/status", response_model=StatusOut)
def status(_: CurrentUser, session: DbSession) -> StatusOut:
    return StatusOut(threats=_kind_status(session, "threats"), vulns=_kind_status(session, "vulns"))


def _bdu_dir():
    return get_settings().bdu_dir


def _reject(session: Session, user: User, ip: str | None, name: str, code: str, text: str):
    audit.record_now(
        session,
        action="bdu.import.rejected",
        actor=user,
        result="error",
        ip=ip,
        details={"name": name, "code": code, "reason": text},
    )


@router.post("/imports", response_model=ImportOut, status_code=201)
async def upload(request: Request, user: Editor, session: DbSession) -> ImportOut:
    """Выгрузка БДУ (multipart: file; kind — threats|vulns, необязательно; export_version —
    дата выгрузки ГГГГ-ММ-ДД, если её нет в файле)."""
    if not request.headers.get("content-type", "").startswith("multipart/form-data"):
        raise HTTPException(422, detail="Приложите файл выгрузки (multipart/form-data, поле file)")
    form = await request.form(max_files=1, max_fields=10)
    got = form.get("file")
    if not isinstance(got, UploadFile):
        raise HTTPException(422, detail="Приложите файл выгрузки (поле file)")
    kind = form.get("kind") or None
    if kind not in (None, "threats", "vulns"):
        raise HTTPException(422, detail="kind: threats или vulns")
    raw_version = form.get("export_version")
    version: date | None = None
    if isinstance(raw_version, str) and raw_version.strip():
        try:
            version = date.fromisoformat(raw_version.strip())
        except ValueError as e:
            raise HTTPException(422, detail="Дата выгрузки — в формате ГГГГ-ММ-ДД") from e
    return await run_in_threadpool(_upload, got, kind, version, user, session, client_ip(request))


def _parse_stored(sha: str, kind: Kind | None) -> Parsed:
    return parse_file(_bdu_dir() / sha, expect=kind)


def _upload(
    upload: UploadFile,
    kind: Kind | None,
    version: date | None,
    user: User,
    session: Session,
    ip: str | None,
) -> ImportOut:
    settings = get_settings()
    name = clean_name(upload.filename or "")
    if not name.lower().endswith(".xlsx"):
        _reject(session, user, ip, name, "file_type", "не XLSX")
        raise HTTPException(
            422, detail="Нужен файл XLSX: thrlist.xlsx или vullist.xlsx с bdu.fstec.ru"
        )

    def chunks():
        while chunk := upload.file.read(_CHUNK):
            yield chunk

    try:
        stored = store(chunks(), name, settings.bdu_dir, settings.bdu_max_mb * 1024 * 1024)
    except EvidenceFileError as e:
        _reject(session, user, ip, name, e.code, str(e))
        code = 413 if e.code == "file_too_large" else 422
        raise HTTPException(code, detail=str(e), headers={"X-Error-Code": e.code}) from e
    try:
        parsed = _parse_stored(stored.sha256, kind)
    except (BduFormatError, XlsxError) as e:
        _reject(session, user, ip, name, "bdu_format", str(e))
        raise HTTPException(422, detail=str(e), headers={"X-Error-Code": "bdu_format"}) from e
    if version is not None:
        parsed.version, parsed.version_source = version, "user"
    diff = bdu_import.compute_diff(session, parsed, file_sha256=stored.sha256)
    session.execute(
        update(BduImport)
        .where(BduImport.kind == parsed.kind, BduImport.status == "pending")
        .values(status="superseded")
    )
    row = BduImport(
        kind=parsed.kind,
        file_name=name,
        file_sha256=stored.sha256,
        file_size=stored.size,
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
        # Нечего применять: версия выгрузки фиксируется сразу.
        row.status = "applied"
        row.applied_at, row.applied_by, row.applied_by_name = utcnow(), user.id, user.display_name
        row.applied = {"no_changes": True, **bdu_import.ApplyResult().as_dict()}
    s = diff["summary"]
    audit.record(
        session,
        action="bdu.import.diff",
        actor=user,
        entity="bdu_import",
        entity_id=row.id,
        ip=ip,
        details={
            "kind": parsed.kind,
            "file": name,
            "sha256": stored.sha256,
            "version": parsed.version.isoformat() if parsed.version else None,
            **{k: s[k] for k in ("in_file", "add", "update", "restore", "withdraw", "criticality")},
            "warnings": [w["code"] for w in diff["warnings"]],
        },
    )
    session.commit()
    return _out(row)


@router.get("/imports", response_model=list[ImportBrief])
def list_imports(
    _: CurrentUser,
    session: DbSession,
    kind: Annotated[Kind | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[ImportBrief]:
    q = select(BduImport).order_by(BduImport.created_at.desc()).limit(limit)
    if kind:
        q = q.where(BduImport.kind == kind)
    return [_brief(r) for r in session.scalars(q)]


def _get_import(session: Session, import_id: uuid.UUID) -> BduImport:
    row = session.get(BduImport, import_id)
    if row is None:
        raise HTTPException(404, detail="Загрузка не найдена")
    return row


@router.get("/imports/{import_id}", response_model=ImportOut)
def get_import(import_id: uuid.UUID, _: CurrentUser, session: DbSession) -> ImportOut:
    return _out(_get_import(session, import_id))


@router.post("/imports/{import_id}/apply", response_model=ImportOut)
async def apply_import(
    import_id: uuid.UUID, body: ApplyIn, request: Request, user: Editor, session: DbSession
) -> ImportOut:
    return await run_in_threadpool(_apply, import_id, body, user, session, client_ip(request))


def _apply(
    import_id: uuid.UUID, body: ApplyIn, user: User, session: Session, ip: str | None
) -> ImportOut:
    row = _get_import(session, import_id)
    if row.status == "applied":
        raise HTTPException(409, detail="Эта выгрузка уже применена")
    if row.status != "pending":
        raise HTTPException(409, detail="Есть более новая загрузка этого вида. Откройте её")
    if row.warnings and not body.ack_warnings:
        raise HTTPException(
            409,
            detail="Подтвердите, что предупреждения сравнения прочитаны",
            headers={"X-Error-Code": "ack_required"},
        )
    if not (_bdu_dir() / row.file_sha256).exists():
        raise HTTPException(410, detail="Файл выгрузки не найден в хранилище. Загрузите его снова")
    kind: Kind = row.kind  # type: ignore[assignment]
    parsed = _parse_stored(row.file_sha256, kind)
    parsed.version = row.export_version
    current = bdu_import.compute_diff(session, parsed)
    if current["fingerprint"] != row.fingerprint:
        raise HTTPException(
            409, detail="Данные БДУ изменились после сравнения. Загрузите выгрузку заново"
        )
    res = bdu_import.apply(session, parsed, row, version=row.export_version)
    applied = res.as_dict()
    register_assessed = None
    if kind == "vulns":
        # Реестры уязвимостей объектов: новые сведения БДУ — пересчёт оценок (п. 16, 19).
        touched = set(
            session.scalars(
                select(BduVuln.bdu_id).where(
                    or_(
                        BduVuln.criticality_changed_import_id == row.id,
                        BduVuln.first_import_id == row.id,
                    )
                )
            )
        )
        register_assessed = refresh_for_bdu(session, touched, user)
    row.status = "applied"
    row.applied_at = utcnow()
    row.applied_by, row.applied_by_name = user.id, user.display_name
    row.applied = applied
    audit.record(
        session,
        action="bdu.import.apply",
        actor=user,
        entity="bdu_import",
        entity_id=row.id,
        ip=ip,
        details={
            "kind": kind,
            "version": row.export_version.isoformat() if row.export_version else None,
            "ack_warnings": [w["code"] for w in row.warnings],
            **applied,
            "register_assessed": register_assessed,
        },
    )
    session.commit()
    return _out(row)


# ---------- Просмотр ----------


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


@router.get("/threats", response_model=list[ThreatOut])
def list_threats(
    _: CurrentUser,
    session: DbSession,
    response: Response,
    q: Annotated[str | None, Query(max_length=200)] = None,
    withdrawn: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ThreatOut]:
    stmt = select(BduThreat)
    if not withdrawn:
        stmt = stmt.where(BduThreat.withdrawn_at.is_(None))
    if q and q.strip():
        s = q.strip()
        conds = [BduThreat.title.ilike(_like(s), escape="\\")]
        if code := threat_code(s):
            conds.append(BduThreat.code == code[0])
        stmt = stmt.where(or_(*conds))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    response.headers["X-Total-Count"] = str(total)
    rows = session.scalars(stmt.order_by(BduThreat.number).limit(limit).offset(offset))
    return [ThreatOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/threats/{code}", response_model=ThreatOut)
def get_threat(code: str, _: CurrentUser, session: DbSession) -> ThreatOut:
    row = session.get(BduThreat, code)
    if row is None:
        raise HTTPException(404, detail="Угроза не найдена")
    return ThreatOut.model_validate(row, from_attributes=True)


def _vuln_dict(v: BduVuln) -> dict[str, Any]:
    d = {c.key: getattr(v, c.key) for c in BduVuln.__table__.columns}
    d["e_level"] = e_level(v.exploit, v.in_wild)
    d["cve_ids"] = v.cve_ids or []
    d["cwe_ids"] = v.cwe_ids or []
    return d


@router.get("/vulns", response_model=list[VulnBrief])
def list_vulns(
    _: CurrentUser,
    session: DbSession,
    response: Response,
    q: Annotated[str | None, Query(max_length=200)] = None,
    exploit: Annotated[str | None, Query(pattern="^(public|exists|unknown|none|other)$")] = None,
    in_wild: Annotated[str | None, Query(pattern="^(yes|no|unknown|other)$")] = None,
    min_score: Annotated[float | None, Query(ge=0, le=10)] = None,
    crit_changed: Annotated[bool, Query()] = False,
    withdrawn: Annotated[bool, Query()] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[VulnBrief]:
    stmt = select(BduVuln)
    if not withdrawn:
        stmt = stmt.where(BduVuln.withdrawn_at.is_(None))
    if q and q.strip():
        s = q.strip()
        like = _like(s)
        stmt = stmt.where(
            or_(
                BduVuln.bdu_id.ilike(like, escape="\\"),
                BduVuln.title.ilike(like, escape="\\"),
                BduVuln.product.ilike(like, escape="\\"),
                BduVuln.vendor.ilike(like, escape="\\"),
                BduVuln.other_ids.ilike(like, escape="\\"),
            )
        )
    if exploit:
        stmt = stmt.where(BduVuln.exploit == exploit)
    if in_wild:
        stmt = stmt.where(BduVuln.in_wild == in_wild)
    if min_score is not None:
        stmt = stmt.where(BduVuln.cvss3_score >= min_score)
    if crit_changed:
        stmt = stmt.where(BduVuln.criticality_changed_at.is_not(None))
    total = session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    response.headers["X-Total-Count"] = str(total)
    order = (
        [BduVuln.criticality_changed_at.desc(), BduVuln.bdu_id.desc()]
        if crit_changed
        else [BduVuln.bdu_id.desc()]
    )
    rows = session.scalars(stmt.order_by(*order).limit(limit).offset(offset))
    return [VulnBrief.model_validate(_vuln_dict(r)) for r in rows]


@router.get("/vulns/{bdu_id}", response_model=VulnOut)
def get_vuln(bdu_id: str, _: CurrentUser, session: DbSession) -> VulnOut:
    row = session.get(BduVuln, bdu_id)
    if row is None:
        raise HTTPException(404, detail="Уязвимость не найдена")
    d = _vuln_dict(row)
    d["criticality_changed_version"] = None
    if row.criticality_changed_import_id:
        d["criticality_changed_version"] = session.scalar(
            select(BduImport.export_version).where(
                BduImport.id == row.criticality_changed_import_id
            )
        )
    return VulnOut.model_validate(d)
