"""Обновление справочника мер из «Сканера»: сравнение (экран разницы) и применение."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update

from app import audit
from app.api.deps import CurrentUser, DbSession, client_ip, require
from app.core.rbac import Perm
from app.db.models import RefProfile, RefSyncDiff, User, utcnow
from app.integrations.scanner.client import ScannerClient, ScannerError, get_scanner_client
from app.integrations.scanner.schemas import ScannerProfile
from app.refs.sync import apply_diff, compute_diff, fingerprint, payload_hash

router = APIRouter(prefix="/refs", tags=["refs"])
Editor = Annotated[User, Depends(require(Perm.REFS_MANAGE))]
Scanner = Annotated[ScannerClient, Depends(get_scanner_client)]


class SourceOut(BaseModel):
    mode: str
    source: str
    last_synced_at: datetime | None
    pending_diff_id: uuid.UUID | None


class DiffBrief(BaseModel):
    id: uuid.UUID
    created_at: datetime
    created_by_name: str | None
    mode: str
    source: str
    status: str
    summary: dict[str, Any]
    applied_at: datetime | None
    applied_by_name: str | None
    applied: dict[str, Any] | None


class DiffOut(DiffBrief):
    profiles: list[dict[str, Any]]
    items: list[dict[str, Any]]
    checks: dict[str, Any]


class ApplyIn(BaseModel):
    diff_id: uuid.UUID
    # Ключи «профиль:мера», которые применить. Не задано — всё, кроме конфликтов.
    selected: list[str] | None = Field(default=None, max_length=5000)


def _brief(d: RefSyncDiff) -> DiffBrief:
    return DiffBrief(
        id=d.id,
        created_at=d.created_at,
        created_by_name=d.created_by_name,
        mode=d.mode,
        source=d.source,
        status=d.status,
        summary=d.diff["summary"],
        applied_at=d.applied_at,
        applied_by_name=d.applied_by_name,
        applied=d.applied,
    )


def _out(d: RefSyncDiff) -> DiffOut:
    return DiffOut(
        **_brief(d).model_dump(),
        profiles=d.diff["profiles"],
        items=d.diff["items"],
        checks=d.diff["checks"],
    )


def _scanner_error(e: ScannerError) -> HTTPException:
    status = 503 if e.code == "scanner_not_configured" else 502
    return HTTPException(status, detail=str(e), headers={"X-Error-Code": e.code})


@router.get("/scanner-source", response_model=SourceOut)
def scanner_source(_: CurrentUser, session: DbSession, scanner: Scanner) -> SourceOut:
    pending = session.scalar(
        select(RefSyncDiff.id)
        .where(RefSyncDiff.status == "pending")
        .order_by(RefSyncDiff.created_at.desc())
        .limit(1)
    )
    return SourceOut(
        mode=scanner.mode,
        source=scanner.source,
        last_synced_at=session.scalar(select(func.max(RefProfile.scanner_synced_at))),
        pending_diff_id=pending,
    )


@router.post("/profiles/scanner-diff", response_model=DiffOut, status_code=201)
def scanner_diff(request: Request, user: Editor, session: DbSession, scanner: Scanner) -> DiffOut:
    try:
        profiles = scanner.compliance_profiles()
    except ScannerError as e:
        audit.record_now(
            session,
            action="refs.scanner.diff",
            actor=user,
            result="error",
            ip=client_ip(request),
            details={"source": scanner.source, "code": e.code, "error": str(e)},
        )
        raise _scanner_error(e) from e
    diff = compute_diff(session, profiles)
    # Новое сравнение делает прежние неприменёнными навсегда: применяется только свежее.
    session.execute(
        update(RefSyncDiff).where(RefSyncDiff.status == "pending").values(status="superseded")
    )
    row = RefSyncDiff(
        created_by=user.id,
        created_by_name=user.display_name,
        mode=scanner.mode,
        source=scanner.source,
        payload=[p.model_dump(mode="json") for p in profiles],
        payload_hash=payload_hash(profiles),
        diff=diff,
        fingerprint=fingerprint(diff),
        status="pending" if diff["summary"]["has_changes"] else "applied",
    )
    if not diff["summary"]["has_changes"]:
        # Нечего применять — сравнение сразу закрыто, отметка синхронизации обновляется.
        row.applied_at, row.applied_by, row.applied_by_name = utcnow(), user.id, user.display_name
        row.applied = {"no_changes": True}
        session.execute(
            update(RefProfile)
            .where(RefProfile.id.in_([p.id for p in profiles]))
            .values(scanner_synced_at=row.applied_at)
        )
    session.add(row)
    session.flush()
    audit.record(
        session,
        action="refs.scanner.diff",
        actor=user,
        entity="ref_sync_diff",
        entity_id=row.id,
        ip=client_ip(request),
        details={
            "source": scanner.source,
            "mode": scanner.mode,
            "payload_hash": row.payload_hash,
            **{k: diff["summary"][k] for k in ("add", "update", "remove", "conflict")},
        },
    )
    session.commit()
    return _out(row)


@router.get("/scanner-diffs", response_model=list[DiffBrief])
def list_diffs(
    _: CurrentUser,
    session: DbSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[DiffBrief]:
    rows = session.scalars(select(RefSyncDiff).order_by(RefSyncDiff.created_at.desc()).limit(limit))
    return [_brief(r) for r in rows]


def _get(session, diff_id: uuid.UUID) -> RefSyncDiff:
    row = session.get(RefSyncDiff, diff_id)
    if row is None:
        raise HTTPException(404, detail="Сравнение не найдено")
    return row


@router.get("/scanner-diffs/{diff_id}", response_model=DiffOut)
def get_diff(diff_id: uuid.UUID, _: CurrentUser, session: DbSession) -> DiffOut:
    return _out(_get(session, diff_id))


@router.post("/profiles/scanner-apply", response_model=DiffOut)
def scanner_apply(body: ApplyIn, request: Request, user: Editor, session: DbSession) -> DiffOut:
    row = _get(session, body.diff_id)
    if row.status == "applied":
        raise HTTPException(409, detail="Это сравнение уже применено")
    if row.status != "pending":
        raise HTTPException(
            409, detail="Есть более новое сравнение. Откройте его или сравните заново"
        )
    profiles = [ScannerProfile.model_validate(p) for p in row.payload]
    # Справочник мог измениться после сравнения (правка, сверка, загрузка YAML).
    current = compute_diff(session, profiles)
    if fingerprint(current) != row.fingerprint:
        raise HTTPException(
            409,
            detail="Справочник изменился после сравнения. Сравните со «Сканером» заново",
        )
    keys = {i["key"] for i in current["items"]}
    if body.selected is None:
        selected = {i["key"] for i in current["items"] if i["default"]}
    else:
        selected = set(body.selected)
        if unknown := selected - keys:
            raise HTTPException(
                422, detail=f"Нет таких мер в сравнении: {', '.join(sorted(unknown)[:5])}"
            )
    res = apply_diff(
        session, profiles, current, selected, user_id=user.id, user_name=user.display_name
    )
    row.status = "applied"
    row.applied_at = utcnow()
    row.applied_by, row.applied_by_name = user.id, user.display_name
    row.applied = {**res.as_dict(), "selected": sorted(selected)}
    audit.record(
        session,
        action="refs.scanner.apply",
        actor=user,
        entity="ref_sync_diff",
        entity_id=row.id,
        ip=client_ip(request),
        details={"source": row.source, **res.as_dict()},
    )
    session.commit()
    return _out(row)
