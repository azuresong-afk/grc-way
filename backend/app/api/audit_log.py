"""Журнал аудита: просмотр и выгрузка (администратор)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import Select, func, select

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.schemas import AuditOut
from app.core.rbac import Perm
from app.db.models import AuditRecord, User

router = APIRouter(prefix="/audit", tags=["audit"])
Auditor = Annotated[User, Depends(require(Perm.AUDIT_VIEW))]


def _filtered(
    action: str | None,
    result: str | None,
    user: str | None,
    since: datetime | None,
    until: datetime | None,
) -> Select[tuple[AuditRecord]]:
    stmt = select(AuditRecord)
    if action:
        stmt = stmt.where(AuditRecord.action.startswith(action))
    if result:
        stmt = stmt.where(AuditRecord.result == result)
    if user:
        stmt = stmt.where(func.lower(AuditRecord.user_name).contains(user.lower()))
    if since:
        stmt = stmt.where(AuditRecord.at >= since)
    if until:
        stmt = stmt.where(AuditRecord.at < until)
    return stmt


@router.get("", response_model=list[AuditOut])
def list_audit(
    _: Auditor,
    session: DbSession,
    response: Response,
    action: str | None = None,
    result: str | None = None,
    user: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AuditRecord]:
    stmt = _filtered(action, result, user, since, until)
    response.headers["X-Total-Count"] = str(
        session.scalar(select(func.count()).select_from(stmt.subquery()))
    )
    return list(session.scalars(stmt.order_by(AuditRecord.id.desc()).limit(limit).offset(offset)))


@router.get("/export")
def export_audit(
    request: Request,
    viewer: Auditor,
    session: DbSession,
    action: str | None = None,
    result: str | None = None,
    user: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> Response:
    stmt = _filtered(action, result, user, since, until).order_by(AuditRecord.id)
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(
        [
            "id",
            "время (UTC)",
            "пользователь",
            "действие",
            "объект",
            "id объекта",
            "проект",
            "результат",
            "IP",
            "подробности",
        ]
    )
    for r in session.scalars(stmt):
        w.writerow(
            [
                r.id,
                r.at.isoformat(),
                r.user_name or "",
                r.action,
                r.entity or "",
                r.entity_id or "",
                r.project_id or "",
                r.result,
                r.ip or "",
                json.dumps(r.details, ensure_ascii=False),
            ]
        )
    audit.record_now(session, action="audit.export", actor=viewer, ip=client_ip(request))
    # BOM — чтобы Excel открыл кириллицу без вопросов о кодировке.
    return Response(
        content="﻿" + buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="audit.csv"'},
    )
