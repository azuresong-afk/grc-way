"""«Платформа»: сводка для Главной, приём событий, экран «События платформы» (задача 3.5).

GET  /summary?project=<uuid>          — карточка «Аттестации» на Главной (контракт v1.1, п. 10)
POST /events/platform                 — события платформы и соседей (манифест events.webhook):
                                        platform.keys.rotated, platform.project.updated,
                                        platform.user.blocked, scanner.run.finished,
                                        vm.ticket.status_changed, vm.remediation.verified
GET  /outbox/status                   — режим, адреса, счётчики outbox (администратор)
GET  /outbox?status=                  — исходящие события (администратор)
POST /outbox/{id}/retry              — повторить rejected/dead (администратор)

Подпись входящего события проверяется от байтов тела как есть, до разбора JSON
(платформа пересериализует конверт при доставке); обработка идемпотентна по id (inbox).
"""

from __future__ import annotations

import hmac
import json
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit, platform_events
from app.api.deps import DbSession, client_ip, require
from app.api.nonconformities import handle_event, signature
from app.api.projects import apply_platform_project, get_project_for
from app.core.config import get_settings
from app.core.rbac import Perm
from app.db.models import (
    AssessedObject,
    GeneratedDocument,
    InboxEvent,
    OutboxEvent,
    Project,
    User,
    utcnow,
)

router = APIRouter(tags=["platform"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Admin = Annotated[User, Depends(require(Perm.INTEGRATIONS_MANAGE))]


# ---------- Сводка для Главной ----------


class DocCounts(BaseModel):
    ready: int
    total: int


class PlatformSummaryData(BaseModel):
    systems: int
    # Доля реализованных мер по объектам проекта, 0–100; None — оценивать ещё нечего.
    measures_percent: int | None
    documents: DocCounts


class PlatformSummaryOut(BaseModel):
    product: str
    project_id: str
    generated_at: datetime
    link: str
    data: PlatformSummaryData


def document_counts(session: Session, object_ids: list[uuid.UUID]) -> DocCounts:
    """Документы комплекта: все (последняя версия каждого вида по объекту) и утверждённые."""
    if not object_ids:
        return DocCounts(ready=0, total=0)
    latest: dict[tuple[uuid.UUID, str], GeneratedDocument] = {}
    for d in session.scalars(
        select(GeneratedDocument)
        .where(GeneratedDocument.object_id.in_(object_ids))
        .order_by(GeneratedDocument.version)
    ):
        latest[(d.object_id, d.doc_type)] = d
    approved = {
        (d.object_id, d.doc_type)
        for d in session.scalars(
            select(GeneratedDocument).where(
                GeneratedDocument.object_id.in_(object_ids), GeneratedDocument.status == "approved"
            )
        )
    }
    return DocCounts(ready=sum(1 for k in latest if k in approved), total=len(latest))


@router.get("/summary", response_model=PlatformSummaryOut)
def platform_summary(
    user: Viewer, session: DbSession, project: Annotated[uuid.UUID, Query()]
) -> PlatformSummaryOut:
    p = get_project_for(session, project, user)
    s = get_settings()
    objs = list(
        session.scalars(
            select(AssessedObject).where(
                AssessedObject.project_id == p.id, AssessedObject.status == "active"
            )
        )
    )
    progress = platform_events.object_progress(session, objs, s.partial_weight)
    score = sum(x.score for x in progress.values())
    denominator = sum(x.denominator for x in progress.values())
    pid = str(p.platform_project_id or p.id)
    return PlatformSummaryOut(
        product=s.platform_product_id,
        project_id=pid,
        generated_at=utcnow().replace(microsecond=0),
        link=f"{s.base_path}?project={pid}",
        data=PlatformSummaryData(
            systems=len(objs),
            measures_percent=round(score / denominator * 100) if denominator else None,
            documents=document_counts(session, [o.id for o in objs]),
        ),
    )


# ---------- Приём событий ----------


def _platform_event(session: Session, request: Request, envelope: dict[str, Any]) -> str:
    etype = envelope.get("type")
    data = envelope.get("data") if isinstance(envelope.get("data"), dict) else {}
    if etype == "platform.keys.rotated":
        revoked = [str(k) for k in data.get("revoked") or [] if k]
        jwks = getattr(request.app.state, "jwks", None)
        if jwks is not None:
            if revoked:
                jwks.revoke(revoked)
            else:
                jwks.invalidate()
        audit.record(
            session,
            action="platform.keys_rotated",
            actor_name="platform",
            details={"kid": data.get("kid"), "revoked": revoked},
        )
        return "applied"
    if etype == "platform.project.updated":
        try:
            pid = uuid.UUID(str(data.get("project_id") or envelope.get("project_id")))
        except ValueError:
            return "ignored"
        p = session.scalar(select(Project).where(Project.platform_project_id == pid))
        if p is None:
            return "unknown_project"  # тень появится при первом обращении
        changed = apply_platform_project(
            session, p, {k: data[k] for k in ("name", "status") if k in data}
        )
        if changed:
            audit.record(
                session,
                action="project.shadow_sync",
                actor_name="platform",
                entity="project",
                entity_id=p.id,
                project_id=p.id,
                details={"fields": changed, "source": "event"},
            )
        return "applied"
    if etype == "platform.user.blocked":
        # Токен живёт до 15 минут; своих фоновых операций от имени пользователя у нас нет.
        return "noted"
    if etype == "scanner.run.finished":
        # Результаты прогона забираются импортом снимка (задача 1.9) — здесь только отметка.
        return "noted"
    if isinstance(etype, str) and etype.startswith("vm."):
        return handle_event(session, envelope)
    return "ignored"


@router.post("/events/platform")
async def receive_platform_event(request: Request, session: DbSession) -> dict[str, str]:
    secret = get_settings().events_secret
    if not secret:
        raise HTTPException(503, detail="Приём событий выключен (PLATFORM_EVENTS_SECRET не задан)")
    body = await request.body()
    if len(body) > 256 * 1024:
        raise HTTPException(413, detail="Событие слишком большое")
    if not hmac.compare_digest(request.headers.get("x-signature", ""), signature(secret, body)):
        audit.record_now(
            session,
            action="event.receive",
            actor_name="—",
            result="denied",
            ip=client_ip(request),
            details={"reason": "bad_signature", "webhook": "platform"},
        )
        raise HTTPException(401, detail="Неверная подпись события")
    try:
        envelope = json.loads(body)
    except ValueError as e:
        raise HTTPException(422, detail="Тело события — не JSON") from e
    if not isinstance(envelope, dict) or not envelope.get("id") or not envelope.get("type"):
        raise HTTPException(422, detail="В событии нет id или type")
    event_id = str(envelope["id"])[:64]
    if session.get(InboxEvent, event_id) is not None:
        return {"status": "duplicate"}
    result = _platform_event(session, request, envelope)
    session.add(
        InboxEvent(
            event_id=event_id,
            type=str(envelope["type"])[:64],
            source=str(envelope.get("source") or "")[:32],
            result=result,
        )
    )
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        return {"status": "duplicate"}
    return {"status": result}


# ---------- Экран «События платформы» ----------


class PlatformStatusOut(BaseModel):
    auth_mode: str
    product_id: str
    platform_url: str
    jwks_url: str
    events_url: str
    events_secret_set: bool
    outbox_enabled: bool
    counts: dict[str, int]
    shadow_users: int
    shadow_projects: int
    last_inbox_at: datetime | None


class OutboxOut(BaseModel):
    id: str
    type: str
    project_id: str | None
    subject: str | None
    status: str
    attempts: int
    next_at: datetime
    last_error: str | None
    created_at: datetime
    delivered_at: datetime | None
    data: dict[str, Any]


def _utc(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


@router.get("/outbox/status", response_model=PlatformStatusOut)
def platform_status(_: Admin, session: DbSession) -> PlatformStatusOut:
    s = get_settings()
    counts = {k: 0 for k in ("pending", "delivered", "rejected", "dead")}
    for st, n in session.execute(
        select(OutboxEvent.status, func.count()).group_by(OutboxEvent.status)
    ):
        counts[st] = n
    return PlatformStatusOut(
        auth_mode=s.auth_mode,
        product_id=s.platform_product_id,
        platform_url=s.platform_url,
        jwks_url=s.jwks_url,
        events_url=s.events_url,
        events_secret_set=bool(s.events_secret),
        outbox_enabled=s.outbox_enabled,
        counts=counts,
        shadow_users=session.scalar(
            select(func.count()).select_from(User).where(User.platform_sub.is_not(None))
        )
        or 0,
        shadow_projects=session.scalar(
            select(func.count())
            .select_from(Project)
            .where(Project.platform_project_id.is_not(None))
        )
        or 0,
        last_inbox_at=_utc(session.scalar(select(func.max(InboxEvent.received_at)))),
    )


def _outbox_out(r: OutboxEvent) -> OutboxOut:
    try:
        data = json.loads(r.body).get("data") or {}
    except ValueError:
        data = {}
    return OutboxOut(
        id=r.id,
        type=r.type,
        project_id=r.project_id,
        subject=r.subject,
        status=r.status,
        attempts=r.attempts,
        next_at=_utc(r.next_at) or r.next_at,
        last_error=r.last_error,
        created_at=_utc(r.created_at) or r.created_at,
        delivered_at=_utc(r.delivered_at),
        data=data if isinstance(data, dict) else {},
    )


@router.get("/outbox", response_model=list[OutboxOut])
def list_outbox(
    _: Admin,
    session: DbSession,
    response: Response,
    status_: Annotated[
        str | None, Query(alias="status", pattern=r"^(pending|delivered|rejected|dead)$")
    ] = None,
    type_: Annotated[str | None, Query(alias="type", max_length=64)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[OutboxOut]:
    stmt = select(OutboxEvent)
    if status_:
        stmt = stmt.where(OutboxEvent.status == status_)
    if type_:
        stmt = stmt.where(OutboxEvent.type == type_)
    response.headers["X-Total-Count"] = str(
        session.scalar(select(func.count()).select_from(stmt.subquery()))
    )
    rows = session.scalars(
        stmt.order_by(OutboxEvent.created_at.desc(), OutboxEvent.id).limit(limit).offset(offset)
    )
    return [_outbox_out(r) for r in rows]


@router.post("/outbox/{event_id}/retry", response_model=OutboxOut)
def retry_outbox(event_id: str, request: Request, user: Admin, session: DbSession) -> OutboxOut:
    r = session.get(OutboxEvent, event_id)
    if r is None:
        raise HTTPException(404, detail="Событие не найдено")
    if r.status not in ("dead", "rejected"):
        raise HTTPException(409, detail="Повторить можно только недоставленное событие")
    r.status = "pending"
    r.next_at = utcnow()
    r.attempts = 0
    audit.record(
        session,
        action="platform.outbox_retry",
        actor=user,
        entity="outbox",
        entity_id=r.id,
        ip=client_ip(request),
        details={"type": r.type},
    )
    session.commit()
    return _outbox_out(r)
