"""События для «Платформы»: outbox, доставка, сводные показатели (задача 3.5).

Контракт v1.1, п. 6; docs/integration/README.md, п. 7.

- Событие пишется в таблицу `outbox` в той же транзакции, что и изменение данных.
  Тело сериализуется один раз и хранится как есть: подпись
  `X-Signature: sha256=<HMAC-SHA256(тело, PLATFORM_EVENTS_SECRET)>` считается
  от этих байтов, и в сеть уходят они же.
- Доставка — фоновый поток в процессе API (`OutboxWorker`): `POST
  {PLATFORM_EVENTS_URL}` с `X-Platform-Product`, `X-Event-Id`, `X-Signature`.
  202 и 200 `{"duplicate":true}` — доставлено; 422 — `rejected` (повторять
  бессмысленно); сеть, 401, 5xx — повтор через 1, 5, 15, 60 мин, затем `dead`
  и ручной повтор на экране «События платформы». Строки в БД, поэтому доставка
  переживает рестарт.
- `audit.recorded` — каждая запись журнала аудита (обработчик сессии SQLAlchemy:
  запись outbox добавляется в ту же транзакцию, что и запись журнала).
- `grc.assessment.updated` — процент реализации мер и статус оценки объекта; не
  чаще раза в минуту на объект и только последнее значение: проход доставки
  сравнивает текущие показатели с последними отправленными (`assessment_feed`).
- `grc.document.approval_requested` — документ отправлен на утверждение,
  `notify` — теневым пользователям с ролью `approve` в проекте, кроме автора.

Outbox ведётся, только когда заданы адрес событий и секрет (`Settings.outbox_enabled`):
в отдельном запуске без платформы ничего не копится.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import uuid
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import event, select
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.db.models import (
    AssessedObject,
    AssessmentFeed,
    AuditRecord,
    GeneratedDocument,
    ObjectMeasure,
    OutboxEvent,
    Project,
    User,
    utcnow,
)
from app.domain.measures import Item, compute_stats

log = logging.getLogger(__name__)

# Повторы после неудачи: через 1, 5, 15, 60 минут, затем — dead.
RETRY_MINUTES = (1, 5, 15, 60)

_AUDIT_RESULT = {"ok": "success", "denied": "denied", "error": "failure"}


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def build_body(
    settings: Settings,
    *,
    event_id: str,
    type_: str,
    project_id: str | None,
    subject: str | None,
    data: dict[str, Any],
    notify: dict[str, Any] | None = None,
    time: datetime | None = None,
) -> str:
    envelope: dict[str, Any] = {
        "id": event_id,
        "type": type_,
        "source": settings.platform_product_id,
        "time": _iso(time or utcnow()),
        "project_id": project_id,
        "subject": subject,
        "data": data,
    }
    if notify:
        envelope["notify"] = notify
    # Компактно и без \\u: тело подписывается ровно в этом виде.
    return json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))


def enqueue(
    session: Session,
    type_: str,
    *,
    project_id: object,
    subject: str | None,
    data: dict[str, Any],
    notify: dict[str, Any] | None = None,
    time: datetime | None = None,
) -> OutboxEvent | None:
    """Добавляет событие в outbox текущей транзакции (None — outbox выключен)."""
    settings = get_settings()
    if not settings.outbox_enabled:
        return None
    event_id = str(uuid.uuid4())
    pid = None if project_id is None else str(project_id)
    row = OutboxEvent(
        id=event_id,
        type=type_,
        project_id=pid,
        subject=subject,
        body=build_body(
            settings,
            event_id=event_id,
            type_=type_,
            project_id=pid,
            subject=subject,
            data=data,
            notify=notify,
            time=time,
        ),
        status="pending",
        attempts=0,
        next_at=utcnow(),
    )
    session.add(row)
    return row


def platform_project_id(session: Session, project_id: object) -> str | None:
    """uuid проекта в платформе для конверта (у тени он равен нашему id)."""
    if project_id is None:
        return None
    with session.no_autoflush:
        p = session.get(Project, project_id)
    if p is None or p.platform_project_id is None:
        return None
    return str(p.platform_project_id)


# ---------- audit.recorded ----------


def _audit_data(session: Session, rec: AuditRecord) -> dict[str, Any]:
    actor = None
    if rec.user_id is not None:
        with session.no_autoflush:
            u = session.get(User, rec.user_id)
        actor = {
            "sub": (u.platform_sub if u and u.platform_sub else str(rec.user_id))[:100],
            "name": (rec.user_name or (u.display_name if u else "") or "")[:200],
        }
    elif rec.user_name:
        actor = {"sub": "", "name": rec.user_name[:200]}
    obj = None
    if rec.entity:
        obj = rec.entity + (f"/{rec.entity_id}" if rec.entity_id else "")
    data: dict[str, Any] = {
        "time": _iso(rec.at or utcnow()),
        "action": rec.action[:100],
        "object": obj[:300] if obj else None,
        "result": _AUDIT_RESULT.get(rec.result, "success"),
        "ip": (rec.ip or None) and rec.ip[:64],
        "details": rec.details or {},
    }
    if actor:
        data["actor"] = actor
    return data


@event.listens_for(Session, "after_flush")
def _collect_audit(session: Session, _ctx: object) -> None:
    if not get_settings().outbox_enabled:
        return
    new = [o for o in session.new if isinstance(o, AuditRecord)]
    if new:
        session.info.setdefault("grc_audit_outbox", []).extend(new)


@event.listens_for(Session, "after_flush_postexec")
def _audit_to_outbox(session: Session, _ctx: object) -> None:
    pending: list[AuditRecord] = session.info.pop("grc_audit_outbox", [])
    for rec in pending:
        # Запись outbox попадёт в следующий проход flush той же транзакции
        # (commit сбрасывает сессию, пока в ней есть изменения).
        enqueue(
            session,
            "audit.recorded",
            project_id=platform_project_id(session, rec.project_id),
            subject=f"audit/{rec.id}",
            data=_audit_data(session, rec),
            time=rec.at,
        )


# ---------- grc.assessment.updated ----------


@dataclass
class Progress:
    title: str
    percent: int | None
    status: str  # not_started | in_progress | assessed
    score: float
    denominator: int


def object_progress(
    session: Session, objs: Iterable[AssessedObject], partial_weight: float
) -> dict[uuid.UUID, Progress]:
    """Процент реализации мер объекта по правилу сводки платформы (контракт v1.1, п. 10):
    организационные меры без оценки в знаменатель не входят."""
    objs = list(objs)
    measures: dict[uuid.UUID, list[ObjectMeasure]] = defaultdict(list)
    ids = [o.id for o in objs]
    if ids:
        for m in session.scalars(select(ObjectMeasure).where(ObjectMeasure.object_id.in_(ids))):
            measures[m.object_id].append(m)
    out: dict[uuid.UUID, Progress] = {}
    for o in objs:
        ms = measures.get(o.id, [])
        title = o.name[:300]
        if not ms:
            out[o.id] = Progress(title, None, "not_started", 0.0, 0)
            continue
        items = [
            Item(m.measure_id, m.method, m.status, m.adaptation, tuple(m.compensating_ids or ()))
            for m in ms
        ]
        stats = compute_stats(items, partial_weight)
        denominator = stats.total.total - stats.manual.unassessed
        percent = round(stats.total.score / denominator * 100) if denominator else None
        counted = [m for m in ms if m.adaptation != "excluded"]
        done = bool(counted) and all(m.confirmed_at is not None for m in counted)
        out[o.id] = Progress(
            title, percent, "assessed" if done else "in_progress", stats.total.score, denominator
        )
    return out


def scan_assessments(session: Session, now: datetime | None = None) -> int:
    """Ставит grc.assessment.updated по объектам, чьи показатели изменились
    с последней отправки, но не чаще раза в N секунд на объект. Возвращает число событий."""
    settings = get_settings()
    if not settings.outbox_enabled:
        return 0
    now = now or utcnow()
    every = timedelta(seconds=settings.assessment_event_seconds)
    objs = list(
        session.scalars(
            select(AssessedObject)
            .join(Project, Project.id == AssessedObject.project_id)
            .where(AssessedObject.status == "active", Project.platform_project_id.is_not(None))
        )
    )
    if not objs:
        return 0
    progress = object_progress(session, objs, settings.partial_weight)
    feed = {
        f.object_id: f
        for f in session.scalars(
            select(AssessmentFeed).where(AssessmentFeed.object_id.in_([o.id for o in objs]))
        )
    }
    sent = 0
    for o in objs:
        p = progress[o.id]
        row = feed.get(o.id)
        current = (p.percent, p.status, p.title)
        if row is not None and (row.percent, row.status, row.title) == current:
            continue
        if row is not None:
            last = row.sent_at if row.sent_at.tzinfo else row.sent_at.replace(tzinfo=UTC)
            if now - last < every:
                continue  # отправим последнее значение на следующем проходе
        enqueue(
            session,
            "grc.assessment.updated",
            project_id=platform_project_id(session, o.project_id),
            subject=f"system/{o.id}",
            data={
                "system_id": str(o.id),
                "title": p.title,
                "percent": p.percent,
                "status": p.status,
                "regime": o.regime,
            },
            time=now,
        )
        if row is None:
            session.add(
                AssessmentFeed(
                    object_id=o.id, percent=p.percent, status=p.status, title=p.title, sent_at=now
                )
            )
        else:
            row.percent, row.status, row.title, row.sent_at = p.percent, p.status, p.title, now
        sent += 1
    session.commit()
    return sent


# ---------- grc.document.approval_requested ----------


def approvers(session: Session, project_id: object, exclude: Iterable[object]) -> list[str]:
    """sub теневых пользователей с ролью approve и доступом к проекту, кроме исключённых."""
    skip = {e for e in exclude if e is not None}
    pid = str(project_id)
    out: list[str] = []
    for u in session.scalars(
        select(User).where(User.platform_sub.is_not(None), User.is_active).order_by(User.username)
    ):
        if u.id in skip or u.platform_typ == "service":
            continue
        if "approve" not in (u.platform_roles or []):
            continue
        projects = u.platform_projects or []
        if "*" in projects or pid in projects:
            out.append(u.platform_sub or "")
    return [s for s in out if s]


def document_approval_requested(session: Session, d: GeneratedDocument, submitter: User) -> None:
    pid = platform_project_id(session, d.project_id)
    if pid is None:
        return
    settings = get_settings()
    author = session.get(User, d.created_by) if d.created_by else None
    users = approvers(session, pid, exclude=(d.created_by, submitter.id))
    base = settings.base_path.rstrip("/")
    link = f"{base}/objects/{d.object_id}?project={pid}&tab=documents"
    enqueue(
        session,
        "grc.document.approval_requested",
        project_id=pid,
        subject=f"document/{d.id}",
        data={
            "document_id": str(d.id),
            "title": d.title,
            "system_id": str(d.object_id),
            "version": d.version,
            "author_sub": (author.platform_sub if author and author.platform_sub else None),
        },
        notify={
            "users": users,
            "title": f"Документ ждёт утверждения: {d.title}"[:200],
            "link": link,
        }
        if users
        else None,
    )


# ---------- Доставка ----------


Sender = Callable[[str, bytes, dict[str, str]], tuple[int, str]]


def http_sender(timeout: float) -> Sender:
    def send(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str]:
        r = httpx.post(url, content=body, headers=headers, timeout=timeout)
        return r.status_code, r.text[:300]

    return send


def _retry(row: OutboxEvent, now: datetime, error: str) -> None:
    row.attempts += 1
    row.last_error = error[:500]
    if row.attempts > len(RETRY_MINUTES):
        row.status = "dead"
    else:
        row.next_at = now + timedelta(minutes=RETRY_MINUTES[row.attempts - 1])


def deliver_due(
    session: Session, sender: Sender | None = None, now: datetime | None = None, limit: int = 50
) -> dict[str, int]:
    """Один проход доставки: отправляет созревшие записи outbox."""
    settings = get_settings()
    counts = {"delivered": 0, "rejected": 0, "retry": 0, "dead": 0}
    if not settings.outbox_enabled:
        return counts
    now = now or utcnow()
    send = sender or http_sender(settings.platform_timeout_seconds)
    rows = list(
        session.scalars(
            select(OutboxEvent)
            .where(OutboxEvent.status == "pending", OutboxEvent.next_at <= now)
            .order_by(OutboxEvent.created_at, OutboxEvent.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )
    for row in rows:
        body = row.body.encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-Platform-Product": settings.platform_product_id,
            "X-Event-Id": row.id,
            "X-Signature": sign(settings.events_secret, body),
        }
        try:
            code, text = send(settings.events_url, body, headers)
        except (httpx.HTTPError, OSError) as e:
            _retry(row, now, f"сеть: {e}")
        else:
            if 200 <= code < 300:
                row.status = "delivered"
                row.attempts += 1
                row.delivered_at = now
                row.last_error = None
            elif code == 422:
                row.status = "rejected"
                row.attempts += 1
                row.last_error = f"HTTP 422: {text}"[:500]
            elif code == 401:
                _retry(row, now, "HTTP 401: подпись не принята — проверьте PLATFORM_EVENTS_SECRET")
            else:
                _retry(row, now, f"HTTP {code}: {text}")
        if row.status == "delivered":
            counts["delivered"] += 1
        elif row.status == "rejected":
            counts["rejected"] += 1
        elif row.status == "dead":
            counts["dead"] += 1
        else:
            counts["retry"] += 1
        session.commit()
    return counts


class OutboxWorker:
    """Фоновый поток: раз в N секунд — показатели объектов и доставка outbox."""

    def __init__(self, session_factory: Callable[[], Session], interval: float):
        self._factory = session_factory
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="grc-outbox", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def tick(self) -> None:
        with self._factory() as session:
            scan_assessments(session)
        with self._factory() as session:
            deliver_due(session)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("outbox: проход доставки завершился ошибкой")
            self._stop.wait(self._interval)
