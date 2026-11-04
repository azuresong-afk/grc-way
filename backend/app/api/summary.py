"""Сводка проекта и быстрый поиск (задача 1.11).

- `GET /projects/{id}/summary` — показатели проекта и таблица объектов: класс,
  процент реализации (авто · вручную · всего), несоответствия, текущий снимок
  «Сканера», что ждёт подтверждения и что не сверено методистом. Проценты
  считаются теми же правилами, что и в наборе мер (app/domain/measures.py);
  процент проекта — сумма баллов всех объектов к сумме их знаменателей.
- `GET /search?q=` — для Ctrl+K и платформы: проекты, объекты, хосты и меры
  объектов, видимые пользователю. Сравнение без учёта регистра на стороне
  Python: SQLite не умеет lower() для кириллицы, а объёмы проекта небольшие.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DbSession, require
from app.api.measures import StatsOut
from app.api.objects import ClassBrief, current_classes
from app.api.projects import get_project_for
from app.api.szi import SziCounts, count_states, szi_states
from app.core.config import get_settings
from app.core.rbac import Perm
from app.db.models import (
    Adaptation,
    AssessedObject,
    Classification,
    ObjectHost,
    ObjectMeasure,
    ObjectSzi,
    Project,
    ProjectMember,
    RefClassificationTable,
    RefMeasure,
    ScannerSnapshot,
    User,
)
from app.domain.measures import Bucket, Item, Stats, compute_stats, effective_status
from app.domain.szi import CertState

router = APIRouter(tags=["summary"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]


# ---------- Схемы ----------


class SnapshotRef(BaseModel):
    id: uuid.UUID
    number: int
    run_id: int
    run_name: str | None
    run_finished_at: datetime | None
    imported_at: datetime
    # Пары «хост × модуль» прогона, которые не выполнены (покрытие неполное).
    coverage_gaps: int


class AdaptationRef(BaseModel):
    version: int
    status: str


class ObjectSummary(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    regime: str | None
    status: str
    host_count: int
    classification: ClassBrief | None
    # Классификация посчитана по таблице, не сверенной методистом.
    class_unverified: bool
    # no_regime | no_class | not_built | built — как у набора мер.
    state: str
    stats: StatsOut | None
    adaptation: AdaptationRef | None
    snapshot: SnapshotRef | None
    snapshots: int
    measures: int
    # Не реализовано или реализовано частично (по статусу для процента).
    nonconformities: int
    # Организационные меры, ещё не оценённые вручную.
    manual_pending: int
    # Оценены, но не подтверждены испытателем.
    to_confirm: int
    confirmed: int
    # Меры набора, сопоставление которых не сверено методистом.
    unverified: int
    # СЗИ объекта и состояние их сертификатов (задача 2.5).
    szi: SziCounts


class ProjectKpi(BaseModel):
    objects: int
    hosts: int
    # Объекты с собранным набором мер — только они входят в процент проекта.
    objects_assessed: int
    stats: StatsOut | None
    nonconformities: int
    manual_pending: int
    to_confirm: int
    confirmed: int
    unverified: int
    unverified_tables: list[str]
    szi: SziCounts
    szi_expiry_days: int


class SummaryOut(BaseModel):
    project_id: uuid.UUID
    name: str
    client: str
    partial_weight: float
    kpi: ProjectKpi
    objects: list[ObjectSummary]


SearchKind = Literal["project", "object", "host", "measure"]


class SearchItem(BaseModel):
    kind: SearchKind
    id: str
    title: str
    subtitle: str | None
    project_id: uuid.UUID
    # Маршрут SPA («/objects/…») и полный адрес в платформе (base_path + маршрут).
    path: str
    url: str


class SearchOut(BaseModel):
    q: str
    items: list[SearchItem]


# ---------- Сводка ----------


def _add(into: Bucket, b: Bucket) -> None:
    for f in (
        "total",
        "implemented",
        "partial",
        "not_implemented",
        "unassessed",
        "excluded",
        "not_applicable",
        "compensated",
    ):
        setattr(into, f, getattr(into, f) + getattr(b, f))
    into.score += b.score


def _stats_out(s: Stats) -> StatsOut:
    return StatsOut.model_validate(s.as_dict())


def _verified_refs(session: Session, profiles: set[str]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    if not profiles:
        return out
    rows = session.execute(
        select(RefMeasure.profile_id, RefMeasure.id).where(
            RefMeasure.profile_id.in_(profiles), RefMeasure.verified_at.is_not(None)
        )
    )
    for pid, mid in rows:
        out[pid].add(mid)
    return out


def project_summary(session: Session, project: Project, partial_weight: float) -> SummaryOut:
    objs = list(
        session.scalars(
            select(AssessedObject)
            .where(AssessedObject.project_id == project.id, AssessedObject.status == "active")
            .order_by(AssessedObject.name)
        )
    )
    ids = [o.id for o in objs]
    classes = current_classes(session, objs)

    measures: dict[uuid.UUID, list[ObjectMeasure]] = defaultdict(list)
    adaptations: dict[uuid.UUID, Adaptation] = {}
    snapshots: dict[uuid.UUID, list[ScannerSnapshot]] = defaultdict(list)
    class_rows: dict[uuid.UUID, Classification] = {}
    if ids:
        for m in session.scalars(
            select(ObjectMeasure)
            .where(ObjectMeasure.object_id.in_(ids))
            .order_by(ObjectMeasure.position, ObjectMeasure.measure_id)
        ):
            measures[m.object_id].append(m)
        for a in session.scalars(
            select(Adaptation).where(Adaptation.object_id.in_(ids)).order_by(Adaptation.version)
        ):
            adaptations[a.object_id] = a  # последняя версия
        for s in session.scalars(
            select(ScannerSnapshot)
            .where(ScannerSnapshot.object_id.in_(ids))
            .order_by(ScannerSnapshot.number.desc())
        ):
            snapshots[s.object_id].append(s)
        cls_ids = [c.id for c in classes.values()]
        if cls_ids:
            for c in session.scalars(select(Classification).where(Classification.id.in_(cls_ids))):
                class_rows[c.object_id] = c

    szi_rows: dict[uuid.UUID, list[CertState]] = defaultdict(list)
    if ids:
        all_szi = list(session.scalars(select(ObjectSzi).where(ObjectSzi.object_id.in_(ids))))
        for r, st in zip(all_szi, szi_states(session, all_szi), strict=True):
            szi_rows[r.object_id].append(st)

    verified = _verified_refs(session, {m.profile_id for ms in measures.values() for m in ms})

    total = Stats()
    rows: list[ObjectSummary] = []
    for o in objs:
        ms = measures.get(o.id, [])
        items = [
            Item(m.measure_id, m.method, m.status, m.adaptation, tuple(m.compensating_ids or ()))
            for m in ms
        ]
        by_id = {i.measure_id: i for i in items}
        stats = compute_stats(items, partial_weight) if ms else None
        if stats:
            _add(total.total, stats.total)
            _add(total.auto, stats.auto)
            _add(total.manual, stats.manual)
        eff = [effective_status(i, by_id) for i in items]
        cls = classes.get(o.id)
        a = adaptations.get(o.id)
        if o.regime is None:
            state = "no_regime"
        elif a is not None:
            state = "built"
        elif cls is not None and cls.status == "approved":
            state = "not_built"
        else:
            state = "no_class"
        snaps = snapshots.get(o.id, [])
        cur = snaps[0] if snaps else None
        crow = class_rows.get(o.id)
        rows.append(
            ObjectSummary(
                id=o.id,
                name=o.name,
                kind=o.kind,
                regime=o.regime,
                status=o.status,
                host_count=len(o.hosts),
                classification=cls,
                class_unverified=bool(crow and not crow.table_verified),
                state=state,
                stats=_stats_out(stats) if stats else None,
                adaptation=AdaptationRef(version=a.version, status=a.status) if a else None,
                snapshot=SnapshotRef(
                    id=cur.id,
                    number=cur.number,
                    run_id=cur.run_id,
                    run_name=cur.run_name,
                    run_finished_at=cur.run_finished_at,
                    imported_at=cur.imported_at,
                    coverage_gaps=int(((cur.coverage or {}).get("summary") or {}).get("gaps") or 0),
                )
                if cur
                else None,
                snapshots=len(snaps),
                measures=len(ms),
                nonconformities=sum(1 for s in eff if s in ("not_implemented", "partial")),
                manual_pending=sum(
                    1
                    for m, s in zip(ms, eff, strict=True)
                    if m.method == "manual" and s == "unassessed" and m.adaptation == "none"
                ),
                to_confirm=sum(
                    1
                    for m in ms
                    if m.confirmed_at is None
                    and m.status != "unassessed"
                    and m.adaptation != "excluded"
                ),
                confirmed=sum(1 for m in ms if m.confirmed_at is not None),
                unverified=sum(
                    1
                    for m in ms
                    if m.adaptation != "excluded"
                    and m.measure_id not in verified.get(m.profile_id, set())
                ),
                szi=count_states(szi_rows.get(o.id, [])),
            )
        )

    # Таблицы классификации действующих режимов, не сверенные методистом.
    regimes = {o.regime for o in objs if o.regime}
    tables = (
        session.scalars(
            select(RefClassificationTable.regime).where(
                RefClassificationTable.regime.in_(regimes),
                RefClassificationTable.verified_at.is_(None),
            )
        ).all()
        if regimes
        else []
    )
    built = [r for r in rows if r.stats]
    return SummaryOut(
        project_id=project.id,
        name=project.name,
        client=project.customer.name,
        partial_weight=partial_weight,
        kpi=ProjectKpi(
            objects=len(objs),
            hosts=sum(r.host_count for r in rows),
            objects_assessed=len(built),
            stats=_stats_out(total) if built else None,
            nonconformities=sum(r.nonconformities for r in rows),
            manual_pending=sum(r.manual_pending for r in rows),
            to_confirm=sum(r.to_confirm for r in rows),
            confirmed=sum(r.confirmed for r in rows),
            unverified=sum(r.unverified for r in rows),
            unverified_tables=sorted(tables),
            szi=count_states([st for sts in szi_rows.values() for st in sts]),
            szi_expiry_days=get_settings().szi_expiry_days,
        ),
        objects=rows,
    )


@router.get("/projects/{project_id}/summary", response_model=SummaryOut)
def summary(project_id: uuid.UUID, user: Viewer, session: DbSession) -> SummaryOut:
    project = get_project_for(session, project_id, user)
    return project_summary(session, project, get_settings().partial_weight)


# ---------- Поиск ----------

PER_KIND = 8


def _fold(s: str | None) -> str:
    return (s or "").casefold().replace("ё", "е")


def _hit(needle: str, *fields: str | None) -> int | None:
    """Ранг совпадения: 0 — поле совпало целиком, 1 — с начала, 2 — внутри."""
    best: int | None = None
    for f in fields:
        v = _fold(f)
        if not v or needle not in v:
            continue
        rank = 0 if v == needle else 1 if v.startswith(needle) else 2
        best = rank if best is None else min(best, rank)
    return best


@router.get("/search", response_model=SearchOut)
def search(
    user: Viewer,
    session: DbSession,
    q: Annotated[str, Query(max_length=200)] = "",
    project_id: uuid.UUID | None = None,
) -> SearchOut:
    text = q.strip()
    needle = _fold(text)
    if len(needle) < 2:
        return SearchOut(q=text, items=[])
    base = get_settings().base_path.rstrip("/")
    visible = select(ProjectMember.project_id).where(ProjectMember.user_id == user.id)
    stmt = select(Project).where(Project.id.in_(visible))
    if project_id is not None:
        stmt = stmt.where(Project.id == project_id)
    projects = {p.id: p for p in session.scalars(stmt)}
    if not projects:
        return SearchOut(q=text, items=[])

    found: dict[str, list[tuple[int, str, SearchItem]]] = defaultdict(list)

    def add(rank: int, kind: SearchKind, sort: str, item: dict) -> None:
        path = item.pop("path")
        found[kind].append((rank, sort, SearchItem(kind=kind, path=path, url=base + path, **item)))

    for p in projects.values():
        rank = _hit(needle, p.name, p.customer.name, p.contract_ref)
        if rank is not None:
            add(
                rank,
                "project",
                p.name,
                {
                    "id": str(p.id),
                    "title": p.name,
                    "subtitle": p.customer.name,
                    "project_id": p.id,
                    "path": f"/projects/{p.id}",
                },
            )

    objs = {
        o.id: o
        for o in session.scalars(
            select(AssessedObject).where(AssessedObject.project_id.in_(projects))
        )
    }
    for o in objs.values():
        rank = _hit(needle, o.name)
        if rank is not None:
            p = projects[o.project_id]
            add(
                rank,
                "object",
                o.name,
                {
                    "id": str(o.id),
                    "title": o.name,
                    "subtitle": p.name + (" · в архиве" if o.status == "archived" else ""),
                    "project_id": o.project_id,
                    "path": f"/objects/{o.id}?project={o.project_id}",
                },
            )

    if objs:
        for h in session.scalars(select(ObjectHost).where(ObjectHost.object_id.in_(objs))):
            rank = _hit(needle, h.address, h.hostname)
            if rank is None:
                continue
            o = objs[h.object_id]
            add(
                rank,
                "host",
                h.address,
                {
                    "id": str(h.id),
                    "title": h.address + (f" · {h.hostname}" if h.hostname else ""),
                    "subtitle": o.name + (f" · {h.role}" if h.role else ""),
                    "project_id": o.project_id,
                    "path": f"/objects/{o.id}?project={o.project_id}&tab=composition",
                },
            )

        active = [oid for oid, o in objs.items() if o.status == "active"]
        rows = (
            session.scalars(select(ObjectMeasure).where(ObjectMeasure.object_id.in_(active)))
            if active
            else []
        )
        for m in rows:
            rank = _hit(needle, m.measure_id, m.title)
            if rank is None:
                continue
            o = objs[m.object_id]
            add(
                rank,
                "measure",
                f"{o.name}\x00{m.position:05d}",
                {
                    "id": str(m.id),
                    "title": f"{m.measure_id} · {m.title}",
                    "subtitle": o.name,
                    "project_id": o.project_id,
                    "path": (f"/objects/{o.id}?project={o.project_id}&tab=measures&measure={m.id}"),
                },
            )

    items: list[SearchItem] = []
    for kind in ("project", "object", "host", "measure"):
        hits = sorted(found.get(kind, []), key=lambda t: (t[0], t[1]))
        items.extend(h[2] for h in hits[:PER_KIND])
    return SearchOut(q=text, items=items)
