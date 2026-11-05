"""Объекты проекта: описание, сегменты, хосты (вручную и из активов «Сканера»).

Хост объекта сопоставляется с активом «Сканера» по ключу (проект, адрес):
проект «Аттестации» связан с engagement «Сканера» (`projects.scanner_engagement_id`),
адрес — IP в каноническом виде, как `host_key` «Сканера».
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.projects import get_project_for
from app.api.refs_sync import _scanner_error
from app.core.rbac import Perm
from app.db.models import (
    AssessedObject,
    Classification,
    ObjectHost,
    ObjectSegment,
    Project,
    RefVulnMethodology,
    User,
    utcnow,
)
from app.domain.vuln_criticality import InputError, MethodologyError
from app.domain.vuln_inventory import normalize_types
from app.integrations.scanner.client import ScannerClient, ScannerError, get_scanner_client
from app.integrations.scanner.schemas import ScannerAsset

router = APIRouter(tags=["objects"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Editor = Annotated[User, Depends(require(Perm.OBJECTS_EDIT))]
Scanner = Annotated[ScannerClient, Depends(get_scanner_client)]

Kind = Literal["gis", "ispdn", "kii", "other"]
Regime = Literal["117", "21", "239"]

# Режим по умолчанию для вида объекта (ТЗ: №117 — ГИС, №21 — ПДн, №239 — КИИ).
DEFAULT_REGIME: dict[str, str | None] = {"gis": "117", "ispdn": "21", "kii": "239", "other": None}

# В журнал — не больше стольких адресов на одно изменение, остальное — счётчиком.
_AUDIT_ADDRESSES = 50


# ---------- Схемы ----------


class Responsible(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    position: str | None = Field(default=None, max_length=200)
    role: str | None = Field(default=None, max_length=200)
    phone: str | None = Field(default=None, max_length=50)
    email: str | None = Field(default=None, max_length=200)


class Interconnection(BaseModel):
    system: str = Field(min_length=1, max_length=300)
    owner: str | None = Field(default=None, max_length=300)
    direction: Literal["in", "out", "both"] = "both"
    channel: str | None = Field(default=None, max_length=300)
    description: str | None = Field(default=None, max_length=2000)


class ObjectIn(BaseModel):
    kind: Kind
    name: str = Field(min_length=1, max_length=300)
    regime: Regime | None = None
    purpose: str | None = Field(default=None, max_length=4000)
    boundaries: str | None = Field(default=None, max_length=4000)
    interconnections: list[Interconnection] = Field(default_factory=list, max_length=100)
    internet: bool = False
    responsible: list[Responsible] = Field(default_factory=list, max_length=50)


class ObjectPatch(BaseModel):
    kind: Kind | None = None
    name: str | None = Field(default=None, min_length=1, max_length=300)
    regime: Regime | None = None
    purpose: str | None = Field(default=None, max_length=4000)
    boundaries: str | None = Field(default=None, max_length=4000)
    interconnections: list[Interconnection] | None = Field(default=None, max_length=100)
    internet: bool | None = None
    responsible: list[Responsible] | None = Field(default=None, max_length=50)
    status: Literal["active", "archived"] | None = None


class SegmentOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    scanner_group: str | None
    host_count: int


class ClassBrief(BaseModel):
    """Текущая классификация объекта: утверждённая или (если её нет) черновик."""

    id: uuid.UUID
    result: str
    # Короткая подпись для списков (К2, УЗ3, Кат. 2).
    short: str
    result_label: str
    status: str


class ObjectBrief(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    kind: str
    name: str
    regime: str | None
    status: str
    internet: bool
    host_count: int
    segment_count: int
    updated_at: datetime
    classification: ClassBrief | None = None


class ObjectOut(ObjectBrief):
    purpose: str | None
    boundaries: str | None
    interconnections: list[Interconnection]
    responsible: list[Responsible]
    created_at: datetime
    scanner_synced_at: datetime | None
    scanner_engagement_id: int | None
    segments: list[SegmentOut]


class SegmentIn(BaseModel):
    id: uuid.UUID | None = None
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    scanner_group: str | None = Field(default=None, max_length=200)


class SegmentsIn(BaseModel):
    items: list[SegmentIn] = Field(max_length=200)


def _canonical(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError as e:
        raise ValueError(f"«{raw.strip()[:64]}» — не IP-адрес") from e


class HostIn(BaseModel):
    address: str = Field(min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    role: str | None = Field(default=None, max_length=300)
    segment_id: uuid.UUID | None = None
    # Инвентаризация для I_infr (задача 2.7). Поле не передано — значение хоста не
    # меняется; null — «не указано».
    component_types: list[str] | None = Field(default=None, max_length=20)
    internet_exposed: bool | None = None

    @field_validator("address")
    @classmethod
    def _address(cls, v: str) -> str:
        return _canonical(v)


class HostsIn(BaseModel):
    items: list[HostIn] = Field(max_length=5000)


class HostOut(BaseModel):
    id: uuid.UUID
    address: str
    hostname: str | None
    role: str | None
    segment_id: uuid.UUID | None
    os: str | None
    os_family: str | None
    source: str
    scanner_asset_id: int | None
    scanner_groups: list[str]
    criticality: str | None
    owner: str | None
    last_seen_at: datetime | None
    scanner_missing: bool
    synced_at: datetime | None
    component_types: list[str] | None
    internet_exposed: bool | None


class AssetOut(BaseModel):
    id: int
    address: str
    hostname: str | None
    os: str | None
    os_family: str | None
    criticality: str | None
    owner: str | None
    groups: list[str]
    last_seen_at: datetime | None
    # Уже в составе этого объекта / других объектов проекта (названия).
    in_object: bool
    other_objects: list[str]


class AssetsOut(BaseModel):
    engagement_id: int
    mode: str
    source: str
    assets: list[AssetOut]


class SyncIn(BaseModel):
    # Адреса активов, которые добавить в состав. Пусто — только обновить уже связанные.
    addresses: list[str] = Field(default_factory=list, max_length=5000)
    # Создавать сегменты по группам активов «Сканера» для добавляемых хостов.
    segments_from_groups: bool = True

    @field_validator("addresses")
    @classmethod
    def _addresses(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(_canonical(a) for a in v))


class SyncOut(BaseModel):
    added: list[str]
    updated: list[str]
    linked: list[str]
    missing: list[str]
    segments_created: list[str]
    hosts: list[HostOut]


# ---------- Общее ----------


def _not_found() -> HTTPException:
    return HTTPException(404, detail="Объект не найден")


def get_object_for(session: Session, object_id: uuid.UUID, user: User) -> AssessedObject:
    """Объект, если пользователь — участник его проекта; иначе 404 (не раскрываем)."""
    obj = session.get(AssessedObject, object_id)
    if obj is None:
        raise _not_found()
    try:
        get_project_for(session, obj.project_id, user)
    except HTTPException as e:
        raise _not_found() from e
    return obj


def _editable(session: Session, obj: AssessedObject) -> Project:
    project = session.get(Project, obj.project_id)
    assert project is not None  # noqa: S101 — внешний ключ
    if project.status != "active":
        raise HTTPException(409, detail="Проект в архиве: объекты только для просмотра")
    if obj.status != "active":
        raise HTTPException(409, detail="Объект в архиве: верните его, чтобы менять")
    return project


def _check_regime(kind: str, regime: str | None) -> None:
    if kind != "other" and regime is None:
        raise HTTPException(422, detail="Для ГИС, ИСПДн и КИИ нужен нормативный режим")


def _segment_out(obj: AssessedObject, s: ObjectSegment) -> SegmentOut:
    return SegmentOut(
        id=s.id,
        name=s.name,
        description=s.description,
        scanner_group=s.scanner_group,
        host_count=sum(1 for h in obj.hosts if h.segment_id == s.id),
    )


def current_classes(session: Session, objs: list[AssessedObject]) -> dict[uuid.UUID, ClassBrief]:
    """Утверждённая классификация по текущему режиму объекта, иначе последний черновик."""
    if not objs:
        return {}
    regime = {o.id: o.regime for o in objs}
    rows = session.scalars(
        select(Classification)
        .where(
            Classification.object_id.in_(regime),
            Classification.status.in_(("approved", "draft")),
        )
        .order_by(Classification.created_at.desc())
    )
    out: dict[uuid.UUID, ClassBrief] = {}
    for c in rows:
        if c.regime != regime[c.object_id]:
            continue
        have = out.get(c.object_id)
        if have is None or (have.status == "draft" and c.status == "approved"):
            values = (c.table_snapshot.get("result") or {}).get("values") or []
            short = next((v.get("short") for v in values if str(v["value"]) == c.result), None)
            out[c.object_id] = ClassBrief(
                id=c.id,
                result=c.result,
                short=short or c.result,
                result_label=c.result_label,
                status=c.status,
            )
    return out


def _brief(obj: AssessedObject, cls: ClassBrief | None = None) -> ObjectBrief:
    return ObjectBrief(
        id=obj.id,
        project_id=obj.project_id,
        kind=obj.kind,
        name=obj.name,
        regime=obj.regime,
        status=obj.status,
        internet=obj.internet,
        host_count=len(obj.hosts),
        segment_count=len(obj.segments),
        updated_at=obj.updated_at,
        classification=cls,
    )


def _out(session: Session, obj: AssessedObject) -> ObjectOut:
    project = session.get(Project, obj.project_id)
    return ObjectOut(
        **_brief(obj, current_classes(session, [obj]).get(obj.id)).model_dump(),
        purpose=obj.purpose,
        boundaries=obj.boundaries,
        interconnections=[Interconnection(**x) for x in obj.interconnections],
        responsible=[Responsible(**x) for x in obj.responsible],
        created_at=obj.created_at,
        scanner_synced_at=obj.scanner_synced_at,
        scanner_engagement_id=project.scanner_engagement_id if project else None,
        segments=[_segment_out(obj, s) for s in obj.segments],
    )


def _host_out(h: ObjectHost) -> HostOut:
    return HostOut(
        id=h.id,
        address=h.address,
        hostname=h.hostname,
        role=h.role,
        segment_id=h.segment_id,
        os=h.os,
        os_family=h.os_family,
        source=h.source,
        scanner_asset_id=h.scanner_asset_id,
        scanner_groups=list(h.scanner_groups or []),
        criticality=h.criticality,
        owner=h.owner,
        last_seen_at=h.last_seen_at,
        scanner_missing=h.scanner_missing,
        synced_at=h.synced_at,
        component_types=list(h.component_types) if h.component_types else None,
        internet_exposed=h.internet_exposed,
    )


def _sort_key(address: str) -> tuple[int, int]:
    ip = ipaddress.ip_address(address)
    return (ip.version, int(ip))


def _hosts_out(obj: AssessedObject) -> list[HostOut]:
    return [_host_out(h) for h in sorted(obj.hosts, key=lambda h: _sort_key(h.address))]


# Методика, по которой у хостов задаётся тип компонента (значения её показателя K).
INVENTORY_METHODOLOGY = "fstec-2025"


def inventory_definition(session: Session) -> dict:
    m = session.get(RefVulnMethodology, INVENTORY_METHODOLOGY)
    if m is None:
        raise HTTPException(
            409, detail="Справочник Методики оценки критичности уязвимостей не загружен"
        )
    return m.definition


def _sample(addresses: list[str]) -> dict[str, object]:
    return {"count": len(addresses), "addresses": addresses[:_AUDIT_ADDRESSES]}


def _touch(obj: AssessedObject, user: User) -> None:
    obj.updated_at = utcnow()
    obj.updated_by = user.id


# ---------- Объекты ----------


@router.get("/projects/{project_id}/objects", response_model=list[ObjectBrief])
def list_objects(
    project_id: uuid.UUID,
    user: Viewer,
    session: DbSession,
    response: Response,
    status_: Annotated[str | None, Query(alias="status", pattern=r"^(active|archived)$")] = None,
    kind: Kind | None = None,
    q: str | None = Query(default=None, max_length=200),
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ObjectBrief]:
    get_project_for(session, project_id, user)
    stmt = select(AssessedObject).where(AssessedObject.project_id == project_id)
    if status_:
        stmt = stmt.where(AssessedObject.status == status_)
    if kind:
        stmt = stmt.where(AssessedObject.kind == kind)
    if q:
        like = q.lower()
        stmt = stmt.where(
            or_(
                func.lower(AssessedObject.name).contains(like),
                AssessedObject.id.in_(
                    select(ObjectHost.object_id).where(
                        or_(
                            ObjectHost.address.startswith(q.strip()),
                            func.lower(ObjectHost.hostname).contains(like),
                        )
                    )
                ),
            )
        )
    response.headers["X-Total-Count"] = str(
        session.scalar(select(func.count()).select_from(stmt.subquery()))
    )
    rows = list(session.scalars(stmt.order_by(AssessedObject.name).limit(limit).offset(offset)))
    classes = current_classes(session, rows)
    return [_brief(o, classes.get(o.id)) for o in rows]


@router.post("/projects/{project_id}/objects", response_model=ObjectOut, status_code=201)
def create_object(
    project_id: uuid.UUID, body: ObjectIn, request: Request, user: Editor, session: DbSession
) -> ObjectOut:
    project = get_project_for(session, project_id, user)
    if project.status != "active":
        raise HTTPException(409, detail="Проект в архиве: объекты только для просмотра")
    data = body.model_dump()
    if "regime" not in body.model_fields_set:
        data["regime"] = DEFAULT_REGIME[body.kind]
    _check_regime(data["kind"], data["regime"])
    obj = AssessedObject(
        **data, project_id=project.id, created_by=user.id, updated_by=user.id, status="active"
    )
    session.add(obj)
    session.flush()
    audit.record(
        session,
        action="object.create",
        actor=user,
        entity="object",
        entity_id=obj.id,
        project_id=project.id,
        ip=client_ip(request),
        details={"name": obj.name, "kind": obj.kind, "regime": obj.regime},
    )
    session.commit()
    session.refresh(obj)
    return _out(session, obj)


@router.get("/objects/{object_id}", response_model=ObjectOut)
def get_object(object_id: uuid.UUID, user: Viewer, session: DbSession) -> ObjectOut:
    return _out(session, get_object_for(session, object_id, user))


@router.patch("/objects/{object_id}", response_model=ObjectOut)
def update_object(
    object_id: uuid.UUID, body: ObjectPatch, request: Request, user: Editor, session: DbSession
) -> ObjectOut:
    obj = get_object_for(session, object_id, user)
    data = body.model_dump(exclude_unset=True)
    restoring = data.get("status") == "active" and obj.status == "archived"
    if not restoring:
        project = session.get(Project, obj.project_id)
        if project is not None and project.status != "active":
            raise HTTPException(409, detail="Проект в архиве: объекты только для просмотра")
        if obj.status != "active" and set(data) - {"status"}:
            raise HTTPException(409, detail="Объект в архиве: верните его, чтобы менять")
    for key in ("kind", "name", "internet"):
        if key in data and data[key] is None:
            raise HTTPException(422, detail="Поле не может быть пустым")
    if "kind" in data and "regime" not in data and data["kind"] != obj.kind:
        data["regime"] = DEFAULT_REGIME[data["kind"]]
    _check_regime(data.get("kind", obj.kind), data.get("regime", obj.regime))
    changes: dict[str, object] = {}
    for k, v in data.items():
        if getattr(obj, k) != v:
            changes[k] = v
            setattr(obj, k, v)
    if changes:
        _touch(obj, user)
        action = {"archived": "object.archive", "active": "object.restore"}.get(
            str(changes.get("status")), "object.update"
        )
        audit.record(
            session,
            action=action,
            actor=user,
            entity="object",
            entity_id=obj.id,
            project_id=obj.project_id,
            ip=client_ip(request),
            # Тексты описания — только имена полей, чтобы журнал не разрастался.
            details={
                "fields": sorted(changes),
                **{
                    k: changes[k]
                    for k in ("kind", "regime", "name", "internet", "status")
                    if k in changes
                },
            },
        )
        session.commit()
    return _out(session, obj)


# ---------- Сегменты ----------


@router.get("/objects/{object_id}/segments", response_model=list[SegmentOut])
def list_segments(object_id: uuid.UUID, user: Viewer, session: DbSession) -> list[SegmentOut]:
    obj = get_object_for(session, object_id, user)
    return [_segment_out(obj, s) for s in obj.segments]


@router.put("/objects/{object_id}/segments", response_model=list[SegmentOut])
def put_segments(
    object_id: uuid.UUID, body: SegmentsIn, request: Request, user: Editor, session: DbSession
) -> list[SegmentOut]:
    """Заменяет список сегментов. Хосты удалённого сегмента остаются без сегмента."""
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    names = [s.name.strip().lower() for s in body.items]
    if len(names) != len(set(names)):
        raise HTTPException(422, detail="Названия сегментов повторяются")
    groups = [s.scanner_group.strip() for s in body.items if s.scanner_group]
    if len(groups) != len(set(groups)):
        raise HTTPException(422, detail="Одна группа «Сканера» привязана к двум сегментам")
    existing = {s.id: s for s in obj.segments}
    unknown = [s.id for s in body.items if s.id is not None and s.id not in existing]
    if unknown:
        raise HTTPException(422, detail="Сегмент не найден")

    kept: list[ObjectSegment] = []
    added, renamed = [], []
    for pos, item in enumerate(body.items):
        seg = existing.get(item.id) if item.id else None
        if seg is None:
            seg = ObjectSegment(object_id=obj.id)
            added.append(item.name)
        elif seg.name != item.name:
            renamed.append(f"{seg.name} → {item.name}")
        seg.name = item.name.strip()
        seg.description = item.description or None
        seg.scanner_group = (item.scanner_group or "").strip() or None
        seg.position = pos
        kept.append(seg)
    keep_ids = {s.id for s in kept if s.id is not None}
    removed = [s for s in obj.segments if s.id not in keep_ids]
    for h in obj.hosts:
        if h.segment_id in {s.id for s in removed}:
            h.segment_id = None
    obj.segments = kept
    _touch(obj, user)
    session.flush()
    audit.record(
        session,
        action="object.segments",
        actor=user,
        entity="object",
        entity_id=obj.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "added": added,
            "renamed": renamed,
            "removed": [s.name for s in removed],
            "total": len(kept),
        },
    )
    session.commit()
    session.refresh(obj)
    return [_segment_out(obj, s) for s in obj.segments]


# ---------- Хосты ----------


@router.get("/objects/{object_id}/hosts", response_model=list[HostOut])
def list_hosts(object_id: uuid.UUID, user: Viewer, session: DbSession) -> list[HostOut]:
    return _hosts_out(get_object_for(session, object_id, user))


@router.put("/objects/{object_id}/hosts", response_model=list[HostOut])
def put_hosts(
    object_id: uuid.UUID, body: HostsIn, request: Request, user: Editor, session: DbSession
) -> list[HostOut]:
    """Заменяет состав хостов. Для уже известных адресов данные «Сканера» сохраняются;
    новые адреса добавляются как ручные. Тип компонента и доступность из
    «Интернета» меняются, только если переданы."""
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    definition = None
    if any(h.component_types for h in body.items):
        definition = inventory_definition(session)
    for item in body.items:
        if "component_types" in item.model_fields_set and item.component_types:
            try:
                item.component_types = normalize_types(definition or {}, item.component_types)
            except (InputError, MethodologyError) as e:
                raise HTTPException(422, detail=f"{item.address}: {e}") from e
    addresses = [h.address for h in body.items]
    if dupes := sorted({a for a in addresses if addresses.count(a) > 1}, key=_sort_key):
        raise HTTPException(422, detail=f"Адрес указан дважды: {', '.join(dupes[:5])}")
    segment_ids = {s.id for s in obj.segments}
    if any(h.segment_id is not None and h.segment_id not in segment_ids for h in body.items):
        raise HTTPException(422, detail="Сегмент не найден в этом объекте")

    by_address = {h.address: h for h in obj.hosts}
    added, changed = [], []
    hosts: list[ObjectHost] = []
    for item in body.items:
        host = by_address.get(item.address)
        if host is None:
            host = ObjectHost(
                object_id=obj.id,
                project_id=obj.project_id,
                address=item.address,
                source="manual",
                scanner_groups=[],
                scanner_missing=False,
            )
            added.append(item.address)
        types = (
            (item.component_types or None)
            if "component_types" in item.model_fields_set
            else host.component_types or None
        )
        exposed = (
            item.internet_exposed
            if "internet_exposed" in item.model_fields_set
            else host.internet_exposed
        )
        if host.id is not None and (
            host.hostname,
            host.role,
            host.segment_id,
            host.component_types or None,
            host.internet_exposed,
        ) != (item.hostname or None, item.role or None, item.segment_id, types, exposed):
            changed.append(item.address)
        host.hostname = (item.hostname or "").strip() or None
        host.role = (item.role or "").strip() or None
        host.segment_id = item.segment_id
        host.component_types = types
        host.internet_exposed = exposed
        hosts.append(host)
    removed = sorted(set(by_address) - set(addresses), key=_sort_key)
    if not (added or changed or removed):
        return _hosts_out(obj)
    obj.hosts = hosts
    _touch(obj, user)
    audit.record(
        session,
        action="object.hosts",
        actor=user,
        entity="object",
        entity_id=obj.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "added": _sample(added),
            "removed": _sample(removed),
            "changed": _sample(changed),
            "total": len(hosts),
        },
    )
    session.commit()
    session.refresh(obj)
    return _hosts_out(obj)


# ---------- Активы «Сканера» ----------


def _engagement(session: Session, obj: AssessedObject) -> int:
    project = session.get(Project, obj.project_id)
    if project is None or project.scanner_engagement_id is None:
        raise HTTPException(
            409,
            detail="Проект не связан со «Сканером»: укажите номер engagement в карточке проекта",
            headers={"X-Error-Code": "scanner_not_linked"},
        )
    return project.scanner_engagement_id


def _source(scanner: ScannerClient) -> str:
    """Откуда активы: адрес «Сканера» или файл фикстуры (не профилей)."""
    if scanner.mode == "fixture":
        return "фикстура fixtures/engagement_assets.json"
    return scanner.source


def _fetch_assets(scanner: ScannerClient, engagement_id: int) -> dict[str, ScannerAsset]:
    out: dict[str, ScannerAsset] = {}
    for a in scanner.assets(engagement_id):
        try:
            out[_canonical(a.address)] = a
        except ValueError:
            continue  # «Сканер» хранит только IP; иное пропускаем
    return out


@router.get("/objects/{object_id}/scanner/assets", response_model=AssetsOut)
def scanner_assets(
    object_id: uuid.UUID, user: Viewer, session: DbSession, scanner: Scanner
) -> AssetsOut:
    """Активы engagement проекта: что уже в составе этого и других объектов."""
    obj = get_object_for(session, object_id, user)
    engagement_id = _engagement(session, obj)
    try:
        assets = _fetch_assets(scanner, engagement_id)
    except ScannerError as e:
        raise _scanner_error(e) from e
    elsewhere: dict[str, list[str]] = {}
    rows = session.execute(
        select(ObjectHost.address, AssessedObject.name)
        .join(AssessedObject, AssessedObject.id == ObjectHost.object_id)
        .where(ObjectHost.project_id == obj.project_id, ObjectHost.object_id != obj.id)
        .order_by(AssessedObject.name)
    )
    for address, name in rows:
        elsewhere.setdefault(address, []).append(name)
    mine = {h.address for h in obj.hosts}
    return AssetsOut(
        engagement_id=engagement_id,
        mode=scanner.mode,
        source=_source(scanner),
        assets=[
            AssetOut(
                id=a.id,
                address=addr,
                hostname=a.hostname,
                os=a.os_guess,
                os_family=a.os_family,
                criticality=a.criticality,
                owner=a.owner,
                groups=[g.name for g in a.groups],
                last_seen_at=a.last_seen_at,
                in_object=addr in mine,
                other_objects=elsewhere.get(addr, []),
            )
            for addr, a in sorted(assets.items(), key=lambda kv: _sort_key(kv[0]))
        ],
    )


def _apply_asset(host: ObjectHost, asset: ScannerAsset, now: datetime) -> None:
    """Поля, за которые отвечает «Сканер». Роль и сегмент — наши, их не трогаем."""
    host.scanner_asset_id = asset.id
    host.os = asset.os_guess
    host.os_family = asset.os_family
    host.scanner_groups = [g.name for g in asset.groups]
    host.criticality = asset.criticality
    host.owner = asset.owner
    host.last_seen_at = asset.last_seen_at
    host.scanner_missing = False
    host.synced_at = now
    if not host.hostname and asset.hostname:
        host.hostname = asset.hostname


@router.post("/objects/{object_id}/hosts/sync-from-scanner", response_model=SyncOut)
def sync_from_scanner(
    object_id: uuid.UUID,
    body: SyncIn,
    request: Request,
    user: Editor,
    session: DbSession,
    scanner: Scanner,
) -> SyncOut:
    """Обновляет хосты объекта по активам «Сканера» и добавляет выбранные адреса.

    Сопоставление — по (проект, адрес): хост с тем же адресом, добавленный вручную,
    связывается с активом; хост, которого больше нет среди активов, остаётся в составе
    с пометкой «нет в «Сканере»» — решение об исключении принимает методист.
    """
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    engagement_id = _engagement(session, obj)
    try:
        assets = _fetch_assets(scanner, engagement_id)
    except ScannerError as e:
        audit.record_now(
            session,
            action="object.hosts.sync",
            actor=user,
            entity="object",
            entity_id=obj.id,
            project_id=obj.project_id,
            result="error",
            ip=client_ip(request),
            details={"source": _source(scanner), "code": e.code, "error": str(e)},
        )
        raise _scanner_error(e) from e
    if absent := [a for a in body.addresses if a not in assets]:
        raise HTTPException(422, detail=f"Нет среди активов «Сканера»: {', '.join(absent[:5])}")

    now = utcnow()
    by_address = {h.address: h for h in obj.hosts}
    updated, linked, missing = [], [], []
    for address, host in by_address.items():
        asset = assets.get(address)
        if asset is None:
            if host.scanner_asset_id is not None and not host.scanner_missing:
                missing.append(address)
            if host.scanner_asset_id is not None:
                host.scanner_missing = True
                host.synced_at = now
            continue
        if host.scanner_asset_id is None:
            linked.append(address)
        else:
            updated.append(address)
        _apply_asset(host, asset, now)

    by_group = {s.scanner_group: s for s in obj.segments if s.scanner_group}
    segments_created: list[str] = []
    added: list[str] = []
    for address in body.addresses:
        if address in by_address:
            continue
        asset = assets[address]
        host = ObjectHost(
            object_id=obj.id,
            project_id=obj.project_id,
            address=address,
            hostname=asset.hostname,
            source="scanner",
        )
        _apply_asset(host, asset, now)
        for g in asset.groups:
            seg = by_group.get(g.name)
            if seg is None and body.segments_from_groups:
                seg = ObjectSegment(
                    object_id=obj.id,
                    name=_free_name(obj, g.name),
                    scanner_group=g.name,
                    position=len(obj.segments),
                )
                obj.segments.append(seg)
                session.flush()
                by_group[g.name] = seg
                segments_created.append(seg.name)
            if seg is not None:
                host.segment_id = seg.id
                break
        obj.hosts.append(host)
        added.append(address)

    obj.scanner_synced_at = now
    _touch(obj, user)
    audit.record(
        session,
        action="object.hosts.sync",
        actor=user,
        entity="object",
        entity_id=obj.id,
        project_id=obj.project_id,
        ip=client_ip(request),
        details={
            "source": _source(scanner),
            "engagement_id": engagement_id,
            "added": _sample(added),
            "updated": len(updated),
            "linked": _sample(linked),
            "missing": _sample(missing),
            "segments_created": segments_created,
        },
    )
    session.commit()
    session.refresh(obj)
    key = _sort_key
    return SyncOut(
        added=sorted(added, key=key),
        updated=sorted(updated, key=key),
        linked=sorted(linked, key=key),
        missing=sorted(missing, key=key),
        segments_created=segments_created,
        hosts=_hosts_out(obj),
    )


def _free_name(obj: AssessedObject, name: str) -> str:
    """Название сегмента по группе; если такое уже занято вручную — с пометкой."""
    taken = {s.name.lower() for s in obj.segments}
    if name.lower() not in taken:
        return name
    return f"{name} (группа «Сканера»)"
