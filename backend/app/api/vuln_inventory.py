"""Инвентаризация объекта для показателя I_infr (Методика 2025, задача 2.7).

GET  /objects/{id}/inventory — готовность: сколько хостов каждого типа, у каких
     хостов не указан тип или доступность из сети «Интернет».
POST /objects/{id}/inventory/infr — значения K, L, P и I_infr для набора уязвимых
     хостов; ничего не сохраняет. Если данных не хватает — что именно и у каких
     хостов. Реестр уязвимостей объекта (задача 2.8) берёт значения отсюда же.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.api.deps import DbSession, require
from app.api.objects import INVENTORY_METHODOLOGY, _canonical, _sort_key, get_object_for
from app.core.rbac import Perm
from app.db.models import AssessedObject, RefVulnMethodology, User
from app.domain.vuln_criticality import InputError, MethodologyError
from app.domain.vuln_inventory import HostData, component_types, infrastructure, readiness

router = APIRouter(tags=["objects"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]


class MethodologyRef(BaseModel):
    id: str
    version: str
    revision: int
    verified: bool


class ComponentType(BaseModel):
    code: str
    short: str
    title: str
    score: float
    total: int
    internet: int


class InventoryOut(BaseModel):
    methodology: MethodologyRef
    hosts_total: int
    ready: bool
    missing_type: list[str]
    missing_internet: list[str]
    # Хосты отмечены доступными из «Интернета», а объект — нет (карточка объекта).
    internet_conflict: list[str]
    types: list[ComponentType]


class InfrIn(BaseModel):
    addresses: list[str] = Field(min_length=1, max_length=5000)

    @field_validator("addresses")
    @classmethod
    def _addresses(cls, v: list[str]) -> list[str]:
        return list(dict.fromkeys(_canonical(a) for a in v))


class InfrOut(BaseModel):
    methodology: MethodologyRef
    complete: bool
    inputs: dict[str, list[str]]
    missing: list[dict[str, Any]]
    by_type: list[dict[str, Any]]
    exposed: list[str]
    i_infr: str | None
    trace: list[dict[str, Any]]


def _methodology(session: DbSession) -> RefVulnMethodology:
    m = session.get(RefVulnMethodology, INVENTORY_METHODOLOGY)
    if m is None:
        raise HTTPException(
            409, detail="Справочник Методики оценки критичности уязвимостей не загружен"
        )
    return m


def _ref(m: RefVulnMethodology) -> MethodologyRef:
    return MethodologyRef(
        id=m.id, version=m.version, revision=m.revision, verified=m.verified_at is not None
    )


def _hosts(obj: AssessedObject) -> list[HostData]:
    return [
        HostData(
            address=h.address,
            hostname=h.hostname,
            component_types=tuple(h.component_types or ()),
            internet_exposed=h.internet_exposed,
        )
        for h in sorted(obj.hosts, key=lambda h: _sort_key(h.address))
    ]


@router.get("/objects/{object_id}/inventory", response_model=InventoryOut)
def get_inventory(object_id: uuid.UUID, user: Viewer, session: DbSession) -> InventoryOut:
    obj = get_object_for(session, object_id, user)
    m = _methodology(session)
    hosts = _hosts(obj)
    try:
        r = readiness(m.definition, hosts)
    except MethodologyError as e:
        raise HTTPException(409, detail=str(e)) from e
    return InventoryOut(
        methodology=_ref(m),
        hosts_total=r.hosts_total,
        ready=r.ready,
        missing_type=r.missing_type,
        missing_internet=r.missing_internet,
        internet_conflict=(
            [] if obj.internet else [h.address for h in hosts if h.internet_exposed]
        ),
        types=[ComponentType(**t) for t in r.by_type],
    )


@router.get("/refs/component-types", response_model=list[dict[str, Any]])
def list_component_types(_: Viewer, session: DbSession) -> list[dict[str, Any]]:
    """Типы компонента для выбора у хоста: значения показателя K справочника."""
    try:
        return component_types(_methodology(session).definition)
    except MethodologyError as e:
        raise HTTPException(409, detail=str(e)) from e


@router.post("/objects/{object_id}/inventory/infr", response_model=InfrOut)
def calculate_infr(object_id: uuid.UUID, body: InfrIn, user: Viewer, session: DbSession) -> InfrOut:
    obj = get_object_for(session, object_id, user)
    m = _methodology(session)
    try:
        out = infrastructure(m.definition, _hosts(obj), body.addresses)
    except InputError as e:
        raise HTTPException(422, detail=str(e)) from e
    except MethodologyError as e:
        raise HTTPException(409, detail=str(e)) from e
    return InfrOut(methodology=_ref(m), **out.as_dict())
