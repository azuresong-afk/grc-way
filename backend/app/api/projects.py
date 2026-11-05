"""Заказчики и проекты (режим AUTH_MODE=local; в режиме platform проекты — у платформы)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.schemas import (
    CustomerIn,
    CustomerOut,
    CustomerPatch,
    MemberOut,
    MembersIn,
    ProjectIn,
    ProjectOut,
    ProjectPatch,
)
from app.core.rbac import Perm, Role
from app.db.models import Customer, Project, ProjectMember, User

router = APIRouter(tags=["projects"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Manager = Annotated[User, Depends(require(Perm.PROJECTS_MANAGE))]


def _not_found() -> HTTPException:
    # Чужой проект неотличим от несуществующего: не раскрываем, что он есть.
    return HTTPException(status.HTTP_404_NOT_FOUND, detail="Проект не найден")


def _visible(stmt: Select, user: User) -> Select:
    """Проекты, где пользователь — участник."""
    return stmt.where(
        Project.id.in_(select(ProjectMember.project_id).where(ProjectMember.user_id == user.id))
    )


def get_project_for(session: Session, project_id: uuid.UUID, user: User) -> Project:
    project = session.get(Project, project_id)
    if project is None or user.id not in {m.user_id for m in project.members}:
        raise _not_found()
    return project


def _project_out(session: Session, p: Project) -> ProjectOut:
    ids = [m.user_id for m in p.members]
    users = session.scalars(select(User).where(User.id.in_(ids))).all() if ids else []
    return ProjectOut(
        id=p.id,
        customer_id=p.customer_id,
        client=p.customer.name,
        name=p.name,
        contract_ref=p.contract_ref,
        period_from=p.period_from,
        period_to=p.period_to,
        status=p.status,
        scanner_engagement_id=p.scanner_engagement_id,
        vm_project_id=p.vm_project_id,
        platform_project_id=p.platform_project_id,
        created_at=p.created_at,
        members=sorted(
            (MemberOut(id=u.id, display_name=u.display_name, roles=sorted(u.roles)) for u in users),
            key=lambda m: m.display_name,
        ),
    )


def _check_period(p: Project) -> None:
    if p.period_from and p.period_to and p.period_from > p.period_to:
        raise HTTPException(422, detail="Начало срока позже окончания")


# ---------- Заказчики ----------


@router.get("/customers", response_model=list[CustomerOut])
def list_customers(
    _: Viewer,
    session: DbSession,
    response: Response,
    q: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Customer]:
    stmt = select(Customer)
    if q:
        stmt = stmt.where(
            or_(func.lower(Customer.name).contains(q.lower()), Customer.inn.startswith(q))
        )
    response.headers["X-Total-Count"] = str(
        session.scalar(select(func.count()).select_from(stmt.subquery()))
    )
    return list(session.scalars(stmt.order_by(Customer.name).limit(limit).offset(offset)))


@router.post("/customers", response_model=CustomerOut, status_code=201)
def create_customer(
    body: CustomerIn, request: Request, user: Manager, session: DbSession
) -> Customer:
    c = Customer(
        **body.model_dump(exclude={"contacts"}),
        contacts=[x.model_dump() for x in body.contacts],
        created_by=user.id,
    )
    session.add(c)
    session.flush()
    audit.record(
        session,
        action="customer.create",
        actor=user,
        entity="customer",
        entity_id=c.id,
        ip=client_ip(request),
        details={"name": c.name},
    )
    session.commit()
    return c


@router.patch("/customers/{customer_id}", response_model=CustomerOut)
def update_customer(
    customer_id: uuid.UUID,
    body: CustomerPatch,
    request: Request,
    user: Manager,
    session: DbSession,
) -> Customer:
    c = session.get(Customer, customer_id)
    if c is None:
        raise HTTPException(404, detail="Заказчик не найден")
    data = body.model_dump(exclude_unset=True)
    if "contacts" in data:
        data["contacts"] = [x.model_dump() for x in body.contacts or []]
    for k, v in data.items():
        setattr(c, k, v)
    audit.record(
        session,
        action="customer.update",
        actor=user,
        entity="customer",
        entity_id=c.id,
        ip=client_ip(request),
        details={"fields": sorted(data)},
    )
    session.commit()
    return c


# ---------- Проекты ----------


@router.get("/projects", response_model=list[ProjectOut])
def list_projects(
    user: Viewer,
    session: DbSession,
    response: Response,
    status_: Annotated[str | None, Query(alias="status", pattern=r"^(active|archived)$")] = None,
    q: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ProjectOut]:
    stmt = _visible(select(Project).join(Project.customer), user)
    if status_:
        stmt = stmt.where(Project.status == status_)
    if q:
        like = q.lower()
        stmt = stmt.where(
            or_(
                func.lower(Project.name).contains(like),
                func.lower(Customer.name).contains(like),
                func.lower(Project.contract_ref).contains(like),
            )
        )
    response.headers["X-Total-Count"] = str(
        session.scalar(select(func.count()).select_from(stmt.subquery()))
    )
    rows = session.scalars(stmt.order_by(Project.created_at.desc()).limit(limit).offset(offset))
    return [_project_out(session, p) for p in rows]


@router.post("/projects", response_model=ProjectOut, status_code=201)
def create_project(
    body: ProjectIn, request: Request, user: Manager, session: DbSession
) -> ProjectOut:
    if session.get(Customer, body.customer_id) is None:
        raise HTTPException(422, detail="Заказчик не найден")
    p = Project(**body.model_dump(), created_by=user.id)
    _check_period(p)
    p.members = [ProjectMember(user_id=user.id)]  # автор — первый участник
    session.add(p)
    session.flush()
    audit.record(
        session,
        action="project.create",
        actor=user,
        entity="project",
        entity_id=p.id,
        project_id=p.id,
        ip=client_ip(request),
        details={"name": p.name, "contract_ref": p.contract_ref},
    )
    session.commit()
    session.refresh(p)
    return _project_out(session, p)


@router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: uuid.UUID, user: Viewer, session: DbSession) -> ProjectOut:
    return _project_out(session, get_project_for(session, project_id, user))


@router.patch("/projects/{project_id}", response_model=ProjectOut)
def update_project(
    project_id: uuid.UUID,
    body: ProjectPatch,
    request: Request,
    user: Manager,
    session: DbSession,
) -> ProjectOut:
    p = get_project_for(session, project_id, user)
    data = body.model_dump(exclude_unset=True)
    if "name" in data and not data["name"]:
        raise HTTPException(422, detail="Укажите название проекта")
    for k, v in data.items():
        setattr(p, k, v)
    _check_period(p)
    action = "project.archive" if data.get("status") == "archived" else "project.update"
    audit.record(
        session,
        action=action,
        actor=user,
        entity="project",
        entity_id=p.id,
        project_id=p.id,
        ip=client_ip(request),
        details={k: str(v) for k, v in data.items()},
    )
    session.commit()
    return _project_out(session, p)


@router.put("/projects/{project_id}/members", response_model=ProjectOut)
def set_members(
    project_id: uuid.UUID,
    body: MembersIn,
    request: Request,
    user: Manager,
    session: DbSession,
) -> ProjectOut:
    p = get_project_for(session, project_id, user)
    wanted = set(body.user_ids)
    if user.id not in wanted:
        raise HTTPException(422, detail="Нельзя исключить из проекта самого себя")
    users = session.scalars(select(User).where(User.id.in_(wanted))).all()
    if len(users) != len(wanted):
        raise HTTPException(422, detail="Пользователь не найден")
    if any(Role.ADMIN.value in u.roles for u in users):
        raise HTTPException(422, detail="Администратор не участвует в проектах")
    before = {m.user_id for m in p.members}
    p.members = [m for m in p.members if m.user_id in wanted] + [
        ProjectMember(user_id=uid) for uid in wanted - before
    ]
    audit.record(
        session,
        action="project.members",
        actor=user,
        entity="project",
        entity_id=p.id,
        project_id=p.id,
        ip=client_ip(request),
        details={
            "added": sorted(map(str, wanted - before)),
            "removed": sorted(map(str, before - wanted)),
        },
    )
    session.commit()
    session.refresh(p)
    return _project_out(session, p)


@router.get("/directory/users", response_model=list[MemberOut])
def user_directory(_: Manager, session: DbSession) -> list[MemberOut]:
    """Активные пользователи с рабочими ролями — для выбора участников проекта."""
    users = session.scalars(select(User).where(User.is_active).order_by(User.display_name))
    return [
        MemberOut(id=u.id, display_name=u.display_name, roles=sorted(u.roles))
        for u in users
        if Role.ADMIN.value not in u.roles
    ]
