"""Пользователи и роли (администратор)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, or_, select

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.schemas import UserCreate, UserOut, UserPatch
from app.core.config import get_settings
from app.core.rbac import ROLE_TITLES, Perm, Role, roles_problem
from app.core.security import hash_password, password_problem
from app.db.models import User

router = APIRouter(prefix="/users", tags=["users"])
Admin = Annotated[User, Depends(require(Perm.USERS_MANAGE))]


def _out(u: User) -> UserOut:
    return UserOut(
        id=u.id,
        username=u.username,
        display_name=u.display_name,
        roles=sorted(u.roles),
        is_active=u.is_active,
        created_at=u.created_at,
        last_login_at=u.last_login_at,
        platform_sub=u.platform_sub,
        platform_typ=u.platform_typ,
        platform_seen_at=u.platform_seen_at,
    )


def _local_only() -> None:
    # В режиме platform пользователи и роли ведутся в «Платформе» (контракт v1.1, п. 2).
    if get_settings().auth_mode == "platform":
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="Пользователи и роли ведутся в «Платформе»"
        )


def _check_roles(roles: list[str]) -> set[str]:
    rs = set(roles)
    problem = roles_problem(rs)
    if problem:
        raise HTTPException(422, detail=problem)
    return rs


def _check_password(password: str) -> None:
    problem = password_problem(password)
    if problem:
        raise HTTPException(422, detail=problem)


@router.get("/roles")
def roles(_: Admin) -> list[dict[str, str]]:
    return [{"id": str(r), "title": t} for r, t in ROLE_TITLES.items()]


@router.get("", response_model=list[UserOut])
def list_users(
    _: Admin,
    session: DbSession,
    response: Response,
    q: str | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[UserOut]:
    stmt = select(User)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(func.lower(User.username).like(like), func.lower(User.display_name).like(like))
        )
    total = session.scalar(select(func.count()).select_from(stmt.subquery()))
    response.headers["X-Total-Count"] = str(total)
    rows = session.scalars(stmt.order_by(User.username).limit(limit).offset(offset))
    return [_out(u) for u in rows]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, request: Request, admin: Admin, session: DbSession) -> UserOut:
    _local_only()
    username = body.username.lower()
    if session.scalar(select(User.id).where(User.username == username)):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="Такое имя пользователя уже есть")
    roles = _check_roles(body.roles)
    _check_password(body.password)
    user = User(
        username=username,
        display_name=body.display_name.strip(),
        password_hash=hash_password(body.password),
    )
    user.set_roles(roles)
    session.add(user)
    session.flush()
    audit.record(
        session,
        action="user.create",
        actor=admin,
        entity="user",
        entity_id=user.id,
        ip=client_ip(request),
        details={"username": username, "roles": sorted(roles)},
    )
    session.commit()
    return _out(user)


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID, body: UserPatch, request: Request, admin: Admin, session: DbSession
) -> UserOut:
    _local_only()
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")
    changes: dict[str, object] = {}

    if body.display_name is not None and body.display_name.strip() != user.display_name:
        user.display_name = body.display_name.strip()
        changes["display_name"] = user.display_name
    if body.roles is not None:
        roles = _check_roles(body.roles)
        if user.id == admin.id and Role.ADMIN not in roles:
            raise HTTPException(
                422,
                detail="Нельзя снять роль администратора с самого себя",
            )
        if roles != user.roles:
            changes["roles"] = {"from": sorted(user.roles), "to": sorted(roles)}
            user.set_roles(roles)
    if body.is_active is not None and body.is_active != user.is_active:
        if user.id == admin.id and not body.is_active:
            raise HTTPException(422, detail="Нельзя заблокировать самого себя")
        user.is_active = body.is_active
        changes["is_active"] = body.is_active
    if body.password:
        _check_password(body.password)
        user.password_hash = hash_password(body.password)
        changes["password_changed"] = True

    if changes:
        audit.record(
            session,
            action="user.update",
            actor=admin,
            entity="user",
            entity_id=user.id,
            ip=client_ip(request),
            details={"username": user.username, **changes},
        )
        session.commit()
    return _out(user)
