"""Общие зависимости: сессия БД, текущий пользователь, проверка прав."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.core.config import get_settings
from app.core.rbac import Perm, perms_for
from app.db.models import User, utcnow
from app.db.session import get_session
from app.integrations.platform.tokens import Claims, PlatformAuthError, bearer, verify_token

DbSession = Annotated[Session, Depends(get_session)]
_bearer = HTTPBearer(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Требуется вход",
    headers={"WWW-Authenticate": "Bearer"},
)


def client_ip(request: Request) -> str | None:
    # За nginx адрес клиента приходит в X-Real-IP (uvicorn --proxy-headers).
    return request.headers.get("x-real-ip") or (request.client.host if request.client else None)


def _platform_error(e: PlatformAuthError) -> HTTPException:
    headers = {"WWW-Authenticate": "Bearer"} if e.status == 401 else None
    return HTTPException(status_code=e.status, detail=e.detail, headers=headers)


# Как часто обновлять отметку «последний раз заходил» у теневой записи.
_SEEN_EVERY = timedelta(minutes=5)


def _free_username(session: Session, wanted: str, sub: str) -> str:
    name = (wanted or sub).strip().lower()[:64] or sub[:64]
    if session.scalar(select(User.id).where(User.username == name)) is None:
        return name
    # Логин занят локальной записью: связь задаётся только явно (контракт v1.1, п. 2.5).
    return f"{name[:52]}~{sub.replace('-', '')[-10:]}"


def shadow_user(session: Session, claims: Claims, ip: str | None = None) -> User:
    """Теневая запись пользователя платформы по sub: создаётся при первом запросе,
    имя и последние роли/проекты обновляются при следующих. Пароля нет."""
    user = session.scalar(select(User).where(User.platform_sub == claims.sub))
    now = utcnow()
    roles = sorted(set(claims.roles))
    projects = sorted(set(claims.projects))
    if user is None:
        user = User(
            username=_free_username(session, claims.username, claims.sub),
            display_name=(claims.name or claims.username or claims.sub)[:200],
            password_hash=None,
            platform_sub=claims.sub,
            platform_typ=claims.typ,
            platform_roles=roles,
            platform_projects=projects,
            platform_seen_at=now,
            last_login_at=now,
        )
        session.add(user)
        try:
            session.flush()
        except IntegrityError:
            # Тот же sub пришёл параллельным запросом.
            session.rollback()
            found = session.scalar(select(User).where(User.platform_sub == claims.sub))
            if found is None:
                raise
            return found
        audit.record(
            session,
            action="user.shadow_create",
            actor=user,
            entity="user",
            entity_id=user.id,
            ip=ip,
            details={"sub": claims.sub, "typ": claims.typ, "username": user.username},
        )
        session.commit()
        return user
    name = (claims.name or claims.username or user.display_name)[:200]
    seen = user.platform_seen_at
    if seen is not None and seen.tzinfo is None:
        seen = seen.replace(tzinfo=now.tzinfo)
    changed = (
        user.display_name != name
        or user.platform_typ != claims.typ
        or (user.platform_roles or []) != roles
        or (user.platform_projects or []) != projects
    )
    if changed or seen is None or now - seen > _SEEN_EVERY:
        user.display_name = name
        user.platform_typ = claims.typ
        user.platform_roles = roles
        user.platform_projects = projects
        user.platform_seen_at = now
        session.commit()
    return user


def _platform_user(request: Request, session: Session) -> User:
    settings = get_settings()
    try:
        token = bearer(request.headers.get("authorization"))
        claims = verify_token(token, settings.platform_product_id, request.app.state.jwks)
    except PlatformAuthError as e:
        raise _platform_error(e) from e
    user = shadow_user(session, claims, client_ip(request))
    if not user.is_active:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Учётная запись отключена")
    # Права этого запроса — только из его токена (роли в записи не хранятся).
    user.token_roles = set(claims.roles)
    user.token_projects = list(claims.projects)
    user.token = token
    return user


def current_user(
    request: Request,
    session: DbSession,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
    if get_settings().auth_mode == "platform":
        return _platform_user(request, session)
    if creds is None:
        raise _UNAUTHORIZED
    user_id = request.app.state.signer.verify(creds.credentials)
    if user_id is None:
        raise _UNAUTHORIZED
    user = session.get(User, user_id)
    if user is None or not user.is_active:
        raise _UNAUTHORIZED
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def require(*perms: Perm) -> Callable[..., User]:
    """Зависимость эндпоинта: пользователь должен иметь все перечисленные права."""

    def dep(request: Request, user: CurrentUser, session: DbSession) -> User:
        have = perms_for(user.roles)
        missing = [p for p in perms if p not in have]
        if missing:
            audit.record_now(
                session,
                action="access.denied",
                actor=user,
                result="denied",
                ip=client_ip(request),
                details={
                    "path": request.url.path,
                    "method": request.method,
                    "missing": [str(p) for p in missing],
                },
            )
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Недостаточно прав")
        return user

    return dep
