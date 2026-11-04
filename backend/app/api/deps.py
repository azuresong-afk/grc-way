"""Общие зависимости: сессия БД, текущий пользователь, проверка прав."""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app import audit
from app.core.rbac import Perm, perms_for
from app.db.models import User
from app.db.session import get_session

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


def current_user(
    request: Request,
    session: DbSession,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
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
