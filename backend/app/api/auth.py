"""Вход, выход, текущий пользователь (режим AUTH_MODE=local)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app import audit
from app.api.deps import CurrentUser, DbSession, client_ip
from app.api.schemas import LoginIn, MeOut, TokenOut
from app.core.rbac import perms_for
from app.core.security import DUMMY_HASH, verify_password
from app.db.models import User, utcnow

router = APIRouter(tags=["auth"])


@router.post("/auth/token", response_model=TokenOut)
def login(body: LoginIn, request: Request, session: DbSession) -> TokenOut:
    throttle = request.app.state.throttle
    username = body.username.strip().lower()
    ip = client_ip(request)

    if throttle.locked(username):
        audit.record_now(
            session,
            action="auth.login",
            actor_name=username,
            result="denied",
            ip=ip,
            details={"reason": "throttled"},
        )
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Слишком много неудачных попыток. Повторите позже",
        )

    user = session.scalar(select(User).where(User.username == username))
    ok = verify_password(body.password, user.password_hash if user else DUMMY_HASH)
    if not user or not ok or not user.is_active:
        throttle.failure(username)
        reason = "inactive" if user and ok else "bad_credentials"
        audit.record_now(
            session,
            action="auth.login",
            actor_name=username,
            result="denied",
            ip=ip,
            details={"reason": reason},
        )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Неверное имя или пароль")

    throttle.success(username)
    user.last_login_at = utcnow()
    audit.record(session, action="auth.login", actor=user, ip=ip)
    session.commit()
    signer = request.app.state.signer
    return TokenOut(access_token=signer.issue(user.id), expires_in=signer.ttl)


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, user: CurrentUser, session: DbSession) -> None:
    audit.record_now(session, action="auth.logout", actor=user, ip=client_ip(request))


@router.get("/me", response_model=MeOut)
def me(user: CurrentUser) -> MeOut:
    return MeOut(
        id=user.id,
        username=user.username,
        display_name=user.display_name,
        roles=sorted(user.roles),
        permissions=sorted(str(p) for p in perms_for(user.roles)),
    )
