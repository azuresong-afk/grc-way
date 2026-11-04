"""Создание первого администратора из .env, если пользователей ещё нет.

Запуск: python -m app.bootstrap (вызывается в docker-entrypoint.sh после миграций).
"""

from __future__ import annotations

import sys

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.core.config import get_settings
from app.core.rbac import Role
from app.core.security import hash_password, password_problem
from app.db.models import User
from app.db.session import get_engine


def ensure_admin(session: Session, username: str, password: str) -> str:
    if session.scalar(select(func.count()).select_from(User)):
        return "пользователи уже есть — администратор не создаётся"
    if not password:
        raise SystemExit("ошибка: пользователей нет, задайте GRC_BOOTSTRAP_ADMIN_PASSWORD")
    problem = password_problem(password)
    if problem:
        raise SystemExit(f"ошибка: GRC_BOOTSTRAP_ADMIN_PASSWORD: {problem}")
    user = User(
        username=username.lower(),
        display_name="Администратор",
        password_hash=hash_password(password),
    )
    user.set_roles({Role.ADMIN.value})
    session.add(user)
    session.flush()
    audit.record(
        session,
        action="user.bootstrap",
        actor_name="system",
        entity="user",
        entity_id=user.id,
        details={"username": user.username},
    )
    session.commit()
    return f"создан администратор «{user.username}»"


def main() -> int:
    s = get_settings()
    with Session(get_engine()) as session:
        print(ensure_admin(session, s.bootstrap_admin, s.bootstrap_admin_password))
    return 0


if __name__ == "__main__":
    sys.exit(main())
