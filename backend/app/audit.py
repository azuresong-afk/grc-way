"""Запись в журнал аудита. Секреты (пароли, токены) в details не попадают никогда."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import AuditRecord, User

_SECRET_KEYS = {"password", "password_hash", "token", "access_token", "secret"}


def _clean(details: dict[str, Any] | None) -> dict[str, Any]:
    return {k: v for k, v in (details or {}).items() if k.lower() not in _SECRET_KEYS}


def record(
    session: Session,
    *,
    action: str,
    actor: User | None = None,
    actor_name: str | None = None,
    entity: str | None = None,
    entity_id: object = None,
    project_id: uuid.UUID | None = None,
    result: str = "ok",
    ip: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditRecord:
    """Добавляет запись в текущую транзакцию: она фиксируется вместе с изменением."""
    rec = AuditRecord(
        user_id=actor.id if actor else None,
        user_name=(actor.display_name if actor else None) or actor_name,
        action=action,
        entity=entity,
        entity_id=None if entity_id is None else str(entity_id),
        project_id=project_id,
        result=result,
        ip=ip,
        details=_clean(details),
    )
    session.add(rec)
    return rec


def record_now(session: Session, **kwargs: Any) -> None:
    """Отдельная запись с немедленной фиксацией (неудачный вход, отказ в доступе)."""
    record(session, **kwargs)
    session.commit()
