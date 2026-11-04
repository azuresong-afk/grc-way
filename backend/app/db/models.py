"""Модели: пользователи, роли, журнал аудита."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base

JsonType = JSON().with_variant(JSONB(), "postgresql")
# BIGSERIAL в PostgreSQL, INTEGER PRIMARY KEY (автоинкремент) в SQLite.
BigId = BigInteger().with_variant(Integer(), "sqlite")


def utcnow() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    display_name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    # Режим platform: sub из токена «Платформы» (этап 3).
    platform_sub: Mapped[str | None] = mapped_column(String(64), unique=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    role_rows: Mapped[list[UserRole]] = relationship(cascade="all, delete-orphan", lazy="selectin")

    @property
    def roles(self) -> set[str]:
        return {r.role for r in self.role_rows}

    def set_roles(self, roles: set[str]) -> None:
        keep = [r for r in self.role_rows if r.role in roles]
        have = {r.role for r in keep}
        self.role_rows = keep + [UserRole(role=r) for r in sorted(roles - have)]


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role: Mapped[str] = mapped_column(String(32), primary_key=True)


class AuditRecord(Base):
    """Журнал аудита: только добавление (UPDATE/DELETE запрещены триггером)."""

    __tablename__ = "audit_log"
    __table_args__ = (
        Index("ix_audit_log_at", "at"),
        Index("ix_audit_log_action", "action"),
        Index("ix_audit_log_user_id", "user_id"),
        Index("ix_audit_log_entity", "entity", "entity_id"),
    )

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    user_name: Mapped[str | None] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(64))
    entity: Mapped[str | None] = mapped_column(String(64))
    entity_id: Mapped[str | None] = mapped_column(String(64))
    project_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    result: Mapped[str] = mapped_column(String(16))  # ok | denied | error
    ip: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JsonType, default=dict)
