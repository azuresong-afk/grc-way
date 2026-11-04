"""Модели: пользователи, роли, журнал аудита."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
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


class Customer(Base):
    """Заказчик: организация, по договору с которой ведутся работы."""

    __tablename__ = "customers"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(300))
    inn: Mapped[str | None] = mapped_column(String(12))
    ogrn: Mapped[str | None] = mapped_column(String(15))
    address: Mapped[str | None] = mapped_column(String(500))
    # Ответственные лица: [{name, position, phone, email}]
    contacts: Mapped[list] = mapped_column(JsonType, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)


class Project(Base):
    """Проект = договор на работы с заказчиком (контракт платформы v1, п. 3)."""

    __tablename__ = "projects"
    __table_args__ = (
        Index("ix_projects_status", "status"),
        Index("ix_projects_customer_id", "customer_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"))
    name: Mapped[str] = mapped_column(String(300))
    contract_ref: Mapped[str | None] = mapped_column(String(200))
    period_from: Mapped[date | None] = mapped_column(Date)
    period_to: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | archived
    platform_project_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, unique=True)
    scanner_engagement_id: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    customer: Mapped[Customer] = relationship(lazy="joined")
    members: Mapped[list[ProjectMember]] = relationship(
        cascade="all, delete-orphan", lazy="selectin"
    )


class ProjectMember(Base):
    __tablename__ = "project_members"
    __table_args__ = (Index("ix_project_members_user_id", "user_id"),)

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )


# ---------- Справочники ----------


class RefProfile(Base):
    """Профиль мер (нормативный документ): fstec-117, fstec-21, fstec-239, cis-*."""

    __tablename__ = "ref_profiles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    short: Mapped[str] = mapped_column(String(100))
    document: Mapped[str | None] = mapped_column(String(2000))
    url: Mapped[str | None] = mapped_column(String(500))
    level_label: Mapped[str | None] = mapped_column(String(100))
    levels: Mapped[list] = mapped_column(JsonType, default=list)
    default_level: Mapped[str | None] = mapped_column(String(16))
    dynamic: Mapped[str | None] = mapped_column(String(64))
    position: Mapped[int] = mapped_column(Integer, default=0)
    # Хэш YAML-файла, из которого профиль загружен последним (reference/profiles).
    source_hash: Mapped[str] = mapped_column(String(64))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Когда профиль последний раз обновлён из API «Сканера» (экран разницы).
    scanner_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RefGroup(Base):
    __tablename__ = "ref_groups"

    profile_id: Mapped[str] = mapped_column(
        ForeignKey("ref_profiles.id", ondelete="CASCADE"), primary_key=True
    )
    code: Mapped[str] = mapped_column(String(16), primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    position: Mapped[int] = mapped_column(Integer, default=0)


class RefMeasure(Base):
    """Мера или мероприятие. Идентификатор совпадает со «Сканером» (ИАФ.1, ВУ, …)."""

    __tablename__ = "ref_measures"
    __table_args__ = (Index("ix_ref_measures_group", "profile_id", "group_code"),)

    profile_id: Mapped[str] = mapped_column(
        ForeignKey("ref_profiles.id", ondelete="CASCADE"), primary_key=True
    )
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    group_code: Mapped[str] = mapped_column(String(16))
    position: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(500))
    # Текст требования из официального документа; None — текст не загружен.
    text: Mapped[str | None] = mapped_column(String(10000))
    levels: Mapped[list] = mapped_column(JsonType, default=list)
    checks: Mapped[list] = mapped_column(JsonType, default=list)
    # {document, clause, appendix, url, note}
    source: Mapped[dict] = mapped_column(JsonType, default=dict)
    # scanner — импорт из «Сканера»; local — правка в интерфейсе; official; stub.
    origin: Mapped[str] = mapped_column(String(16))
    verified_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    verified_by_name: Mapped[str | None] = mapped_column(String(200))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)

    @property
    def kind(self) -> str:
        """Техническая — есть проверки «Сканера»; организационная — проверяется вручную."""
        return "technical" if self.checks else "organizational"


class RefCheck(Base):
    """Техническая проверка «Сканера» (каталог checks.yaml)."""

    __tablename__ = "ref_checks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
    platform: Mapped[str] = mapped_column(String(16))
    remediation: Mapped[str | None] = mapped_column(String(4000))
    doc: Mapped[str | None] = mapped_column(String(500))
    # Источники проверки (openscap, lynis, windows, …) — как в «Сканере».
    sources: Mapped[dict] = mapped_column(JsonType, default=dict)


class RefRevision(Base):
    """История правок записей справочника: снимок записи до изменения."""

    __tablename__ = "ref_revisions"
    __table_args__ = (Index("ix_ref_revisions_entity", "entity", "entity_key"),)

    id: Mapped[int] = mapped_column(BigId, primary_key=True, autoincrement=True)
    entity: Mapped[str] = mapped_column(String(32))
    entity_key: Mapped[str] = mapped_column(String(128))
    revision: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict] = mapped_column(JsonType)
    changed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    changed_by_name: Mapped[str | None] = mapped_column(String(200))
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    comment: Mapped[str | None] = mapped_column(String(1000))


class RefSyncDiff(Base):
    """Сравнение справочника с ответом «Сканера» (GET /compliance/profiles).

    Ответ «Сканера» хранится целиком: применяется ровно то, что показано на экране
    разницы. Перед применением разница пересчитывается и сверяется по отпечатку —
    если справочник успел измениться, применение отклоняется.
    """

    __tablename__ = "ref_sync_diffs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
    # live | fixture и адрес «Сканера» / имя фикстуры.
    mode: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(500))
    payload: Mapped[list] = mapped_column(JsonType)
    payload_hash: Mapped[str] = mapped_column(String(64))
    diff: Mapped[dict] = mapped_column(JsonType)
    fingerprint: Mapped[str] = mapped_column(String(64))
    # pending — ждёт решения; applied — применено; superseded — есть более новое сравнение.
    status: Mapped[str] = mapped_column(String(16), default="pending")
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    applied_by_name: Mapped[str | None] = mapped_column(String(200))
    applied: Mapped[dict | None] = mapped_column(JsonType)
