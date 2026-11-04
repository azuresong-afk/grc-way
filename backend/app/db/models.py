"""Модели: пользователи и аудит, проекты, справочники, объекты, меры и их оценка."""

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


# ---------- Объекты ----------


class AssessedObject(Base):
    """Объект оценки: ГИС, ИСПДн, значимый объект КИИ или иная система внутри проекта."""

    __tablename__ = "objects"
    __table_args__ = (Index("ix_objects_project", "project_id", "status"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(8))  # gis | ispdn | kii | other
    name: Mapped[str] = mapped_column(String(300))
    # Нормативный режим: 117 | 21 | 239; None — не выбран (для «иной» системы).
    regime: Mapped[str | None] = mapped_column(String(8))
    purpose: Mapped[str | None] = mapped_column(String(4000))
    boundaries: Mapped[str | None] = mapped_column(String(4000))
    # [{system, owner, direction (in|out|both), channel, description}]
    interconnections: Mapped[list] = mapped_column(JsonType, default=list)
    internet: Mapped[bool] = mapped_column(Boolean, default=False)
    # [{name, position, role, phone, email}]
    responsible: Mapped[list] = mapped_column(JsonType, default=list)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | archived
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    # Когда состав последний раз сверялся с активами «Сканера».
    scanner_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    segments: Mapped[list[ObjectSegment]] = relationship(
        cascade="all, delete-orphan", lazy="selectin", order_by="ObjectSegment.position"
    )
    hosts: Mapped[list[ObjectHost]] = relationship(
        cascade="all, delete-orphan", lazy="selectin", order_by="ObjectHost.address"
    )


class ObjectSegment(Base):
    """Сегмент объекта (ЛВС, ДМЗ, площадка). Может соответствовать группе активов «Сканера»."""

    __tablename__ = "object_segments"
    __table_args__ = (Index("ix_object_segments_object", "object_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(String(2000))
    # Имя группы активов «Сканера»: хосты этой группы при синхронизации попадают сюда.
    scanner_group: Mapped[str | None] = mapped_column(String(200))
    position: Mapped[int] = mapped_column(Integer, default=0)


class ObjectHost(Base):
    """Хост в составе объекта. Ключ сопоставления с активами «Сканера» — (project, address)."""

    __tablename__ = "object_hosts"
    __table_args__ = (
        Index("ux_object_hosts_address", "object_id", "address", unique=True),
        Index("ix_object_hosts_project_address", "project_id", "address"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    segment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("object_segments.id", ondelete="SET NULL")
    )
    # IP-адрес в каноническом виде (как host_key «Сканера»).
    address: Mapped[str] = mapped_column(String(64))
    hostname: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str | None] = mapped_column(String(300))
    os: Mapped[str | None] = mapped_column(String(200))
    os_family: Mapped[str | None] = mapped_column(String(32))
    # manual — добавлен вручную; scanner — из активов «Сканера».
    source: Mapped[str] = mapped_column(String(16))
    scanner_asset_id: Mapped[int | None] = mapped_column(Integer)
    # Данные актива на момент последней синхронизации (только для показа).
    scanner_groups: Mapped[list] = mapped_column(JsonType, default=list)
    criticality: Mapped[str | None] = mapped_column(String(16))
    owner: Mapped[str | None] = mapped_column(String(200))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Последняя синхронизация не нашла адрес среди активов «Сканера».
    scanner_missing: Mapped[bool] = mapped_column(Boolean, default=False)
    synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ---------- Классификация ----------


class RefClassificationTable(Base):
    """Таблица классификации режима (117 — класс ГИС, 21 — УЗ ПДн, 239 — категория КИИ).

    Определение — данные (см. app/domain/classification.py), мастер их только
    интерпретирует. Каждая правка — новая ревизия, прежнее определение — в ref_revisions.
    """

    __tablename__ = "ref_classification_tables"

    regime: Mapped[str] = mapped_column(String(8), primary_key=True)
    title: Mapped[str] = mapped_column(String(300))
    # Метка версии из файла (например, 117-stub-1); номер ревизии — в revision.
    version: Mapped[str] = mapped_column(String(64))
    definition: Mapped[dict] = mapped_column(JsonType)
    definition_hash: Mapped[str] = mapped_column(String(64))
    # {document, clause, appendix, url, note}
    source: Mapped[dict] = mapped_column(JsonType, default=dict)
    origin: Mapped[str] = mapped_column(String(16))  # stub | official | local
    verified_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    verified_by_name: Mapped[str | None] = mapped_column(String(200))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    # Хэш YAML-файла последней загрузки: неизменённый файл при старте не трогается.
    source_hash: Mapped[str] = mapped_column(String(64))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)


class Classification(Base):
    """Расчёт класса / уровня защищённости / категории объекта.

    Новая классификация — новая запись; прежние сохраняются. Запись хранит снимок
    определения таблицы, по которому считали, — расчёт воспроизводим, даже если
    таблицу потом исправили.
    """

    __tablename__ = "classifications"
    __table_args__ = (Index("ix_classifications_object", "object_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    regime: Mapped[str] = mapped_column(String(8))
    inputs: Mapped[dict] = mapped_column(JsonType)
    result: Mapped[str] = mapped_column(String(32))
    result_label: Mapped[str] = mapped_column(String(200))
    # Промежуточные значения шагов и трасса: какая строка таблицы сработала.
    step_values: Mapped[dict] = mapped_column(JsonType, default=dict)
    trace: Mapped[list] = mapped_column(JsonType, default=list)
    justification: Mapped[str | None] = mapped_column(String(10000))
    table_version: Mapped[str] = mapped_column(String(64))
    table_revision: Mapped[int] = mapped_column(Integer)
    table_hash: Mapped[str] = mapped_column(String(64))
    table_snapshot: Mapped[dict] = mapped_column(JsonType)
    # Таблица на момент расчёта не была сверена методистом.
    table_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    # draft — черновик; approved — утверждена; superseded — заменена более новой.
    status: Mapped[str] = mapped_column(String(16), default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    approved_by_name: Mapped[str | None] = mapped_column(String(200))
    approval_comment: Mapped[str | None] = mapped_column(String(2000))
    # Утверждающий явно подтвердил использование несверенной таблицы.
    unverified_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    superseded_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)


# ---------- Набор мер объекта ----------


class Adaptation(Base):
    """Версия адаптации набора мер объекта: черновик → утверждена → заменена.

    Последняя версия объекта — текущая. Пересборка базового набора или правка
    адаптации после утверждения открывает новую версию-черновик; утверждённая
    остаётся в истории со снимком набора на момент утверждения.
    """

    __tablename__ = "adaptations"
    __table_args__ = (Index("ux_adaptations_version", "object_id", "version", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    # По какой утверждённой классификации собран базовый набор.
    classification_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("classifications.id", ondelete="SET NULL")
    )
    profile_id: Mapped[str] = mapped_column(String(64))
    level: Mapped[str] = mapped_column(String(16))
    level_label: Mapped[str] = mapped_column(String(200))
    # draft | approved | superseded
    status: Mapped[str] = mapped_column(String(16), default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
    # Кто менял адаптацию в этой версии (id строками): им утверждать нельзя.
    editors: Mapped[list] = mapped_column(JsonType, default=list)
    edits: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    approved_by_name: Mapped[str | None] = mapped_column(String(200))
    approval_comment: Mapped[str | None] = mapped_column(String(2000))
    # Утверждающий подтвердил, что состав мер не сверен методистом.
    unverified_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    # Снимок адаптации на момент утверждения:
    # [{measure_id, origin, adaptation, reason, compensating}].
    snapshot: Mapped[list | None] = mapped_column(JsonType)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ObjectMeasure(Base):
    """Мера в наборе объекта: из базового набора или добавленная при адаптации."""

    __tablename__ = "object_measures"
    __table_args__ = (
        Index("ux_object_measures_measure", "object_id", "profile_id", "measure_id", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    profile_id: Mapped[str] = mapped_column(String(64))
    measure_id: Mapped[str] = mapped_column(String(32))
    # Копия из справочника на момент включения — если меру потом уберут из справочника.
    group_code: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(500))
    position: Mapped[int] = mapped_column(Integer, default=0)
    # baseline — из базового набора по классу; added — дополнение при адаптации.
    origin: Mapped[str] = mapped_column(String(16))
    # none | excluded | compensated
    adaptation: Mapped[str] = mapped_column(String(16), default="none")
    # Обоснование исключения, компенсации или дополнения.
    adaptation_reason: Mapped[str | None] = mapped_column(String(4000))
    compensating_ids: Mapped[list] = mapped_column(JsonType, default=list)
    # implemented | partial | not_implemented | not_applicable | unassessed
    status: Mapped[str] = mapped_column(String(16), default="unassessed")
    # auto — есть проверки «Сканера»; manual — организационная; mixed — оба способа.
    method: Mapped[str] = mapped_column(String(8))
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    comment: Mapped[str | None] = mapped_column(String(4000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    adapted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    adapted_by_name: Mapped[str | None] = mapped_column(String(200))
    status_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status_by_name: Mapped[str | None] = mapped_column(String(200))
    # Откуда текущий статус: auto — предложение «Сканера»; manual — поставлен вручную
    # (повторный импорт его не перезаписывает); None — не ставился.
    status_source: Mapped[str | None] = mapped_column(String(8))
    # Предложение «Сканера» по текущему (последнему) снимку и его пояснение.
    auto_status: Mapped[str | None] = mapped_column(String(16))
    auto_note: Mapped[str | None] = mapped_column(String(1000))
    auto_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scanner_snapshots.id", ondelete="SET NULL")
    )


# ---------- Результаты «Сканера» ----------


class ScannerSnapshot(Base):
    """Снимок результата прогона «Сканера» для объекта на дату оценки.

    Неизменяем (UPDATE запрещён триггером): повторный импорт — новый снимок,
    прежние остаются как были. Текущий снимок объекта — последний импортированный.
    """

    __tablename__ = "scanner_snapshots"
    __table_args__ = (
        Index("ix_scanner_snapshots_object", "object_id", "imported_at"),
        Index("ux_scanner_snapshots_number", "object_id", "number", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    # Номер снимка в объекте: 1, 2, …
    number: Mapped[int] = mapped_column(Integer)
    engagement_id: Mapped[int] = mapped_column(Integer)
    run_id: Mapped[int] = mapped_column(Integer)
    run_name: Mapped[str | None] = mapped_column(String(300))
    run_status: Mapped[str] = mapped_column(String(32))
    run_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    run_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    run_modules: Mapped[list] = mapped_column(JsonType, default=list)
    # latest — «последний завершённый»; manual — прогон выбран вручную.
    selection: Mapped[str] = mapped_column(String(8))
    profile_id: Mapped[str] = mapped_column(String(64))
    level: Mapped[str | None] = mapped_column(String(16))
    adaptation_version: Mapped[int | None] = mapped_column(Integer)
    # Сводка «Сканера» по профилю и уровню: процент и {passed, failed, na, manual}.
    percent: Mapped[float | None] = mapped_column()
    counts: Mapped[dict] = mapped_column(JsonType, default=dict)
    # Ответы «Сканера» как есть (после проверки схемы): compliance и покрытие.
    compliance: Mapped[dict] = mapped_column(JsonType)
    coverage: Mapped[dict] = mapped_column(JsonType)
    # Состав объекта на момент импорта (адреса) и итог по мерам объекта.
    object_hosts: Mapped[list] = mapped_column(JsonType, default=list)
    # {measures, implemented, partial, not_implemented, unassessed, applied, kept_manual}
    summary: Mapped[dict] = mapped_column(JsonType, default=dict)
    # sha256 ответов и состава — повторный импорт без изменений не создаёт дубль.
    content_hash: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(300))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    imported_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    imported_by_name: Mapped[str | None] = mapped_column(String(200))


class Evidence(Base):
    """Доказательство по мере объекта. В 1.9 — автоматическое из снимка «Сканера»;
    ручные (файл, интервью, осмотр) — задача 1.10."""

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_measure", "object_measure_id", "created_at"),
        Index("ix_evidence_snapshot", "snapshot_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_measure_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("object_measures.id", ondelete="CASCADE")
    )
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    measure_id: Mapped[str] = mapped_column(String(32))
    # scanner | file | interview | inspection | certificate
    kind: Mapped[str] = mapped_column(String(16))
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scanner_snapshots.id", ondelete="CASCADE")
    )
    # Предложенный статус (для scanner) и краткое пояснение.
    status: Mapped[str | None] = mapped_column(String(16))
    summary: Mapped[str] = mapped_column(String(1000))
    # scanner: AutoResult + проверки и нарушения по хостам, рекомендации.
    data: Mapped[dict] = mapped_column(JsonType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
