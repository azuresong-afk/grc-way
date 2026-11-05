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
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    Uuid,
    text,
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
    # Проект в «Устранении», куда уходят заявки по несоответствиям (задача 3.4).
    vm_project_id: Mapped[str | None] = mapped_column(String(64))
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
    # Шрифт документов комплекта (встроенные шаблоны): astra | inter; None — astra.
    doc_font: Mapped[str | None] = mapped_column(String(16))

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
    # Инвентаризация для I_infr (Методика 2025, п. 14): коды типов компонента —
    # значения показателя K справочника; доступность из сети «Интернет».
    # NULL — не указано («Сканер» эти поля не заполняет и не меняет).
    component_types: Mapped[list | None] = mapped_column(JsonType)
    internet_exposed: Mapped[bool | None] = mapped_column(Boolean)
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
    # Подтверждение итогового статуса испытателем. Снимается, когда меняется статус,
    # меру исключают или отзывают доказательство, на которое оно опиралось.
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confirmed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    confirmed_by_name: Mapped[str | None] = mapped_column(String(200))
    confirmed_status: Mapped[str | None] = mapped_column(String(16))
    confirm_comment: Mapped[str | None] = mapped_column(String(2000))
    # id доказательств, на которые опиралось подтверждение.
    confirmed_evidence: Mapped[list] = mapped_column(JsonType, default=list)


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
    # Находки прогона с идентификаторами БДУ на хостах объекта (задача 2.4), без
    # ложных срабатываний; None — снимок сделан до того, как находки импортировались.
    findings: Mapped[list | None] = mapped_column(JsonType)
    # {measures, implemented, partial, not_implemented, unassessed, applied, kept_manual}
    summary: Mapped[dict] = mapped_column(JsonType, default=dict)
    # sha256 ответов и состава — повторный импорт без изменений не создаёт дубль.
    content_hash: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(300))
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    imported_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    imported_by_name: Mapped[str | None] = mapped_column(String(200))


class EvidenceFile(Base):
    """Файл доказательства. Содержимое — в томе под именем sha256 (app/domain/evidence_files.py);
    одинаковое содержимое хранится один раз, записей может быть несколько."""

    __tablename__ = "files"
    __table_args__ = (Index("ix_files_sha256", "sha256"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    sha256: Mapped[str] = mapped_column(String(64))
    # Имя, как его прислали (без пути); тип определён по содержимому.
    name: Mapped[str] = mapped_column(String(255))
    ext: Mapped[str] = mapped_column(String(8))
    mime: Mapped[str] = mapped_column(String(100))
    size: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))


class Evidence(Base):
    """Доказательство по мере объекта: автоматическое из снимка «Сканера» (1.9)
    или ручное — файл, интервью, осмотр (1.10). Ручное не удаляется, а отзывается."""

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
    # scanner: AutoResult + проверки и нарушения по хостам, рекомендации;
    # ручные: дата, участники, место, подробности, категория файла.
    data: Mapped[dict] = mapped_column(JsonType, default=dict)
    file_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("files.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_by_name: Mapped[str | None] = mapped_column(String(200))
    withdraw_reason: Mapped[str | None] = mapped_column(String(1000))


class RefThreatItem(Base):
    """Запись справочника Методики оценки угроз (ФСТЭК России, 2021).

    Виды записей (kind): consequence_type — вид негативных последствий У1–У3;
    consequence — пример последствия (родитель — вид); capability — уровень
    возможностей нарушителя Н1–Н4; intruder — вид нарушителя (attrs.capability —
    типовой уровень, attrs.category — внешний/внутренний); tactic — тактика Т1–Т10;
    technique — техника (родитель — тактика).
    """

    __tablename__ = "ref_threat_items"
    __table_args__ = (Index("ix_ref_threat_items_kind", "kind", "position"),)

    code: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(32))
    parent_code: Mapped[str | None] = mapped_column(String(32))
    position: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(1000))
    description: Mapped[str | None] = mapped_column(String(4000))
    attrs: Mapped[dict] = mapped_column(JsonType, default=dict)
    # {document, clause, appendix, url, note}
    source: Mapped[dict] = mapped_column(JsonType, default=dict)
    origin: Mapped[str] = mapped_column(String(16))  # stub | official | local
    verified_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    verified_by_name: Mapped[str | None] = mapped_column(String(200))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    # Хэш записи в файле при последней загрузке: неизменённая в файле запись при
    # старте не трогается (и не откатывает правку из интерфейса). NULL — запись
    # добавлена в интерфейсе.
    file_hash: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)


class BduImport(Base):
    """Загрузка выгрузки БДУ: сравнение с текущими данными и его применение.

    Файл хранится в томе под sha256; при применении он разбирается заново, и
    сравнение пересчитывается — если данные изменились, применение отклоняется.
    """

    __tablename__ = "bdu_imports"
    __table_args__ = (Index("ix_bdu_imports_kind", "kind", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(16))  # threats | vulns
    file_name: Mapped[str] = mapped_column(String(255))
    file_sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(BigInteger)
    export_version: Mapped[date | None] = mapped_column(Date)
    version_source: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16))  # pending | applied | superseded
    summary: Mapped[dict] = mapped_column(JsonType)
    items: Mapped[list] = mapped_column(JsonType)
    warnings: Mapped[list] = mapped_column(JsonType)
    fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    applied_by_name: Mapped[str | None] = mapped_column(String(200))
    applied: Mapped[dict | None] = mapped_column(JsonType)


class _BduRecord:
    """Общие поля записей БДУ: хэш, версии выгрузки, исключение из выгрузки."""

    row_hash: Mapped[str] = mapped_column(String(64))
    first_version: Mapped[date | None] = mapped_column(Date)
    changed_version: Mapped[date | None] = mapped_column(Date)
    first_import_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    changed_import_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    # Запись пропала из выгрузки: не удаляется (на неё могут ссылаться модели угроз).
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_import_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BduThreat(_BduRecord, Base):
    """Угроза безопасности информации из БДУ (thrlist.xlsx)."""

    __tablename__ = "bdu_threats"

    code: Mapped[str] = mapped_column(String(16), primary_key=True)  # УБИ.001
    number: Mapped[int] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(1000))
    description: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str | None] = mapped_column(Text)
    target: Mapped[str | None] = mapped_column(Text)
    conf: Mapped[bool | None] = mapped_column(Boolean)
    integ: Mapped[bool | None] = mapped_column(Boolean)
    avail: Mapped[bool | None] = mapped_column(Boolean)
    published_on: Mapped[date | None] = mapped_column(Date)
    changed_on: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str | None] = mapped_column(Text)


class BduVuln(_BduRecord, Base):
    """Уязвимость из БДУ (vullist.xlsx) с полями для Методики критичности 2025."""

    __tablename__ = "bdu_vulns"
    __table_args__ = (Index("ix_bdu_vulns_crit_changed", "criticality_changed_at"),)

    bdu_id: Mapped[str] = mapped_column(String(32), primary_key=True)  # BDU:2024-04835
    title: Mapped[str] = mapped_column(String(2000))
    description: Mapped[str | None] = mapped_column(Text)
    vendor: Mapped[str | None] = mapped_column(Text)
    product: Mapped[str | None] = mapped_column(Text)
    product_version: Mapped[str | None] = mapped_column(Text)
    sw_type: Mapped[str | None] = mapped_column(Text)
    platform: Mapped[str | None] = mapped_column(Text)
    vuln_class: Mapped[str | None] = mapped_column(Text)
    identified_on: Mapped[date | None] = mapped_column(Date)
    published_on: Mapped[date | None] = mapped_column(Date)
    severity: Mapped[str | None] = mapped_column(Text)
    cvss3_vector: Mapped[str | None] = mapped_column(String(200))
    cvss3_version: Mapped[str | None] = mapped_column(String(8))
    cvss3_score: Mapped[float | None] = mapped_column(Float)
    cvss3_score_source: Mapped[str | None] = mapped_column(String(16))  # bdu | computed
    # {cvss2: {vector, score}, cvss4: {vector, score}}
    cvss_other: Mapped[dict | None] = mapped_column(JsonType)
    measures: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str | None] = mapped_column(Text)
    exploit: Mapped[str | None] = mapped_column(String(16))  # public|exists|unknown|none|other
    exploit_raw: Mapped[str | None] = mapped_column(String(500))
    in_wild: Mapped[str | None] = mapped_column(String(16))  # yes|no|unknown|other
    in_wild_raw: Mapped[str | None] = mapped_column(String(500))
    fix_info: Mapped[str | None] = mapped_column(Text)
    links: Mapped[str | None] = mapped_column(Text)
    cve_ids: Mapped[list] = mapped_column(JsonType, default=list)
    cwe_ids: Mapped[list] = mapped_column(JsonType, default=list)
    other_ids: Mapped[str | None] = mapped_column(Text)
    other_info: Mapped[str | None] = mapped_column(Text)
    exploit_method: Mapped[str | None] = mapped_column(Text)
    fix_method: Mapped[str | None] = mapped_column(Text)
    # Хэш полей, влияющих на уровень критичности (CVSS, эксплойт, эксплуатация, статус).
    crit_hash: Mapped[str] = mapped_column(String(64))
    # Когда эти поля последний раз изменились при загрузке выгрузки: оценки критичности,
    # сделанные раньше, требуют пересчёта (Методика 2025, п. 16, 19; задача 2.8).
    criticality_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    criticality_changed_import_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    # {поле: [было, стало]} последнего такого изменения.
    criticality_changes: Mapped[dict | None] = mapped_column(JsonType)


# ---------- Модель угроз ----------


class ThreatModel(Base):
    """Версия модели угроз объекта по Методике 2021: черновик → утверждена → заменена.

    Шаги мастера (последствия, объекты воздействия, нарушители, способы, сценарии)
    хранятся в steps; угрозы БДУ с решением об актуальности — в ThreatModelThreat.
    Утверждённая версия не меняется: правка начинается с новой версии-черновика,
    скопированной с неё. При утверждении в snapshot фиксируются записи справочника
    и угрозы БДУ в том виде, в каком их видел утверждающий.
    """

    __tablename__ = "threat_models"
    __table_args__ = (Index("ux_threat_models_version", "object_id", "version", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    # draft | approved | superseded
    status: Mapped[str] = mapped_column(String(16), default="draft")
    # {consequences: {...}, objects: {...}, intruders: {...}, methods: {...}, scenarios: {...}}
    steps: Mapped[dict] = mapped_column(JsonType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
    # Версия, с которой скопирован черновик.
    based_on: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    # Кто менял эту версию (id строками): им утверждать нельзя.
    editors: Mapped[list] = mapped_column(JsonType, default=list)
    edits: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    approved_by_name: Mapped[str | None] = mapped_column(String(200))
    approval_comment: Mapped[str | None] = mapped_column(String(2000))
    # Утверждающий подтвердил, что записи справочника Методики не сверены.
    unverified_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    # {refs: {code: {kind, title, revision, verified}}, bdu: {code: {title, version}}}
    snapshot: Mapped[dict | None] = mapped_column(JsonType)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    threats: Mapped[list[ThreatModelThreat]] = relationship(
        cascade="all, delete-orphan", lazy="selectin", order_by="ThreatModelThreat.threat_code"
    )


class ThreatModelThreat(Base):
    """Угроза БДУ, рассмотренная в модели: актуальна или нет, почему, через что.

    Ссылки на шаги модели: intruders — коды актуальных нарушителей (НВ…),
    objects — ключи объектов воздействия, consequences — коды последствий,
    methods — коды способов (СР…), tactics — коды тактик и техник.
    linked_findings — находки «Сканера» с bdu_ids (задача 2.4).
    """

    __tablename__ = "threat_model_threats"
    __table_args__ = (
        Index("ux_threat_model_threats_code", "model_id", "threat_code", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    model_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("threat_models.id", ondelete="CASCADE"))
    threat_code: Mapped[str] = mapped_column(String(16))  # УБИ.006
    # None — решение ещё не принято.
    relevant: Mapped[bool | None] = mapped_column(Boolean)
    justification: Mapped[str | None] = mapped_column(String(4000))
    intruders: Mapped[list] = mapped_column(JsonType, default=list)
    objects: Mapped[list] = mapped_column(JsonType, default=list)
    consequences: Mapped[list] = mapped_column(JsonType, default=list)
    methods: Mapped[list] = mapped_column(JsonType, default=list)
    tactics: Mapped[list] = mapped_column(JsonType, default=list)
    linked_findings: Mapped[list] = mapped_column(JsonType, default=list)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by_name: Mapped[str | None] = mapped_column(String(200))


# ---------- СЗИ ----------


class SziImport(Base):
    """Загрузка реестра сертифицированных СЗИ (CSV/XLSX): сравнение → применение.

    Как у БДУ: файл хранится в томе под sha256, при применении разбирается заново,
    и если сравнение изменилось, применение отклоняется.
    """

    __tablename__ = "szi_imports"
    __table_args__ = (Index("ix_szi_imports_created", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    file_name: Mapped[str] = mapped_column(String(255))
    file_sha256: Mapped[str] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(BigInteger)
    file_ext: Mapped[str] = mapped_column(String(8))  # csv | xlsx
    export_version: Mapped[date | None] = mapped_column(Date)
    version_source: Mapped[str] = mapped_column(String(16))  # user | title | file | none
    status: Mapped[str] = mapped_column(String(16))  # pending | applied | superseded
    summary: Mapped[dict] = mapped_column(JsonType)
    items: Mapped[list] = mapped_column(JsonType)
    warnings: Mapped[list] = mapped_column(JsonType)
    fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    applied_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    applied_by_name: Mapped[str | None] = mapped_column(String(200))
    applied: Mapped[dict | None] = mapped_column(JsonType)


class SziCert(Base):
    """Запись реестра сертифицированных СЗИ: один сертификат ФСТЭК России.

    Ключ — номер сертификата. Пропавшая из реестра запись не удаляется, а
    помечается исключённой: на неё ссылаются СЗИ объектов.
    """

    __tablename__ = "szi_registry"
    __table_args__ = (Index("ix_szi_registry_valid_to", "valid_to"),)

    cert_number: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(2000))
    registered_on: Mapped[date | None] = mapped_column(Date)
    valid_to: Mapped[date | None] = mapped_column(Date)
    # Текст ячейки «Срок действия», если в нём не только дата.
    valid_to_raw: Mapped[str | None] = mapped_column(String(500))
    requirements: Mapped[str | None] = mapped_column(Text)
    scheme: Mapped[str | None] = mapped_column(Text)
    lab: Mapped[str | None] = mapped_column(Text)
    cert_body: Mapped[str | None] = mapped_column(Text)
    applicant: Mapped[str | None] = mapped_column(Text)
    applicant_details: Mapped[str | None] = mapped_column(Text)
    support_until: Mapped[date | None] = mapped_column(Date)
    support_raw: Mapped[str | None] = mapped_column(String(1000))
    note: Mapped[str | None] = mapped_column(Text)
    # active | suspended | terminated — по тексту примечания (эвристика, требует сверки).
    cert_status: Mapped[str] = mapped_column(String(16), default="active")
    # Уровень доверия и профили защиты, найденные в «Наименованиях документов»
    # (эвристика: в реестре это свободный текст).
    trust_level: Mapped[int | None] = mapped_column(Integer)
    profiles: Mapped[list] = mapped_column(JsonType, default=list)
    row_hash: Mapped[str] = mapped_column(String(64))
    first_version: Mapped[date | None] = mapped_column(Date)
    changed_version: Mapped[date | None] = mapped_column(Date)
    first_import_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    changed_import_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    withdrawn_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    withdrawn_import_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ObjectSzi(Base):
    """Средство защиты информации на объекте.

    Номер сертификата сопоставляется с реестром (SziCert): срок действия, уровень
    доверия и состояние сертификата берутся оттуда, если запись есть; иначе —
    введённые вручную. measure_ids — коды мер набора объекта, которые закрывает СЗИ.
    """

    __tablename__ = "object_szi"
    __table_args__ = (
        Index("ix_object_szi_object", "object_id"),
        Index("ix_object_szi_cert", "cert_number"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(300))
    # Вид средства (код из app/domain/szi.py: fw, av, nsd, …).
    kind: Mapped[str] = mapped_column(String(16))
    vendor: Mapped[str | None] = mapped_column(String(300))
    version: Mapped[str | None] = mapped_column(String(100))
    cert_number: Mapped[str | None] = mapped_column(String(32))
    # Введено вручную; при наличии записи в реестре действуют её значения.
    cert_valid_to: Mapped[date | None] = mapped_column(Date)
    trust_level: Mapped[int | None] = mapped_column(Integer)
    protection_class: Mapped[str | None] = mapped_column(String(200))
    # Где установлено: хосты, сегменты, количество лицензий.
    placement: Mapped[str | None] = mapped_column(String(2000))
    measure_ids: Mapped[list] = mapped_column(JsonType, default=list)
    comment: Mapped[str | None] = mapped_column(String(2000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    updated_by_name: Mapped[str | None] = mapped_column(String(200))


class RefVulnMethodology(Base):
    """Методика оценки уровня критичности уязвимостей (ФСТЭК России, 30.06.2025).

    Определение — данные (см. app/domain/vuln_criticality.py): показатели таблицы 1,
    уровни таблицы 2 со сроками п. 21, компенсирующие меры п. 25, контрольные
    примеры приложения. Хранится и сверяется целиком, как таблица классификации:
    каждая правка — новая ревизия, прежнее определение — в ref_revisions.
    """

    __tablename__ = "ref_vuln_methodologies"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(500))
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


class RefDocument(Base):
    """Нормативный документ: реквизиты и статус (применяется / не применяется).

    Документ, который заменён, остаётся в справочнике со ссылкой на заменивший
    его (replaced_by) и основанием в source — например, Методика критичности
    уязвимостей 2022 г. «не применяется» по п. 6 Методики 2025 г.
    """

    __tablename__ = "ref_documents"

    code: Mapped[str] = mapped_column(String(64), primary_key=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    short: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(1000))
    issuer: Mapped[str | None] = mapped_column(String(200))
    issued: Mapped[date | None] = mapped_column(Date)
    number: Mapped[str | None] = mapped_column(String(32))
    url: Mapped[str | None] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(16))  # active | not_applicable
    replaced_by: Mapped[str | None] = mapped_column(String(64))
    # Основание реквизитов и статуса: {document, clause, appendix, url, note}
    source: Mapped[dict] = mapped_column(JsonType, default=dict)
    origin: Mapped[str] = mapped_column(String(16))  # stub | official | local
    verified_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    verified_by_name: Mapped[str | None] = mapped_column(String(200))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revision: Mapped[int] = mapped_column(Integer, default=1)
    # Хэш записи в файле при последней загрузке (как у RefThreatItem); NULL —
    # документ добавлен в интерфейсе.
    file_hash: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)


# ---------- Реестр уязвимостей объекта ----------


class ObjectVuln(Base):
    """Уязвимость в реестре объекта (Методика оценки критичности уязвимостей 2025, задача 2.8).

    Одна запись на идентификатор БДУ в объекте: хосты берутся из находок текущего
    снимка «Сканера» (scanner_hosts) и из результатов контроля защищённости,
    внесённых специалистом (manual_hosts, п. 8 «г»). Уязвимость без идентификатора
    БДУ вносится только вручную. Выбор специалиста (CVSS, если в БДУ нет 3.1; E; H;
    отметка п. 4) хранится здесь, оценки — в ObjectVulnAssessment.
    """

    __tablename__ = "object_vulns"
    __table_args__ = (
        Index("ix_object_vulns_object", "object_id"),
        Index("ix_object_vulns_bdu", "bdu_id"),
        Index(
            "ux_object_vulns_bdu",
            "object_id",
            "bdu_id",
            unique=True,
            postgresql_where=text("bdu_id IS NOT NULL"),
            sqlite_where=text("bdu_id IS NOT NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    # Ключ записи в объекте: BDU:2024-04835; NULL — уязвимость без идентификатора БДУ.
    bdu_id: Mapped[str | None] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(2000))
    description: Mapped[str | None] = mapped_column(Text)
    origin: Mapped[str] = mapped_column(String(16))  # scanner | manual
    # Результаты контроля защищённости: pentest | exercise | experiment | other.
    manual_source: Mapped[str | None] = mapped_column(String(16))
    manual_hosts: Mapped[list] = mapped_column(JsonType, default=list)
    # Из текущего снимка «Сканера»: адреса и находки (поля FINDING_FIELDS).
    scanner_hosts: Mapped[list] = mapped_column(JsonType, default=list)
    scanner_findings: Mapped[list] = mapped_column(JsonType, default=list)
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    snapshot_number: Mapped[int | None] = mapped_column(Integer)
    # Снимок, в котором уязвимость последний раз была найдена.
    last_seen_snapshot: Mapped[int | None] = mapped_column(Integer)
    # Выбор специалиста.
    cvss_choice: Mapped[dict | None] = mapped_column(JsonType)
    e_choice: Mapped[list] = mapped_column(JsonType, default=list)
    h_choice: Mapped[list] = mapped_column(JsonType, default=list)
    certified_szi: Mapped[bool] = mapped_column(Boolean, default=False)
    comment: Mapped[str | None] = mapped_column(String(2000))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    updated_by_name: Mapped[str | None] = mapped_column(String(200))


class ObjectVulnAssessment(Base):
    """Оценка критичности уязвимости объекта. Неизменяема (UPDATE запрещён триггером).

    Повторный расчёт — новая оценка с номером на единицу больше; текущая —
    последняя. В записи — всё, чтобы показать «как посчитано» без справочника:
    исходные данные, трассировка расчёта, ревизия Методики, снимок и сведения БДУ.
    """

    __tablename__ = "object_vuln_assessments"
    __table_args__ = (Index("ux_object_vuln_assessments", "vuln_id", "number", unique=True),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    vuln_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("object_vulns.id", ondelete="CASCADE"))
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    number: Mapped[int] = mapped_column(Integer)
    # choices | manual | snapshot | bdu | recalc — что вызвало расчёт.
    trigger: Mapped[str] = mapped_column(String(16))
    reasons: Mapped[list] = mapped_column(JsonType, default=list)
    hosts: Mapped[list] = mapped_column(JsonType, default=list)
    inputs: Mapped[dict] = mapped_column(JsonType)
    outcome: Mapped[dict] = mapped_column(JsonType)
    # Откуда взяты значения: cvss, exploitation, infra, notes.
    details: Mapped[dict] = mapped_column(JsonType, default=dict)
    v: Mapped[str] = mapped_column(String(16))
    level: Mapped[str] = mapped_column(String(16))
    level_title: Mapped[str] = mapped_column(String(100))
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Номер оценки, от которой отсчитан срок (тот же уровень — срок не продлевается).
    deadline_from: Mapped[int] = mapped_column(Integer)
    methodology_id: Mapped[str] = mapped_column(String(32))
    methodology_version: Mapped[str] = mapped_column(String(64))
    methodology_revision: Mapped[int] = mapped_column(Integer)
    methodology_hash: Mapped[str] = mapped_column(String(64))
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    snapshot_number: Mapped[int | None] = mapped_column(Integer)
    bdu_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fingerprint: Mapped[str] = mapped_column(String(64))
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    assessed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    assessed_by_name: Mapped[str | None] = mapped_column(String(200))


# ---------- Документы комплекта ----------


class GeneratedDocument(Base):
    """Сформированный документ комплекта (задача 3.1): версия DOCX и PDF.

    Каждое формирование — новая версия с номером на единицу больше; прежние
    сохраняются. В записи — контекст, по которому собран документ, карта полей
    («из каких данных собран / что пусто») и несверенные записи справочников:
    что попало в версию, видно и после правки данных. Файлы — в томе
    GRC_DOCUMENTS_DIR под именем sha256.

    Согласование (задача 3.3): проект → на согласовании → утверждён; прежняя
    утверждённая версия после утверждения новой — «заменён». Утверждение
    пересобирает файлы без отметки «Проект» (файлы проекта — draft_*_sha256).
    """

    __tablename__ = "documents"
    __table_args__ = (
        Index("ux_documents_version", "object_id", "doc_type", "version", unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    # Код документа из каталога reference/documents/catalog.yaml.
    doc_type: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    version: Mapped[int] = mapped_column(Integer)
    # draft — проект; review — на согласовании; approved — утверждён;
    # superseded — заменён более новой утверждённой версией.
    status: Mapped[str] = mapped_column(String(16), default="draft")
    template_name: Mapped[str] = mapped_column(String(200))
    template_sha256: Mapped[str] = mapped_column(String(64))
    # Хэш контекста и шаблона: тот же — документ не формируется заново.
    context_hash: Mapped[str] = mapped_column(String(64))
    context: Mapped[dict] = mapped_column(JsonType)
    field_map: Mapped[list] = mapped_column(JsonType)
    unverified: Mapped[list] = mapped_column(JsonType, default=list)
    # Водяной знак «Проект» и почему он стоит.
    watermark: Mapped[bool] = mapped_column(Boolean, default=True)
    watermark_reasons: Mapped[list] = mapped_column(JsonType, default=list)
    docx_sha256: Mapped[str] = mapped_column(String(64))
    docx_size: Mapped[int] = mapped_column(BigInteger)
    pdf_sha256: Mapped[str | None] = mapped_column(String(64))
    pdf_size: Mapped[int | None] = mapped_column(BigInteger)
    # Почему нет PDF (LibreOffice не установлен, не уложился во время…).
    pdf_error: Mapped[str | None] = mapped_column(String(1000))
    # Шрифт встроенного шаблона (astra | inter); None — свой шаблон, шрифты его.
    font: Mapped[str | None] = mapped_column(String(16))
    # Свой шаблон (document_templates); None — встроенный.
    template_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    created_by_name: Mapped[str | None] = mapped_column(String(200))
    # Согласование (задача 3.3).
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submitted_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    submitted_by_name: Mapped[str | None] = mapped_column(String(200))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    approved_by_name: Mapped[str | None] = mapped_column(String(200))
    approval_comment: Mapped[str | None] = mapped_column(String(2000))
    # Утверждён, хотя в нём есть несверенные записи справочников.
    unverified_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Файлы проекта, если утверждение пересобрало документ.
    draft_docx_sha256: Mapped[str | None] = mapped_column(String(64))
    draft_pdf_sha256: Mapped[str | None] = mapped_column(String(64))


class DocumentReview(Base):
    """Событие согласования версии документа (задача 3.3).

    submit — отправлен на согласование; return — возвращён на доработку (с
    причиной); approve — утверждён; supersede — заменён новой утверждённой.
    """

    __tablename__ = "document_reviews"
    __table_args__ = (Index("ix_document_reviews_doc", "document_id", "at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    document_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("documents.id", ondelete="CASCADE"))
    action: Mapped[str] = mapped_column(String(16))
    from_status: Mapped[str] = mapped_column(String(16))
    to_status: Mapped[str] = mapped_column(String(16))
    comment: Mapped[str | None] = mapped_column(String(2000))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_name: Mapped[str | None] = mapped_column(String(200))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DocumentTemplate(Base):
    """Свой (фирменный) шаблон документа комплекта, загруженный пользователем (задача 3.2).

    Общий для всех проектов: шаблон — оформление компании-исполнителя. Действующий —
    не более одного на код документа; загрузка нового делает прежний недействующим,
    «вернуть встроенный» — снимает действующий. Записи не удаляются: по template_id
    версии документа видно, по какому шаблону она собрана. Файл — в томе
    GRC_DOCUMENTS_DIR/templates под именем sha256.
    """

    __tablename__ = "document_templates"
    __table_args__ = (
        Index("ix_document_templates_type", "doc_type", "uploaded_at"),
        Index(
            "ux_document_templates_active",
            "doc_type",
            unique=True,
            postgresql_where=text("active"),
            sqlite_where=text("active"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    doc_type: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    # Имена верхнего уровня, которые использует шаблон (проверены при загрузке).
    variables: Mapped[list] = mapped_column(JsonType, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    comment: Mapped[str | None] = mapped_column(String(1000))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    uploaded_by_name: Mapped[str | None] = mapped_column(String(200))
    deactivated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deactivated_by_name: Mapped[str | None] = mapped_column(String(200))


# ---------- Несоответствия и «Устранение» (задача 3.4) ----------


class Nonconformity(Base):
    """Пункт плана устранения: мера «Не реализована / Частично» или уязвимость.

    План собирается из текущих данных объекта (app/api/nonconformities.sync_plan);
    здесь хранится то, что вносит специалист, копия оценки уязвимости и заявка в
    «Устранении». Пункт, источник которого перестал быть несоответствием,
    закрывается (closed_at), а не удаляется: история заявки остаётся.
    """

    __tablename__ = "nonconformities"
    __table_args__ = (
        Index("ix_nonconformities_object", "object_id"),
        Index("ux_nonconformities_measure", "object_measure_id", unique=True),
        Index("ux_nonconformities_vuln", "object_vuln_id", unique=True),
        Index("ix_nonconformities_ticket", "vm_ticket_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    object_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("objects.id", ondelete="CASCADE"))
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(8))  # measure | vuln
    object_measure_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("object_measures.id", ondelete="CASCADE")
    )
    object_vuln_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("object_vulns.id", ondelete="CASCADE")
    )
    # Мера — её код (УПД.1); уязвимость — идентификатор БДУ или «без БДУ».
    ref: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(2000))
    # Мера — итоговый статус (not_implemented | partial); уязвимость — состояние реестра.
    source_status: Mapped[str | None] = mapped_column(String(16))
    hosts: Mapped[list] = mapped_column(JsonType, default=list)
    details: Mapped[str | None] = mapped_column(String(4000))
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    v: Mapped[str | None] = mapped_column(String(16))
    level: Mapped[str | None] = mapped_column(String(16))
    level_title: Mapped[str | None] = mapped_column(String(100))
    assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    certified_szi: Mapped[bool] = mapped_column(Boolean, default=False)
    priority: Mapped[str | None] = mapped_column(String(8))  # high | medium | low
    due_date: Mapped[date | None] = mapped_column(Date)
    action: Mapped[str | None] = mapped_column(String(2000))
    responsible: Mapped[str | None] = mapped_column(String(300))
    comment: Mapped[str | None] = mapped_column(String(2000))
    # Способ устранения уязвимости (п. 22): update | compensating.
    method: Mapped[str | None] = mapped_column(String(16))
    # Обновление: чьё ПО (foreign | opensource | domestic) и отметка о тестировании (п. 23).
    update_origin: Mapped[str | None] = mapped_column(String(16))
    update_tested: Mapped[bool | None] = mapped_column(Boolean)
    # Компенсирующие меры из перечня п. 25: коды CM1…CM5.
    compensating: Mapped[list] = mapped_column(JsonType, default=list)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    close_reason: Mapped[str | None] = mapped_column(String(500))
    vm_ticket_id: Mapped[str | None] = mapped_column(String(64))
    vm_project_id: Mapped[str | None] = mapped_column(String(64))
    vm_status: Mapped[str | None] = mapped_column(String(32))
    vm_status_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    vm_verified_result: Mapped[str | None] = mapped_column(String(32))
    vm_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    vm_verified_run_id: Mapped[str | None] = mapped_column(String(64))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    sent_by_name: Mapped[str | None] = mapped_column(String(200))
    # Хэш отправленного содержимого: изменилась оценка или способ — «отправьте повторно».
    sent_hash: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by_name: Mapped[str | None] = mapped_column(String(200))


class NonconformityEvent(Base):
    """История пункта плана: открыт, закрыт, отправлен, статус заявки, проверка."""

    __tablename__ = "nonconformity_events"
    __table_args__ = (Index("ix_nonconformity_events_nc", "nonconformity_id", "at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    nonconformity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("nonconformities.id", ondelete="CASCADE")
    )
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    kind: Mapped[str] = mapped_column(String(32))
    text: Mapped[str] = mapped_column(String(1000))
    data: Mapped[dict] = mapped_column(JsonType, default=dict)
    actor_name: Mapped[str | None] = mapped_column(String(200))


class InboxEvent(Base):
    """Принятое событие «Платформы» или «Устранения»: повтор с тем же id не обрабатывается."""

    __tablename__ = "inbox"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    type: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(32))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # applied | ignored | unknown_ticket | stale
    result: Mapped[str] = mapped_column(String(32))
