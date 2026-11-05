"""Схемы запросов и ответов API."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 — тип токена, не секрет
    expires_in: int


class MeOut(BaseModel):
    id: uuid.UUID
    username: str
    display_name: str
    roles: list[str]
    permissions: list[str]
    # local | platform — интерфейс прячет свой вход и управление пользователями.
    auth_mode: str = "local"
    # Сервисная учётная запись платформы (typ=service).
    service: bool = False


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    display_name: str
    roles: list[str]
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None
    # Теневая запись «Платформы» (задача 3.5): sub, user | service, последний запрос.
    platform_sub: str | None = None
    platform_typ: str | None = None
    platform_seen_at: datetime | None = None


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    display_name: str = Field(min_length=1, max_length=200)
    password: str = Field(max_length=1024)
    roles: list[str]


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=200)
    password: str | None = Field(default=None, max_length=1024)
    roles: list[str] | None = None
    is_active: bool | None = None


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    at: datetime
    user_id: uuid.UUID | None
    user_name: str | None
    action: str
    entity: str | None
    entity_id: str | None
    project_id: uuid.UUID | None
    result: str
    ip: str | None
    details: dict[str, Any]


INN = r"^(\d{10}|\d{12})$"
OGRN = r"^(\d{13}|\d{15})$"


class Contact(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    position: str | None = Field(default=None, max_length=200)
    phone: str | None = Field(default=None, max_length=50)
    email: str | None = Field(default=None, max_length=200)


class CustomerIn(BaseModel):
    name: str = Field(min_length=1, max_length=300)
    inn: str | None = Field(default=None, pattern=INN)
    ogrn: str | None = Field(default=None, pattern=OGRN)
    address: str | None = Field(default=None, max_length=500)
    contacts: list[Contact] = Field(default_factory=list, max_length=50)


class CustomerPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=300)
    inn: str | None = Field(default=None, pattern=INN)
    ogrn: str | None = Field(default=None, pattern=OGRN)
    address: str | None = Field(default=None, max_length=500)
    contacts: list[Contact] | None = Field(default=None, max_length=50)


class CustomerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    inn: str | None
    ogrn: str | None
    address: str | None
    contacts: list[Contact]
    created_at: datetime


class ProjectIn(BaseModel):
    customer_id: uuid.UUID
    name: str = Field(min_length=1, max_length=300)
    contract_ref: str | None = Field(default=None, max_length=200)
    period_from: date | None = None
    period_to: date | None = None
    scanner_engagement_id: int | None = Field(default=None, ge=1)
    # Проект в «Устранении» (uuid или код), куда уходят заявки по несоответствиям.
    vm_project_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")


class ProjectPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=300)
    contract_ref: str | None = Field(default=None, max_length=200)
    period_from: date | None = None
    period_to: date | None = None
    status: str | None = Field(default=None, pattern=r"^(active|archived)$")
    scanner_engagement_id: int | None = Field(default=None, ge=1)
    # Проект в «Устранении» (uuid или код), куда уходят заявки по несоответствиям.
    vm_project_id: str | None = Field(default=None, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")


class MemberOut(BaseModel):
    id: uuid.UUID
    display_name: str
    roles: list[str]


class ProjectOut(BaseModel):
    id: uuid.UUID
    customer_id: uuid.UUID
    client: str
    name: str
    contract_ref: str | None
    period_from: date | None
    period_to: date | None
    status: str
    scanner_engagement_id: int | None
    vm_project_id: str | None
    platform_project_id: uuid.UUID | None
    created_at: datetime
    members: list[MemberOut]


class MembersIn(BaseModel):
    user_ids: list[uuid.UUID] = Field(max_length=500)
