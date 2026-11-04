"""Схемы запросов и ответов API."""

from __future__ import annotations

import uuid
from datetime import datetime
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


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    display_name: str
    roles: list[str]
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


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
