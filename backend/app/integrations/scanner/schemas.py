"""Схемы ответов API «Сканера», которые читает «Аттестация».

Повторяют `Profile.to_dict()` из scanner/compliance/catalog.py и ответ
`GET /compliance/profiles` (scanner/api/routes_compliance.py). Лишние поля
игнорируются, чтобы новая версия «Сканера» не ломала импорт; отсутствие
обязательных — ошибка «неожиданный ответ».
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)


class ScannerGroup(_Model):
    code: str = Field(min_length=1, max_length=16)
    title: str = Field(min_length=1, max_length=300)


class ScannerControl(_Model):
    id: str = Field(min_length=1, max_length=32)
    title: str = Field(min_length=1, max_length=500)
    group: str = Field(min_length=1, max_length=16)
    levels: list[str] = Field(default_factory=list)
    checks: list[str] = Field(default_factory=list)


class ScannerCheck(_Model):
    title: str = Field(min_length=1, max_length=500)
    platform: str = Field(default="any", max_length=16)


class ScannerProfile(_Model):
    id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=300)
    short: str = Field(min_length=1, max_length=100)
    document: str | None = Field(default=None, max_length=2000)
    url: str | None = Field(default=None, max_length=500)
    level_label: str | None = Field(default=None, max_length=100)
    levels: list[str] = Field(default_factory=list)
    default_level: str | None = Field(default=None, max_length=16)
    dynamic: str | None = Field(default=None, max_length=64)
    groups: list[ScannerGroup] = Field(default_factory=list)
    controls: list[ScannerControl] = Field(default_factory=list)
    checks: dict[str, ScannerCheck] = Field(default_factory=dict)


class ScannerGroupRef(_Model):
    id: int
    name: str = Field(min_length=1, max_length=200)


class ScannerAsset(_Model):
    """Актив договора — `AssetOut` из scanner/api/schemas.py (GET /engagements/{id}/assets)."""

    id: int
    engagement_id: int
    address: str = Field(min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    owner: str | None = Field(default=None, max_length=200)
    criticality: str | None = Field(default=None, max_length=16)
    tags: list[str] = Field(default_factory=list)
    groups: list[ScannerGroupRef] = Field(default_factory=list)
    os_guess: str | None = Field(default=None, max_length=200)
    os_family: str | None = Field(default=None, max_length=32)
    os_family_label: str | None = Field(default=None, max_length=100)
    findings_total: int = 0
    source: str = "manual"
    last_seen_at: datetime | None = None
