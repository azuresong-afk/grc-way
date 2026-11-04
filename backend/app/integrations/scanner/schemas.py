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


# ---------- Прогоны и их результаты (задача 1.9) ----------

# Завершённые прогоны — все, кроме pending/running (как FINISHED_RUN_STATUSES «Сканера»).
FINISHED_RUN_STATUSES = frozenset({"done", "partial", "failed", "stopped", "interrupted"})


class ScannerRun(_Model):
    """Прогон — `RunOut` из scanner/api/schemas.py."""

    id: int
    engagement_id: int
    name: str | None = Field(default=None, max_length=300)
    modules: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list)
    status: str = Field(min_length=1, max_length=32)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error_message: str | None = Field(default=None, max_length=4000)
    warnings: list[dict] = Field(default_factory=list)

    @property
    def finished(self) -> bool:
        return self.status in FINISHED_RUN_STATUSES


class ComplianceCheckFailure(_Model):
    id: str = Field(min_length=1, max_length=64)
    failures: list[dict] = Field(default_factory=list)
    more: int = 0


class ComplianceFailedHost(_Model):
    host: str = Field(min_length=1, max_length=64)
    checks: list[ComplianceCheckFailure] = Field(default_factory=list)


class ComplianceRecommendation(_Model):
    check: str = Field(min_length=1, max_length=64)
    title: str = Field(max_length=500)
    remediation: str | None = Field(default=None, max_length=8000)
    doc: str | None = Field(default=None, max_length=1000)


class ComplianceControl(_Model):
    """Мера с автопроверкой в сводке прогона (`summarize`, scanner/compliance/engine.py)."""

    id: str = Field(min_length=1, max_length=32)
    title: str = Field(max_length=500)
    group: str = Field(max_length=16)
    # passed | failed | na
    status: str = Field(pattern="^(passed|failed|na)$")
    # Сколько хостов дали каждый итог: {passed, failed, manual, na}.
    hosts: dict[str, int] = Field(default_factory=dict)
    failed_hosts: list[ComplianceFailedHost] = Field(default_factory=list)
    recommendations: list[ComplianceRecommendation] = Field(default_factory=list)


class ComplianceManual(_Model):
    id: str = Field(min_length=1, max_length=32)
    title: str = Field(max_length=500)
    group: str = Field(max_length=16)


class ScannerCompliance(_Model):
    """Ответ `GET /runs/{id}/compliance?profile=&level=`."""

    level: str | None = None
    percent: float | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    controls: list[ComplianceControl] = Field(default_factory=list)
    manual: list[ComplianceManual] = Field(default_factory=list)
    has_results: bool = True
    run_status: str | None = None


class CoverageModule(_Model):
    status: str = Field(min_length=1, max_length=32)
    label: str | None = Field(default=None, max_length=100)
    reason: str | None = Field(default=None, max_length=2000)


class CoverageHost(_Model):
    host: str = Field(min_length=1, max_length=64)
    status: str | None = Field(default=None, max_length=32)
    modules: dict[str, CoverageModule] = Field(default_factory=dict)


class ScannerCoverage(_Model):
    """Ответ `GET /runs/{id}/coverage`: что реально проверено (хост × модуль)."""

    scan_run_id: int
    status: str | None = None
    summary: dict = Field(default_factory=dict)
    hosts: list[CoverageHost] = Field(default_factory=list)
    legacy: bool = False
