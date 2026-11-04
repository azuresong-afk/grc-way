"""Клиент API «Сканера». Всё обращение к «Сканеру» — только через этот модуль.

- `LiveScannerClient` — REST API «Сканера» по токену сервисной учётной записи
  (роль auditor: только чтение). Токен берётся из GRC_SCANNER_TOKEN или
  получается через `POST /auth/token` по GRC_SCANNER_USERNAME/PASSWORD.
- `FixtureScannerClient` — сохранённые ответы из fixtures/: тесты, демо и стенд
  без «Сканера» (GRC_SCANNER_MODE=fixture).

Ошибки приводятся к `ScannerError` с понятным русским текстом; учётные данные
и токены в текст ошибок и журнал не попадают.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

import httpx
from pydantic import TypeAdapter, ValidationError

from app.core.config import Settings, get_settings
from app.integrations.scanner.schemas import (
    FINISHED_RUN_STATUSES,
    ScannerAsset,
    ScannerCompliance,
    ScannerCoverage,
    ScannerFinding,
    ScannerProfile,
    ScannerRun,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
_PROFILES = TypeAdapter(list[ScannerProfile])
_ASSETS = TypeAdapter(list[ScannerAsset])
_RUNS = TypeAdapter(list[ScannerRun])
_FINDINGS = TypeAdapter(list[ScannerFinding])
# Находки с идентификаторами БДУ без ложных срабатываний — как в «Сканере»
# GET /runs/{id}/findings?bdu_only=true&false_positives=exclude.
FINDINGS_PARAMS = {"bdu_only": "true", "false_positives": "exclude"}
# Сколько последних прогонов договора показывать для выбора.
RUNS_LIMIT = 100


class ScannerError(Exception):
    """«Сканер» недоступен или ответил не так, как ожидалось."""

    def __init__(self, message: str, code: str = "scanner_unavailable") -> None:
        super().__init__(message)
        self.code = code


class ScannerClient(Protocol):
    mode: str
    # Откуда берутся данные: адрес «Сканера» или имя фикстуры (для экрана и журнала).
    source: str

    def compliance_profiles(self) -> list[ScannerProfile]: ...

    def assets(self, engagement_id: int) -> list[ScannerAsset]: ...

    def runs(self, engagement_id: int) -> list[ScannerRun]: ...

    def run(self, run_id: int) -> ScannerRun: ...

    def run_compliance(self, run_id: int, profile: str, level: str | None) -> ScannerCompliance: ...

    def run_coverage(self, run_id: int) -> ScannerCoverage: ...

    def run_findings(self, run_id: int) -> list[ScannerFinding]: ...


def _parse_profiles(data: Any) -> list[ScannerProfile]:
    try:
        profiles = _PROFILES.validate_python(data)
    except ValidationError as e:
        first = e.errors()[0]
        where = ".".join(str(x) for x in first["loc"])
        raise ScannerError(
            f"«Сканер» вернул неожиданный ответ на GET /compliance/profiles ({where}: "
            f"{first['msg']})",
            code="scanner_bad_response",
        ) from e
    ids = [p.id for p in profiles]
    if len(ids) != len(set(ids)):
        raise ScannerError(
            "«Сканер» вернул профили с повторяющимися идентификаторами",
            code="scanner_bad_response",
        )
    for p in profiles:
        cids = [c.id for c in p.controls]
        if len(cids) != len(set(cids)):
            raise ScannerError(
                f"«Сканер» вернул повторяющиеся меры в профиле {p.id}",
                code="scanner_bad_response",
            )
        codes = {g.code for g in p.groups}
        if stray := sorted({c.group for c in p.controls} - codes):
            raise ScannerError(
                f"«Сканер»: в профиле {p.id} меры ссылаются на неизвестные группы: "
                f"{', '.join(stray)}",
                code="scanner_bad_response",
            )
    return profiles


def _parse_assets(data: Any, engagement_id: int) -> list[ScannerAsset]:
    try:
        assets = _ASSETS.validate_python(data)
    except ValidationError as e:
        first = e.errors()[0]
        where = ".".join(str(x) for x in first["loc"])
        raise ScannerError(
            f"«Сканер» вернул неожиданный ответ на GET /engagements/{engagement_id}/assets "
            f"({where}: {first['msg']})",
            code="scanner_bad_response",
        ) from e
    return assets


def _parse(adapter: Any, data: Any, what: str) -> Any:
    try:
        if isinstance(adapter, TypeAdapter):
            return adapter.validate_python(data)
        return adapter.model_validate(data)
    except ValidationError as e:
        first = e.errors()[0]
        where = ".".join(str(x) for x in first["loc"])
        raise ScannerError(
            f"«Сканер» вернул неожиданный ответ на {what} ({where}: {first['msg']})",
            code="scanner_bad_response",
        ) from e


def _level_summary(data: dict[str, Any], profile: ScannerProfile | None, level: str | None) -> dict:
    """Фикстура хранит все меры профиля; «Сканер» отдаёт только меры уровня.

    Отбираем меры по levels[] и пересчитываем сводные числа так же, как
    `summarize` в scanner/compliance/engine.py.
    """
    level = level or (profile.default_level if profile else None) or data.get("level")
    keep = (lambda c: level in (c.get("levels") or [])) if level else (lambda c: True)
    controls = [c for c in data.get("controls") or [] if keep(c)]
    manual = [c for c in data.get("manual") or [] if keep(c)]
    counts = {"passed": 0, "failed": 0, "manual": len(manual), "na": 0}
    for c in controls:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    done = counts["passed"] + counts["failed"]
    return {
        **data,
        "level": level,
        "controls": controls,
        "manual": manual,
        "failures": [c for c in controls if c["status"] == "failed"],
        "counts": counts,
        "evaluated": done,
        "automated": len(controls),
        "percent": round(100.0 * counts["passed"] / done, 1) if done else None,
    }


class FixtureScannerClient:
    mode = "fixture"

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or FIXTURES
        self.source = f"фикстура {self.directory.name}/compliance_profiles.json"

    def compliance_profiles(self) -> list[ScannerProfile]:
        path = self.directory / "compliance_profiles.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise ScannerError(f"Фикстура «Сканера» не читается: {path.name}") from e
        return _parse_profiles(data)

    def assets(self, engagement_id: int) -> list[ScannerAsset]:
        """Активы демо-договора; номер engagement подставляется запрошенный."""
        path = self.directory / "engagement_assets.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise ScannerError(f"Фикстура «Сканера» не читается: {path.name}") from e
        if isinstance(data, list):
            data = [{**a, "engagement_id": engagement_id} for a in data]
        return _parse_assets(data, engagement_id)

    def _read(self, name: str, missing: str | None = None) -> Any:
        path = self.directory / name
        if missing and not path.exists():
            raise ScannerError(missing, code="scanner_not_found")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise ScannerError(f"Фикстура «Сканера» не читается: {path.name}") from e

    def runs(self, engagement_id: int) -> list[ScannerRun]:
        """Прогоны демо-договора; номер engagement подставляется запрошенный."""
        data = self._read("engagement_runs.json")
        if isinstance(data, list):
            data = [{**r, "engagement_id": engagement_id} for r in data]
        return _parse(_RUNS, data, f"GET /engagements/{engagement_id}/runs")

    def run(self, run_id: int) -> ScannerRun:
        for r in self._read("engagement_runs.json"):
            if r.get("id") == run_id:
                return _parse(ScannerRun, r, f"GET /runs/{run_id}")
        raise ScannerError(f"В «Сканере» нет прогона №{run_id}", code="scanner_not_found")

    def run_compliance(self, run_id: int, profile: str, level: str | None) -> ScannerCompliance:
        data = self._read(
            f"run_{run_id}_compliance_{profile}.json",
            missing=f"В фикстуре «Сканера» нет результата прогона №{run_id} по профилю {profile}",
        )
        ref = next((p for p in self.compliance_profiles() if p.id == profile), None)
        if ref is not None and level is not None and ref.levels and level not in ref.levels:
            raise ScannerError(
                f"«Сканер»: для профиля {profile} нет уровня {level}", code="scanner_bad_response"
            )
        return _parse(
            ScannerCompliance,
            _level_summary(data, ref, level),
            f"GET /runs/{run_id}/compliance",
        )

    def run_coverage(self, run_id: int) -> ScannerCoverage:
        data = self._read(
            f"run_{run_id}_coverage.json",
            missing=f"В фикстуре «Сканера» нет покрытия прогона №{run_id}",
        )
        return _parse(ScannerCoverage, data, f"GET /runs/{run_id}/coverage")

    def run_findings(self, run_id: int) -> list[ScannerFinding]:
        """Находки прогона с БДУ без ложных срабатываний; нет файла — находок нет."""
        path = self.directory / f"run_{run_id}_findings.json"
        if not path.exists():
            return []
        data = self._read(path.name)
        rows = _parse(_FINDINGS, data, f"GET /runs/{run_id}/findings")
        return [f for f in rows if f.bdu_ids and f.false_positive is None]


class LiveScannerClient:
    mode = "live"

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self.source = settings.scanner_url.rstrip("/") or "адрес не задан"
        self._transport = transport
        self._token = settings.scanner_token or None

    def ensure_configured(self) -> None:
        if not self.settings.scanner_url:
            raise ScannerError(
                "Адрес «Сканера» не задан (GRC_SCANNER_URL в .env)", code="scanner_not_configured"
            )
        if not self.settings.scanner_token and not (
            self.settings.scanner_username and self.settings.scanner_password
        ):
            raise ScannerError(
                "Не заданы учётные данные сервисной учётной записи «Сканера» "
                "(GRC_SCANNER_USERNAME и GRC_SCANNER_PASSWORD или GRC_SCANNER_TOKEN)",
                code="scanner_not_configured",
            )

    def _client(self) -> httpx.Client:
        verify: Any = self.settings.scanner_ca_file or True
        return httpx.Client(
            base_url=self.settings.scanner_url.rstrip("/"),
            timeout=self.settings.scanner_timeout_seconds,
            verify=verify,
            transport=self._transport,
            headers={"Accept": "application/json", "User-Agent": "grc-attestation"},
            follow_redirects=False,
        )

    def _login(self, http: httpx.Client) -> str:
        r = http.post(
            "/auth/token",
            json={
                "username": self.settings.scanner_username,
                "password": self.settings.scanner_password,
            },
        )
        if r.status_code in (401, 403):
            raise ScannerError(
                "«Сканер» отклонил учётные данные сервисной учётной записи", code="scanner_auth"
            )
        if r.status_code == 429:
            raise ScannerError(
                "«Сканер» временно заблокировал вход сервисной учётной записи после "
                "неудачных попыток",
                code="scanner_auth",
            )
        self._check(r, "POST /auth/token")
        try:
            return str(r.json()["access_token"])
        except (ValueError, KeyError, TypeError) as e:
            raise ScannerError(
                "«Сканер» вернул неожиданный ответ на вход", code="scanner_bad_response"
            ) from e

    @staticmethod
    def _check(r: httpx.Response, what: str) -> None:
        if r.status_code >= 400:
            raise ScannerError(f"«Сканер» ответил {r.status_code} на {what}")

    def _get(self, path: str, not_found: str | None = None, params: Any = None) -> Any:
        self.ensure_configured()
        try:
            with self._client() as http:
                if self._token is None:
                    self._token = self._login(http)
                auth = {"Authorization": f"Bearer {self._token}"}
                r = http.get(path, headers=auth, params=params)
                if r.status_code == 401 and self.settings.scanner_username:
                    # Токен истёк — один повторный вход.
                    self._token = self._login(http)
                    auth = {"Authorization": f"Bearer {self._token}"}
                    r = http.get(path, headers=auth, params=params)
        except httpx.TimeoutException as e:
            raise ScannerError(
                f"«Сканер» не ответил за {self.settings.scanner_timeout_seconds:g} с"
            ) from e
        except httpx.HTTPError as e:
            raise ScannerError(f"Не удалось связаться со «Сканером»: {type(e).__name__}") from e
        if r.status_code == 401:
            raise ScannerError(
                "«Сканер» не принял токен сервисной учётной записи", code="scanner_auth"
            )
        if r.status_code == 403:
            raise ScannerError(
                "У сервисной учётной записи нет права просмотра отчётов в «Сканере» "
                "(нужна роль auditor)",
                code="scanner_auth",
            )
        if r.status_code == 404 and not_found:
            raise ScannerError(not_found, code="scanner_not_found")
        self._check(r, f"GET {path}")
        try:
            return r.json()
        except ValueError as e:
            raise ScannerError(
                f"«Сканер» вернул не JSON на GET {path}", code="scanner_bad_response"
            ) from e

    def compliance_profiles(self) -> list[ScannerProfile]:
        return _parse_profiles(self._get("/compliance/profiles"))

    def assets(self, engagement_id: int) -> list[ScannerAsset]:
        data = self._get(
            f"/engagements/{engagement_id}/assets",
            not_found=f"В «Сканере» нет проекта (engagement) №{engagement_id}",
        )
        return _parse_assets(data, engagement_id)

    def runs(self, engagement_id: int) -> list[ScannerRun]:
        params = [
            *(("status", s) for s in sorted(FINISHED_RUN_STATUSES)),
            ("sort", "id"),
            ("order", "desc"),
            ("limit", str(RUNS_LIMIT)),
        ]
        data = self._get(
            f"/engagements/{engagement_id}/runs",
            not_found=f"В «Сканере» нет проекта (engagement) №{engagement_id}",
            params=params,
        )
        return _parse(_RUNS, data, f"GET /engagements/{engagement_id}/runs")

    def run(self, run_id: int) -> ScannerRun:
        data = self._get(f"/runs/{run_id}", not_found=f"В «Сканере» нет прогона №{run_id}")
        return _parse(ScannerRun, data, f"GET /runs/{run_id}")

    def run_compliance(self, run_id: int, profile: str, level: str | None) -> ScannerCompliance:
        params = {"profile": profile, **({"level": level} if level else {})}
        data = self._get(
            f"/runs/{run_id}/compliance",
            not_found=f"В «Сканере» нет прогона №{run_id}",
            params=params,
        )
        return _parse(ScannerCompliance, data, f"GET /runs/{run_id}/compliance")

    def run_coverage(self, run_id: int) -> ScannerCoverage:
        data = self._get(f"/runs/{run_id}/coverage", not_found=f"В «Сканере» нет прогона №{run_id}")
        return _parse(ScannerCoverage, data, f"GET /runs/{run_id}/coverage")

    def run_findings(self, run_id: int) -> list[ScannerFinding]:
        data = self._get(
            f"/runs/{run_id}/findings",
            not_found=f"В «Сканере» нет прогона №{run_id}",
            params=FINDINGS_PARAMS,
        )
        rows = _parse(_FINDINGS, data, f"GET /runs/{run_id}/findings")
        # Фильтр повторяется у себя: старый «Сканер» мог не знать параметров.
        return [f for f in rows if f.bdu_ids and f.false_positive is None]


def get_scanner_client() -> ScannerClient:
    """Зависимость FastAPI; в тестах подменяется через app.dependency_overrides."""
    settings = get_settings()
    if settings.scanner_mode == "live":
        return LiveScannerClient(settings)
    return FixtureScannerClient(settings.scanner_fixture_dir)
