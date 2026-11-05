"""Импорт результатов прогона «Сканера» в оценку мер объекта (задача 1.9).

- Выбор прогона: список завершённых прогонов engagement проекта; импорт
  конкретного или «последнего завершённого» (кроме `failed`: в нём ничего не
  проверено).
- Импорт сохраняет *снимок* — ответы `GET /runs/{id}/compliance` (по профилю и
  классу объекта) и `GET /runs/{id}/coverage` вместе с составом объекта на дату
  импорта. Снимок неизменяем; повторный импорт другого (или обновлённого) прогона
  создаёт новый, прежние остаются. Текущий снимок объекта — последний.
- По снимку каждая мера с проверками «Сканера» получает предложение статуса и
  доказательство (app/domain/assessment.py). Статус автоматической меры, который
  не ставили вручную и не подтверждал испытатель, принимает предложение;
  поставленный вручную или подтверждённый не трогается — расхождение видно
  в карточке меры.
- Вместе со снимком сохраняются находки прогона с идентификаторами БДУ на хостах
  объекта (без ложных срабатываний) — для привязки к угрозам модели (задача 2.4).
- Импорт выполняется в запросе: это несколько GET к «Сканеру»; таблица jobs
  появится вместе с долгими задачами (генерация документов).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.api.deps import DbSession, client_ip, require
from app.api.measures import _latest_adaptation, _measures
from app.api.object_vulns import refresh_object
from app.api.objects import _editable, _engagement, get_object_for
from app.api.snapshots import SnapshotBrief, _brief, _latest_snapshot
from app.core.rbac import Perm
from app.db.models import (
    AssessedObject,
    Evidence,
    ObjectMeasure,
    RefCheck,
    RefMeasure,
    ScannerSnapshot,
    User,
    utcnow,
)
from app.domain.assessment import AutoResult, auto_status, check_modules, coverage_map
from app.domain.threat_findings import object_findings
from app.integrations.scanner.client import ScannerClient, ScannerError, get_scanner_client
from app.integrations.scanner.schemas import ScannerRun

router = APIRouter(tags=["scanner-import"])
Viewer = Annotated[User, Depends(require(Perm.VIEW))]
Importer = Annotated[User, Depends(require(Perm.SCANNER_IMPORT))]
Scanner = Annotated[ScannerClient, Depends(get_scanner_client)]

AUTO_METHODS = ("auto", "mixed")


# ---------- Схемы ----------


class RunOut(BaseModel):
    id: int
    name: str | None
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    modules: list[str]
    error_message: str | None
    # Номера снимков объекта, сделанных из этого прогона.
    snapshots: list[int]


class RunsOut(BaseModel):
    engagement_id: int
    source: str
    mode: str
    runs: list[RunOut]
    # Что импортирует «последний завершённый».
    latest_id: int | None


class ImportIn(BaseModel):
    run_id: int | Literal["latest"] = "latest"


class ControlOut(BaseModel):
    id: str
    title: str
    group: str
    status: str
    hosts: dict[str, int]
    failed_hosts: list[dict[str, Any]]
    recommendations: list[dict[str, Any]]
    # Итог по объекту: предложение статуса меры, если мера в наборе.
    measure_status: str | None
    note: str | None


class CoverageHostOut(BaseModel):
    host: str
    in_object: bool
    status: str | None
    modules: dict[str, dict[str, Any]]


class SnapshotOut(SnapshotBrief):
    controls: list[ControlOut]
    manual: list[dict[str, Any]]
    coverage_hosts: list[CoverageHostOut]
    # Хосты объекта, которых нет в покрытии прогона.
    missing_hosts: list[str]
    # Находки с БДУ на хостах объекта; None — снимок сделан до импорта находок.
    findings: list[dict[str, Any]] | None


class ImportOut(BaseModel):
    snapshot: SnapshotBrief
    # Сколько статусов мер изменилось и сколько ручных оставлено как есть.
    applied: int
    kept_manual: int


# ---------- Общие функции ----------


def _scanner_error(e: ScannerError) -> HTTPException:
    status = {"scanner_not_configured": 503, "scanner_not_found": 404}.get(e.code, 502)
    return HTTPException(status, detail=str(e), headers={"X-Error-Code": e.code})


def _get_snapshot(session: Session, sid: uuid.UUID, user: User) -> ScannerSnapshot:
    s = session.get(ScannerSnapshot, sid)
    if s is None:
        raise HTTPException(404, detail="Снимок не найден")
    try:
        get_object_for(session, s.object_id, user)
    except HTTPException as e:
        raise HTTPException(404, detail="Снимок не найден") from e
    return s


def _pick_run(scanner: ScannerClient, engagement_id: int, run_id: int | str) -> ScannerRun:
    if run_id == "latest":
        runs = [r for r in scanner.runs(engagement_id) if r.finished and r.status != "failed"]
        if not runs:
            raise HTTPException(
                409,
                detail="В «Сканере» нет завершённых прогонов этого проекта",
                headers={"X-Error-Code": "no_finished_runs"},
            )
        return max(runs, key=lambda r: (r.finished_at or r.started_at or datetime.min, r.id))
    run = scanner.run(int(run_id))
    if run.engagement_id != engagement_id:
        raise HTTPException(404, detail=f"Прогон №{run.id} не относится к проекту «Сканера»")
    if not run.finished:
        raise HTTPException(
            409,
            detail=f"Прогон №{run.id} ещё не завершён — импортируются только завершённые",
            headers={"X-Error-Code": "run_not_finished"},
        )
    return run


def _modules_by_measure(
    session: Session, profile_id: str, measures: list[ObjectMeasure]
) -> dict[str, set[str]]:
    ids = [m.measure_id for m in measures]
    refs = {
        r.id: r
        for r in session.scalars(
            select(RefMeasure).where(RefMeasure.profile_id == profile_id, RefMeasure.id.in_(ids))
        )
    }
    check_ids = {c for r in refs.values() for c in r.checks or ()}
    checks = {c.id: c for c in session.scalars(select(RefCheck).where(RefCheck.id.in_(check_ids)))}
    out: dict[str, set[str]] = {}
    for mid, r in refs.items():
        mods: set[str] = set()
        for cid in r.checks or ():
            c = checks.get(cid)
            if c is not None:
                mods |= check_modules(c.sources or {})
        out[mid] = mods
    return out


def _evidence_data(
    result: AutoResult, control: dict[str, Any] | None, snapshot_meta: dict[str, Any]
) -> dict[str, Any]:
    in_object = set(result.hosts)
    failed_hosts = [
        fh for fh in (control or {}).get("failed_hosts") or () if fh.get("host") in in_object
    ]
    return {
        **result.as_dict(),
        "run": snapshot_meta,
        "failed_hosts": failed_hosts,
        "recommendations": (control or {}).get("recommendations") or [],
        "host_counts": (control or {}).get("hosts") or {},
    }


def _follows_scanner(m: ObjectMeasure) -> bool:
    """Статус меры берётся из предложения «Сканера»: не ставился вручную и не подтверждён."""
    return m.method == "auto" and m.status_source != "manual" and m.confirmed_at is None


def _hash(*parts: Any) -> str:
    raw = json.dumps(parts, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------- Эндпоинты ----------


@router.get("/objects/{object_id}/scanner/runs", response_model=RunsOut)
def list_runs(object_id: uuid.UUID, user: Viewer, session: DbSession, scanner: Scanner) -> RunsOut:
    """Завершённые прогоны engagement проекта и какие из них уже импортированы."""
    obj = get_object_for(session, object_id, user)
    engagement_id = _engagement(session, obj)
    try:
        runs = [r for r in scanner.runs(engagement_id) if r.finished]
    except ScannerError as e:
        raise _scanner_error(e) from e
    taken: dict[int, list[int]] = {}
    for run_id, number in session.execute(
        select(ScannerSnapshot.run_id, ScannerSnapshot.number)
        .where(ScannerSnapshot.object_id == obj.id)
        .order_by(ScannerSnapshot.number)
    ):
        taken.setdefault(run_id, []).append(number)
    runs.sort(key=lambda r: (r.finished_at or r.started_at or datetime.min, r.id), reverse=True)
    latest = next((r.id for r in runs if r.status != "failed"), None)
    return RunsOut(
        engagement_id=engagement_id,
        source=scanner.source if scanner.mode == "live" else "фикстура «Сканера»",
        mode=scanner.mode,
        runs=[
            RunOut(
                id=r.id,
                name=r.name,
                status=r.status,
                started_at=r.started_at,
                finished_at=r.finished_at,
                modules=r.modules,
                error_message=r.error_message,
                snapshots=taken.get(r.id, []),
            )
            for r in runs
        ],
        latest_id=latest,
    )


@router.post("/objects/{object_id}/scanner/import", response_model=ImportOut, status_code=201)
def import_run(
    object_id: uuid.UUID,
    body: ImportIn,
    request: Request,
    user: Importer,
    session: DbSession,
    scanner: Scanner,
) -> ImportOut:
    obj = get_object_for(session, object_id, user)
    _editable(session, obj)
    engagement_id = _engagement(session, obj)
    a = _latest_adaptation(session, obj)
    measures = _measures(session, obj)
    if a is None or not measures:
        raise HTTPException(
            409, detail="Сначала сформируйте набор мер: результаты прогона ложатся на меры набора"
        )
    ip = client_ip(request)
    try:
        run = _pick_run(scanner, engagement_id, body.run_id)
        compliance = scanner.run_compliance(run.id, a.profile_id, a.level)
        coverage = scanner.run_coverage(run.id)
        findings = scanner.run_findings(run.id)
    except ScannerError as e:
        audit.record_now(
            session,
            action="scanner.import",
            actor=user,
            entity="object",
            entity_id=obj.id,
            project_id=obj.project_id,
            result="error",
            ip=ip,
            details={"run": body.run_id, "code": e.code, "error": str(e)},
        )
        raise _scanner_error(e) from e

    compliance_raw = compliance.model_dump(mode="json")
    coverage_raw = coverage.model_dump(mode="json")
    object_hosts = sorted(h.address for h in obj.hosts)
    bdu_findings = object_findings([f.model_dump(mode="json") for f in findings], object_hosts)
    digest = _hash(compliance_raw, coverage_raw, object_hosts, a.profile_id, a.level, bdu_findings)
    prev = _latest_snapshot(session, obj)
    if prev is not None and prev.run_id == run.id and prev.content_hash == digest:
        raise HTTPException(
            409,
            detail=(
                f"Прогон №{run.id} уже импортирован в снимок №{prev.number}, "
                "с тех пор ничего не изменилось"
            ),
            headers={"X-Error-Code": "snapshot_unchanged"},
        )

    now = utcnow()
    number = (
        session.scalar(
            select(func.max(ScannerSnapshot.number)).where(ScannerSnapshot.object_id == obj.id)
        )
        or 0
    ) + 1
    controls = {c["id"]: c for c in compliance_raw["controls"]}
    cov = coverage_map(coverage_raw["hosts"])
    modules = _modules_by_measure(session, a.profile_id, measures)
    run_by = f"«Сканер», прогон №{run.id}"
    meta = {
        "id": run.id,
        "name": run.name,
        "status": run.status,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "percent": compliance.percent,
        "level": compliance.level or a.level,
    }

    snapshot = ScannerSnapshot(
        id=uuid.uuid4(),
        object_id=obj.id,
        project_id=obj.project_id,
        number=number,
        engagement_id=engagement_id,
        run_id=run.id,
        run_name=run.name,
        run_status=run.status,
        run_started_at=run.started_at,
        run_finished_at=run.finished_at,
        run_modules=list(run.modules),
        selection="latest" if body.run_id == "latest" else "manual",
        profile_id=a.profile_id,
        level=compliance.level or a.level,
        adaptation_version=a.version,
        percent=compliance.percent,
        counts=dict(compliance.counts),
        compliance=compliance_raw,
        coverage=coverage_raw,
        object_hosts=object_hosts,
        findings=bdu_findings,
        summary={},
        content_hash=digest,
        source=scanner.source if scanner.mode == "live" else "фикстура «Сканера»",
        imported_at=now,
        imported_by=user.id,
        imported_by_name=user.display_name,
    )
    results: list[tuple[ObjectMeasure, AutoResult, dict[str, Any] | None]] = []
    summary = dict.fromkeys(
        ("measures", "implemented", "partial", "not_implemented", "unassessed"), 0
    )
    summary["applied"] = summary["kept_manual"] = 0
    for m in measures:
        if m.method not in AUTO_METHODS:
            continue
        control = controls.get(m.measure_id)
        result = auto_status(control, object_hosts, cov, modules.get(m.measure_id, set()))
        results.append((m, result, control))
        summary["measures"] += 1
        summary[result.status] += 1
        if _follows_scanner(m):
            summary["applied"] += int(m.status != result.status)
        elif m.status != result.status:
            summary["kept_manual"] += 1
    snapshot.summary = summary
    # Снимок неизменяем: пишем его целиком до ссылок на него из мер и доказательств.
    session.add(snapshot)
    session.flush()

    changed: list[dict[str, Any]] = []
    for m, result, control in results:
        session.add(
            Evidence(
                object_measure_id=m.id,
                object_id=obj.id,
                project_id=obj.project_id,
                measure_id=m.measure_id,
                kind="scanner",
                snapshot_id=snapshot.id,
                status=result.status,
                summary=result.note,
                data=_evidence_data(result, control, meta),
                created_at=now,
                created_by=user.id,
                created_by_name=user.display_name,
            )
        )
        m.auto_status = result.status
        m.auto_note = result.note
        m.auto_snapshot_id = snapshot.id
        m.updated_at = now
        if _follows_scanner(m):
            if m.status != result.status:
                changed.append({"measure_id": m.measure_id, "status": [m.status, result.status]})
                m.status = result.status
                m.status_at = now
                m.status_by_name = run_by
            m.status_source = "auto"
    # Реестр уязвимостей: находки снимка → записи, устаревшие оценки — пересчёт.
    refresh_object(session, obj, user, trigger="snapshot", ip=ip)
    audit.record(
        session,
        action="scanner.import",
        actor=user,
        entity="scanner_snapshot",
        entity_id=snapshot.id,
        project_id=obj.project_id,
        ip=ip,
        details={
            "object_id": str(obj.id),
            "snapshot": number,
            "run_id": run.id,
            "run_status": run.status,
            "selection": snapshot.selection,
            "profile": a.profile_id,
            "level": snapshot.level,
            "percent": compliance.percent,
            "summary": summary,
            "bdu_findings": len(bdu_findings),
            "changed": changed[:50],
            "source": snapshot.source,
        },
    )
    session.commit()
    return ImportOut(
        snapshot=_brief(snapshot, snapshot.id),
        applied=summary["applied"],
        kept_manual=summary["kept_manual"],
    )


@router.get("/objects/{object_id}/snapshots", response_model=list[SnapshotBrief])
def list_snapshots(object_id: uuid.UUID, user: Viewer, session: DbSession) -> list[SnapshotBrief]:
    obj = get_object_for(session, object_id, user)
    rows = list(
        session.scalars(
            select(ScannerSnapshot)
            .where(ScannerSnapshot.object_id == obj.id)
            .order_by(ScannerSnapshot.number.desc())
        )
    )
    current = rows[0].id if rows else None
    return [_brief(s, current) for s in rows]


@router.get("/snapshots/{snapshot_id}", response_model=SnapshotOut)
def get_snapshot(snapshot_id: uuid.UUID, user: Viewer, session: DbSession) -> SnapshotOut:
    s = _get_snapshot(session, snapshot_id, user)
    obj = session.get(AssessedObject, s.object_id)
    assert obj is not None  # noqa: S101 — внешний ключ
    latest = _latest_snapshot(session, obj)
    ev = {
        e.measure_id: e
        for e in session.scalars(select(Evidence).where(Evidence.snapshot_id == s.id))
    }
    in_object = set(s.object_hosts or [])
    controls = [
        ControlOut(
            id=c["id"],
            title=c["title"],
            group=c["group"],
            status=c["status"],
            hosts=c.get("hosts") or {},
            failed_hosts=c.get("failed_hosts") or [],
            recommendations=c.get("recommendations") or [],
            measure_status=ev[c["id"]].status if c["id"] in ev else None,
            note=ev[c["id"]].summary if c["id"] in ev else None,
        )
        for c in (s.compliance or {}).get("controls") or []
    ]
    cov_hosts = [
        CoverageHostOut(
            host=h["host"],
            in_object=h["host"] in in_object,
            status=h.get("status"),
            modules=h.get("modules") or {},
        )
        for h in (s.coverage or {}).get("hosts") or []
    ]
    seen = {h.host for h in cov_hosts}
    return SnapshotOut(
        **_brief(s, latest.id if latest else None).model_dump(),
        controls=controls,
        manual=(s.compliance or {}).get("manual") or [],
        coverage_hosts=cov_hosts,
        missing_hosts=[h for h in s.object_hosts or [] if h not in seen],
        findings=s.findings,
    )
