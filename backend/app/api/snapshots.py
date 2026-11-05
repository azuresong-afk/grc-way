"""Снимки «Сканера»: краткое описание снимка — общее для набора мер и импорта."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import AssessedObject, ScannerSnapshot


class SnapshotBrief(BaseModel):
    id: uuid.UUID
    number: int
    current: bool
    run_id: int
    run_name: str | None
    run_status: str
    run_started_at: datetime | None
    run_finished_at: datetime | None
    selection: str
    profile_id: str
    level: str | None
    adaptation_version: int | None
    percent: float | None
    counts: dict[str, int]
    summary: dict[str, int]
    hosts: int
    coverage_gaps: int
    # Находок с БДУ на хостах объекта; None — снимок сделан до импорта находок.
    bdu_findings: int | None
    source: str
    imported_at: datetime
    imported_by_name: str | None


def _latest_snapshot(session: Session, obj: AssessedObject) -> ScannerSnapshot | None:
    return session.scalars(
        select(ScannerSnapshot)
        .where(ScannerSnapshot.object_id == obj.id)
        .order_by(ScannerSnapshot.number.desc())
        .limit(1)
    ).first()


def _brief(s: ScannerSnapshot, current_id: uuid.UUID | None) -> SnapshotBrief:
    cov = s.coverage or {}
    summary = cov.get("summary") or {}
    return SnapshotBrief(
        id=s.id,
        number=s.number,
        current=s.id == current_id,
        run_id=s.run_id,
        run_name=s.run_name,
        run_status=s.run_status,
        run_started_at=s.run_started_at,
        run_finished_at=s.run_finished_at,
        selection=s.selection,
        profile_id=s.profile_id,
        level=s.level,
        adaptation_version=s.adaptation_version,
        percent=s.percent,
        counts={k: int(v) for k, v in (s.counts or {}).items()},
        summary={k: int(v) for k, v in (s.summary or {}).items()},
        hosts=len(s.object_hosts or []),
        coverage_gaps=int(summary.get("gaps") or 0),
        bdu_findings=None if s.findings is None else len(s.findings),
        source=s.source,
        imported_at=s.imported_at,
        imported_by_name=s.imported_by_name,
    )


def snapshot_brief(session: Session, obj: AssessedObject) -> SnapshotBrief | None:
    """Текущий снимок объекта — для сводки набора мер."""
    s = _latest_snapshot(session, obj)
    return _brief(s, s.id) if s else None
