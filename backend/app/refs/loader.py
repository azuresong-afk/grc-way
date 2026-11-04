"""Загрузка справочника мер из YAML-профилей «Сканера» в БД.

Запускается при каждом старте (docker-entrypoint.sh) и идемпотентна:
- новые профили, группы и меры добавляются с origin=scanner и без отметки о сверке;
- мера, которую не правили в интерфейсе (origin=scanner), обновляется из файла,
  если файл изменился: ревизия +1, прежнее состояние — в ref_revisions, отметка
  о сверке снимается;
- мера, исправленная в интерфейсе (origin=local), не трогается — расхождение
  попадает в отчёт загрузки;
- меры, пропавшие из файла, не удаляются: удаление — только через экран разницы;
- если файл профиля не менялся с прошлой загрузки, профиль не трогается вовсе:
  иначе перезапуск откатил бы обновление из API «Сканера» (refs/sync.py) к
  устаревшему YAML. Каталог проверок из файла дополняет только новые проверки и
  справочные поля (рекомендации, источники), которых нет в API.

Запуск вручную: python -m app.refs.loader
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.core.config import get_settings
from app.db.models import RefCheck, RefGroup, RefMeasure, RefProfile, RefRevision, utcnow
from app.db.session import get_engine

CHECKS_FILE = "checks.yaml"
PROFILE_ORDER = ["fstec-117", "fstec-21", "fstec-239", "cis-controls-v8", "cis-benchmark"]
_CHECK_META = {"id", "title", "platform", "remediation", "doc"}


@dataclass
class LoadReport:
    profiles: int = 0
    added: int = 0
    updated: int = 0
    unchanged: int = 0
    local_conflicts: list[str] = field(default_factory=list)
    missing_in_file: list[str] = field(default_factory=list)
    checks: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.added or self.updated)

    def summary(self) -> str:
        parts = [
            f"профилей {self.profiles}",
            f"мер добавлено {self.added}, обновлено {self.updated}, без изменений {self.unchanged}",
            f"проверок {self.checks}",
        ]
        if self.local_conflicts:
            parts.append(f"изменены в интерфейсе, файл не применён: {len(self.local_conflicts)}")
        if self.missing_in_file:
            parts.append(f"нет в файлах: {len(self.missing_in_file)}")
        return "; ".join(parts)


def measure_snapshot(m: RefMeasure) -> dict[str, Any]:
    return {
        "title": m.title,
        "text": m.text,
        "group_code": m.group_code,
        "levels": m.levels,
        "checks": m.checks,
        "source": m.source,
        "origin": m.origin,
        "verified_by_name": m.verified_by_name,
        "verified_at": m.verified_at.isoformat() if m.verified_at else None,
    }


def _source_for(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "document": profile.get("short") or profile["title"],
        "url": profile.get("url"),
        "note": "Импорт из профиля «Сканера»; состав мер и сопоставление с проверками "
        "не сверены методистом",
    }


def _load_checks(session: Session, path: Path, report: LoadReport) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for item in data.get("checks", []):
        row = session.get(RefCheck, item["id"])
        if row is None:
            row = RefCheck(id=item["id"], title=item["title"], platform=item.get("platform", "any"))
        row.remediation = item.get("remediation")
        row.doc = item.get("doc")
        row.sources = {k: v for k, v in item.items() if k not in _CHECK_META}
        session.add(row)
        report.checks += 1


def _load_profile(session: Session, path: Path, report: LoadReport) -> None:
    raw = path.read_bytes()
    data = yaml.safe_load(raw.decode("utf-8"))
    pid = data["id"]
    digest = hashlib.sha256(raw).hexdigest()
    prof = session.get(RefProfile, pid)
    if prof is not None and prof.source_hash == digest:
        report.profiles += 1
        report.unchanged += sum(len(g.get("controls") or []) for g in data.get("groups") or [])
        return
    prof = prof or RefProfile(id=pid)
    prof.title = data["title"]
    prof.short = data.get("short") or data["title"]
    prof.document = data.get("document")
    prof.url = data.get("url")
    prof.level_label = data.get("level_label")
    prof.levels = list(data.get("levels") or [])
    prof.default_level = data.get("default_level")
    prof.dynamic = data.get("dynamic")
    prof.position = PROFILE_ORDER.index(pid) if pid in PROFILE_ORDER else len(PROFILE_ORDER)
    prof.source_hash = digest
    prof.imported_at = utcnow()
    session.add(prof)
    session.flush()
    report.profiles += 1

    source = _source_for(data)
    in_file: set[str] = set()
    for gpos, g in enumerate(data.get("groups") or []):
        grp = session.get(RefGroup, (pid, g["code"])) or RefGroup(profile_id=pid, code=g["code"])
        grp.title = g["title"]
        grp.position = gpos
        session.add(grp)
        for mpos, c in enumerate(g.get("controls") or []):
            in_file.add(c["id"])
            wanted = {
                "title": c["title"],
                "group_code": g["code"],
                "levels": list(c.get("levels") or []),
                "checks": list(c.get("checks") or []),
            }
            m = session.get(RefMeasure, (pid, c["id"]))
            if m is None:
                session.add(
                    RefMeasure(
                        profile_id=pid,
                        id=c["id"],
                        position=mpos,
                        source=source,
                        origin="scanner",
                        revision=1,
                        **wanted,
                    )
                )
                report.added += 1
                continue
            m.position = mpos
            current = {k: getattr(m, k) for k in wanted}
            if current == wanted:
                report.unchanged += 1
            elif m.origin != "scanner":
                report.local_conflicts.append(f"{pid}:{m.id}")
            else:
                session.add(
                    RefRevision(
                        entity="measure",
                        entity_key=f"{pid}:{m.id}",
                        revision=m.revision,
                        data=measure_snapshot(m),
                        changed_by_name="загрузка из «Сканера»",
                        comment="Обновление из файла профиля",
                    )
                )
                for k, v in wanted.items():
                    setattr(m, k, v)
                m.revision += 1
                m.updated_at = utcnow()
                m.updated_by = None
                m.verified_by = m.verified_by_name = m.verified_at = None
                report.updated += 1

    existing = session.scalars(select(RefMeasure.id).where(RefMeasure.profile_id == pid)).all()
    report.missing_in_file += [f"{pid}:{mid}" for mid in existing if mid not in in_file]


def load_reference(session: Session, directory: Path) -> LoadReport:
    report = LoadReport()
    profiles_dir = directory / "profiles"
    checks = profiles_dir / CHECKS_FILE
    if checks.exists():
        _load_checks(session, checks, report)
    for path in sorted(profiles_dir.glob("*.yaml")):
        if path.name != CHECKS_FILE:
            _load_profile(session, path, report)
    if report.changed:
        audit.record(
            session, action="refs.load", actor_name="system", details={"summary": report.summary()}
        )
    session.commit()
    return report


def main() -> int:
    directory = get_settings().reference_dir
    if not (directory / "profiles").is_dir():
        print(f"справочники: каталог {directory / 'profiles'} не найден — пропуск")
        return 0
    with Session(get_engine()) as session:
        print("справочники:", load_reference(session, directory).summary())
    return 0


if __name__ == "__main__":
    sys.exit(main())
