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

Таблицы классификации (reference/classification/*.yaml) загружаются по тем же
правилам: новая — добавляется; изменённый файл обновляет таблицу, если её не
правили в интерфейсе (origin≠local), — новая ревизия и снятие отметки о сверке;
неизменённый файл таблицу не трогает.

Справочник Методики оценки угроз 2021 (reference/threats/*.yaml) загружается
по записям: новая запись добавляется; запись, изменившаяся в файле, обновляется,
если её не правили в интерфейсе (origin≠local), — новая ревизия и снятие
отметки о сверке; запись, не менявшаяся в файле, не трогается. Записи,
пропавшие из файла, и добавленные в интерфейсе не удаляются.

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
from app.db.models import (
    RefCheck,
    RefClassificationTable,
    RefGroup,
    RefMeasure,
    RefProfile,
    RefRevision,
    RefThreatItem,
    utcnow,
)
from app.db.session import get_engine
from app.domain.classification import definition_hash, validate
from app.domain.threat_refs import item_hash
from app.domain.threat_refs import parse as parse_threats

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
    tables_added: int = 0
    tables_updated: int = 0
    tables_unchanged: int = 0
    threats_added: int = 0
    threats_updated: int = 0
    threats_unchanged: int = 0

    @property
    def changed(self) -> bool:
        return bool(
            self.added
            or self.updated
            or self.tables_added
            or self.tables_updated
            or self.threats_added
            or self.threats_updated
        )

    def summary(self) -> str:
        parts = [
            f"профилей {self.profiles}",
            f"мер добавлено {self.added}, обновлено {self.updated}, без изменений {self.unchanged}",
            f"проверок {self.checks}",
            f"таблиц классификации добавлено {self.tables_added}, обновлено "
            f"{self.tables_updated}, без изменений {self.tables_unchanged}",
            f"Методика угроз: записей добавлено {self.threats_added}, обновлено "
            f"{self.threats_updated}, без изменений {self.threats_unchanged}",
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


# Поля определения, которые хранятся отдельными колонками, а не в definition.
_TABLE_META = {"regime", "title", "version", "origin", "source"}


def table_snapshot(t: RefClassificationTable) -> dict[str, Any]:
    return {
        "title": t.title,
        "version": t.version,
        "definition": t.definition,
        "source": t.source,
        "origin": t.origin,
        "verified_by_name": t.verified_by_name,
        "verified_at": t.verified_at.isoformat() if t.verified_at else None,
    }


def _load_table(session: Session, path: Path, report: LoadReport) -> None:
    raw = path.read_bytes()
    data = yaml.safe_load(raw.decode("utf-8"))
    regime = str(data["regime"])
    definition = {k: v for k, v in data.items() if k not in _TABLE_META}
    validate(definition)
    digest = hashlib.sha256(raw).hexdigest()
    t = session.get(RefClassificationTable, regime)
    if t is not None and t.source_hash == digest:
        report.tables_unchanged += 1
        return
    wanted = {
        "title": data["title"],
        "version": str(data["version"]),
        "definition": definition,
        "source": data.get("source") or {},
    }
    if t is None:
        session.add(
            RefClassificationTable(
                regime=regime,
                origin=data.get("origin") or "stub",
                definition_hash=definition_hash(definition),
                source_hash=digest,
                revision=1,
                **wanted,
            )
        )
        report.tables_added += 1
        return
    t.source_hash = digest
    if t.origin == "local":
        report.local_conflicts.append(f"classification:{regime}")
        return
    if {k: getattr(t, k) for k in wanted} == wanted:
        report.tables_unchanged += 1
        return
    session.add(
        RefRevision(
            entity="classification_table",
            entity_key=regime,
            revision=t.revision,
            data=table_snapshot(t),
            changed_by_name="загрузка справочников",
            comment="Обновление из файла таблицы",
        )
    )
    for k, v in wanted.items():
        setattr(t, k, v)
    t.origin = data.get("origin") or "stub"
    t.definition_hash = definition_hash(definition)
    t.revision += 1
    t.imported_at = t.updated_at = utcnow()
    t.updated_by = None
    t.verified_by = t.verified_by_name = t.verified_at = None
    report.tables_updated += 1


_THREAT_FIELDS = ("kind", "parent_code", "position", "title", "description", "attrs", "source")


def threat_snapshot(t: RefThreatItem) -> dict[str, Any]:
    return {
        **{k: getattr(t, k) for k in _THREAT_FIELDS},
        "origin": t.origin,
        "verified_by_name": t.verified_by_name,
        "verified_at": t.verified_at.isoformat() if t.verified_at else None,
    }


def _load_threats(session: Session, path: Path, report: LoadReport) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for item in parse_threats(data):
        digest = item_hash(item)
        row = session.get(RefThreatItem, item["code"])
        if row is None:
            session.add(
                RefThreatItem(
                    **{k: item[k] for k in ("code", "origin", *_THREAT_FIELDS)},
                    revision=1,
                    file_hash=digest,
                )
            )
            report.threats_added += 1
            continue
        if row.file_hash == digest:
            report.threats_unchanged += 1
            continue
        row.file_hash = digest
        if row.origin == "local":
            report.local_conflicts.append(f"threat:{row.code}")
            continue
        if all(getattr(row, k) == item[k] for k in _THREAT_FIELDS):
            report.threats_unchanged += 1
            continue
        session.add(
            RefRevision(
                entity="threat_item",
                entity_key=row.code,
                revision=row.revision,
                data=threat_snapshot(row),
                changed_by_name="загрузка справочников",
                comment="Обновление из файла справочника",
            )
        )
        for k in _THREAT_FIELDS:
            setattr(row, k, item[k])
        row.origin = item["origin"]
        row.revision += 1
        row.updated_at = utcnow()
        row.updated_by = None
        row.verified_by = row.verified_by_name = row.verified_at = None
        report.threats_updated += 1


def load_reference(session: Session, directory: Path) -> LoadReport:
    report = LoadReport()
    profiles_dir = directory / "profiles"
    checks = profiles_dir / CHECKS_FILE
    if checks.exists():
        _load_checks(session, checks, report)
    for path in sorted(profiles_dir.glob("*.yaml")):
        if path.name != CHECKS_FILE:
            _load_profile(session, path, report)
    for path in sorted((directory / "classification").glob("*.yaml")):
        _load_table(session, path, report)
    for path in sorted((directory / "threats").glob("*.yaml")):
        _load_threats(session, path, report)
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
