"""Сравнение выгрузки БДУ с загруженными данными и применение сравнения."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.db.models import BduImport, BduThreat, BduVuln, utcnow
from app.domain.bdu import CRITICAL_FIELDS, FIELDS, Kind, Parsed

MODELS: dict[Kind, type[BduThreat] | type[BduVuln]] = {"threats": BduThreat, "vulns": BduVuln}
# Сколько изменений хранить в сравнении для показа (сводка считает все).
ITEMS_CAP = 2000
# Выгрузка меньше этой доли действующих записей — вероятно, неполная.
SHRINK_RATIO = 0.9
_BATCH = 500


def model(kind: Kind):
    return MODELS[kind]


def key_column(kind: Kind):
    return BduThreat.code if kind == "threats" else BduVuln.bdu_id


def _plain(v: Any) -> Any:
    if isinstance(v, date | datetime):
        return v.isoformat()
    return v


def _existing(session: Session, kind: Kind) -> dict[str, tuple[str, str | None, bool]]:
    m = model(kind)
    key = key_column(kind)
    crit = BduVuln.crit_hash if kind == "vulns" else None
    cols = [key, m.row_hash, m.withdrawn_at] + ([crit] if crit is not None else [])
    out: dict[str, tuple[str, str | None, bool]] = {}
    for row in session.execute(select(*cols)):
        out[row[0]] = (row[1], row[3] if crit is not None else None, row[2] is not None)
    return out


def _load(session: Session, kind: Kind, keys: list[str]) -> dict[str, Any]:
    m = model(kind)
    key = key_column(kind)
    out: dict[str, Any] = {}
    for i in range(0, len(keys), _BATCH):
        for obj in session.scalars(select(m).where(key.in_(keys[i : i + _BATCH]))):
            out[getattr(obj, key.key)] = obj
    return out


def _field_changes(obj: Any, values: dict[str, Any], fields: tuple[str, ...]) -> dict[str, list]:
    changes: dict[str, list] = {}
    for f in fields:
        old, new = getattr(obj, f), values.get(f)
        if old != new:
            changes[f] = [_plain(old), _plain(new)]
    return changes


def current_version(session: Session, kind: Kind) -> BduImport | None:
    return session.scalar(
        select(BduImport)
        .where(BduImport.kind == kind, BduImport.status == "applied")
        .order_by(BduImport.applied_at.desc())
        .limit(1)
    )


def compute_diff(
    session: Session, parsed: Parsed, *, file_sha256: str | None = None
) -> dict[str, Any]:
    """Сравнение выгрузки с базой: сводка, изменения по полям, предупреждения."""
    kind = parsed.kind
    fields = FIELDS[kind]
    existing = _existing(session, kind)
    file_keys = set(parsed.rows)
    add = sorted(file_keys - existing.keys())
    update: list[str] = []
    restore: list[str] = []
    unchanged = 0
    for k in sorted(file_keys & existing.keys()):
        old_hash, _, withdrawn = existing[k]
        if withdrawn:
            restore.append(k)
        elif old_hash != parsed.rows[k]["_hash"]:
            update.append(k)
        else:
            unchanged += 1
    withdraw = sorted(k for k, (_, _, w) in existing.items() if not w and k not in file_keys)

    # Изменения по полям — только для изменённых записей (их немного между выгрузками).
    changed_objs = _load(session, kind, update + restore)
    crit_ids: list[str] = []
    upd_items: list[dict[str, Any]] = []
    for k in update + restore:
        obj = changed_objs[k]
        values = parsed.rows[k]
        changes = _field_changes(obj, values, fields)
        crit = kind == "vulns" and existing[k][1] != values["_crit"]
        if crit:
            crit_ids.append(k)
        upd_items.append(
            {
                "key": k,
                "change": "restore" if k in restore else "update",
                "title": values["title"],
                "fields": changes,
                "criticality": crit,
            }
        )
    # Сначала критичные изменения, затем прочие, возвраты, исключения, новые.
    upd_items.sort(key=lambda i: (not i["criticality"], i["change"] != "update", i["key"]))
    items = upd_items[:ITEMS_CAP]
    room = max(ITEMS_CAP - len(items), 0)
    gone = _load(session, kind, withdraw[:room])
    for k in withdraw[:room]:
        items.append({"key": k, "change": "withdraw", "title": gone[k].title})
    for k in add:
        if len(items) >= ITEMS_CAP:
            break
        v = parsed.rows[k]
        item: dict[str, Any] = {"key": k, "change": "add", "title": v["title"]}
        if kind == "vulns":
            item["cvss3_score"] = v["cvss3_score"]
            item["exploit"] = v["exploit"]
            item["in_wild"] = v["in_wild"]
        items.append(item)

    active = sum(1 for _, _, w in existing.values() if not w)
    summary = {
        "kind": kind,
        "in_file": len(parsed.rows),
        "rows_in_file": parsed.total_rows,
        "add": len(add),
        "update": len(update),
        "restore": len(restore),
        "withdraw": len(withdraw),
        "unchanged": unchanged,
        "criticality": len(crit_ids),
        "skipped": parsed.skipped_count,
        "duplicates": parsed.duplicates,
        "cvss_mismatch": len(parsed.cvss_mismatch),
        "active_before": active,
        "has_changes": bool(add or update or restore or withdraw),
        "items_shown": len(items),
        "items_total": len(add) + len(update) + len(restore) + len(withdraw),
        "header_row": parsed.header_row,
        "columns": parsed.columns,
        "title": parsed.title,
        "skipped_rows": parsed.skipped,
        "problems": parsed.problems,
        "crit_ids": crit_ids,
    }
    warnings = _warnings(session, parsed, summary, active, file_sha256)
    fp_src = json.dumps(
        {
            "add": [(k, parsed.rows[k]["_hash"]) for k in add],
            "update": [(k, parsed.rows[k]["_hash"]) for k in update],
            "restore": restore,
            "withdraw": withdraw,
        },
        ensure_ascii=False,
    )
    return {
        "summary": summary,
        "items": items,
        "warnings": warnings,
        "fingerprint": hashlib.sha256(fp_src.encode()).hexdigest(),
    }


def _warnings(
    session: Session,
    parsed: Parsed,
    summary: dict[str, Any],
    active: int,
    file_sha256: str | None,
) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    cur = current_version(session, parsed.kind)
    if cur is not None and file_sha256 and cur.file_sha256 == file_sha256:
        out.append({"code": "same_file", "text": "Этот файл уже загружен и применён"})
    if cur is not None and cur.export_version and parsed.version:
        if parsed.version < cur.export_version:
            out.append(
                {
                    "code": "older",
                    "text": f"Выгрузка от {parsed.version:%d.%m.%Y} старше загруженной "
                    f"({cur.export_version:%d.%m.%Y}): применение откатит данные назад",
                }
            )
    if parsed.version is None:
        out.append(
            {
                "code": "no_version",
                "text": "Дату выгрузки определить не удалось — укажите её при загрузке",
            }
        )
    if active and len(parsed.rows) < active * SHRINK_RATIO:
        out.append(
            {
                "code": "shrink",
                "text": f"В файле {len(parsed.rows)} записей, а загружено {active}: "
                f"похоже, выгрузка неполная. {summary['withdraw']} записей будут "
                "отмечены как исключённые",
            }
        )
    if parsed.skipped_count:
        rows = ", ".join(str(s["row"]) for s in parsed.skipped[:10])
        out.append(
            {
                "code": "skipped",
                "text": f"Пропущено строк без распознаваемого идентификатора или "
                f"наименования: {parsed.skipped_count} (строки {rows}"
                f"{'…' if parsed.skipped_count > 10 else ''})",
            }
        )
    if parsed.missing:
        out.append(
            {
                "code": "missing_columns",
                "text": "В файле нет столбцов: "
                + ", ".join(f"«{m}»" for m in parsed.missing)
                + ". Соответствующие поля останутся пустыми",
            }
        )
    if parsed.cvss_mismatch:
        out.append(
            {
                "code": "cvss_mismatch",
                "text": f"У {len(parsed.cvss_mismatch)} уязвимостей оценка CVSS 3.x в «Уровне "
                "опасности» не совпадает с рассчитанной по вектору; сохраняется оценка БДУ",
            }
        )
    return out


@dataclass
class ApplyResult:
    added: int = 0
    updated: int = 0
    restored: int = 0
    withdrawn: int = 0
    criticality: int = 0

    def as_dict(self) -> dict[str, int]:
        return self.__dict__.copy()


def _columns(values: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {f: values.get(f) for f in fields}


def apply(session: Session, parsed: Parsed, row: BduImport, *, version: date | None) -> ApplyResult:
    """Применяет выгрузку: новые записи, изменения, исключённые. Ничего не удаляет."""
    kind = parsed.kind
    m = model(kind)
    key = key_column(kind)
    fields = FIELDS[kind]
    now = utcnow()
    existing = _existing(session, kind)
    res = ApplyResult()

    new_rows = []
    for k, v in parsed.rows.items():
        if k in existing:
            continue
        data = {
            key.key: k,
            **_columns(v, fields),
            "row_hash": v["_hash"],
            "first_version": version,
            "changed_version": version,
            "first_import_id": row.id,
            "changed_import_id": row.id,
            "updated_at": now,
        }
        if kind == "vulns":
            data["crit_hash"] = v["_crit"]
            data["cve_ids"] = data["cve_ids"] or []
            data["cwe_ids"] = data["cwe_ids"] or []
        new_rows.append(data)
    for i in range(0, len(new_rows), _BATCH):
        session.execute(insert(m), new_rows[i : i + _BATCH])
    res.added = len(new_rows)

    changed = [
        k
        for k, (h, _, withdrawn) in existing.items()
        if k in parsed.rows and (withdrawn or h != parsed.rows[k]["_hash"])
    ]
    objs = _load(session, kind, changed)
    for k in changed:
        obj, v = objs[k], parsed.rows[k]
        if kind == "vulns" and obj.crit_hash != v["_crit"]:
            obj.criticality_changes = _field_changes(obj, v, CRITICAL_FIELDS)
            obj.criticality_changed_at = now
            obj.criticality_changed_import_id = row.id
            obj.crit_hash = v["_crit"]
            res.criticality += 1
        if obj.withdrawn_at is not None:
            obj.withdrawn_at = None
            obj.withdrawn_import_id = None
            res.restored += 1
        else:
            res.updated += 1
        for f in fields:
            setattr(obj, f, v.get(f) if f not in ("cve_ids", "cwe_ids") else v.get(f) or [])
        obj.row_hash = v["_hash"]
        obj.changed_version = version
        obj.changed_import_id = row.id
        obj.updated_at = now

    gone = [k for k, (_, _, w) in existing.items() if not w and k not in parsed.rows]
    for obj in _load(session, kind, gone).values():
        obj.withdrawn_at = now
        obj.withdrawn_import_id = row.id
        obj.updated_at = now
    res.withdrawn = len(gone)
    session.flush()
    return res
