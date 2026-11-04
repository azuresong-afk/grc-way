"""Обновление справочника мер из API «Сканера» (GET /compliance/profiles).

Двухшаговый процесс, как требует ТЗ:
1. `compute_diff` — сравнение ответа «Сканера» со справочником в БД: добавленные,
   изменённые и удалённые меры по `id` (с полями «было → стало»), изменения
   профилей, групп и каталога проверок. Ничего не меняет.
2. `apply_diff` — применение выбранных мер отдельным действием, с ревизиями в
   ref_revisions и записью в журнал.

Правила те же, что у загрузчика YAML (refs/loader.py):
- новая мера — origin=scanner, без отметки о сверке;
- изменённая мера получает новую ревизию, прежнее состояние уходит в историю,
  отметка о сверке снимается;
- мера, исправленная в интерфейсе (origin≠scanner), — конфликт: по умолчанию не
  применяется, только если администратор выбрал её явно;
- удаление меры — только через этот экран; удалённая мера остаётся в истории.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.db.models import RefCheck, RefGroup, RefMeasure, RefProfile, RefRevision, utcnow
from app.integrations.scanner.schemas import ScannerProfile
from app.refs.loader import PROFILE_ORDER, measure_snapshot

MEASURE_FIELDS = ("title", "group_code", "levels", "checks")
PROFILE_FIELDS = (
    "title",
    "short",
    "document",
    "url",
    "level_label",
    "levels",
    "default_level",
    "dynamic",
)


def payload_hash(profiles: list[ScannerProfile]) -> str:
    raw = json.dumps(
        [p.model_dump(mode="json") for p in profiles], ensure_ascii=False, sort_keys=True
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def fingerprint(diff: dict[str, Any]) -> str:
    raw = json.dumps(diff, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _wanted(c) -> dict[str, Any]:
    return {
        "title": c.title,
        "group_code": c.group,
        "levels": list(c.levels),
        "checks": list(c.checks),
    }


def _fields(before: dict[str, Any] | None, after: dict[str, Any] | None, names) -> list[dict]:
    out = []
    for f in names:
        b = before.get(f) if before is not None else None
        a = after.get(f) if after is not None else None
        if before is None or after is None or b != a:
            out.append({"field": f, "before": b, "after": a})
    return out


def _measure_item(pid: str, mid: str, action: str, m: RefMeasure | None, fields, title, group):
    origin = m.origin if m is not None else None
    conflict = m is not None and origin != "scanner"
    return {
        "key": f"{pid}:{mid}",
        "profile_id": pid,
        "measure_id": mid,
        "action": action,
        "title": title,
        "group_code": group,
        "fields": fields,
        "origin": origin,
        "revision": m.revision if m is not None else None,
        "verified": bool(m is not None and m.verified_at is not None),
        "conflict": conflict,
        "default": not conflict,
    }


def compute_diff(session: Session, profiles: list[ScannerProfile]) -> dict[str, Any]:
    db_profiles = {p.id: p for p in session.scalars(select(RefProfile))}
    measures: dict[str, dict[str, RefMeasure]] = defaultdict(dict)
    for m in session.scalars(
        select(RefMeasure).order_by(RefMeasure.profile_id, RefMeasure.position)
    ):
        measures[m.profile_id][m.id] = m
    groups: dict[str, dict[str, RefGroup]] = defaultdict(dict)
    for g in session.scalars(select(RefGroup).order_by(RefGroup.position)):
        groups[g.profile_id][g.code] = g

    items: list[dict[str, Any]] = []
    out_profiles: list[dict[str, Any]] = []
    for sp in profiles:
        dp = db_profiles.get(sp.id)
        current = measures.get(sp.id, {})
        prof_fields = (
            []
            if dp is None
            else _fields(
                {f: getattr(dp, f) for f in PROFILE_FIELDS},
                {f: getattr(sp, f) for f in PROFILE_FIELDS},
                PROFILE_FIELDS,
            )
        )
        group_changes = []
        db_groups = groups.get(sp.id, {})
        for g in sp.groups:
            dg = db_groups.get(g.code)
            if dg is None:
                group_changes.append(
                    {"code": g.code, "action": "add", "before": None, "after": g.title}
                )
            elif dg.title != g.title:
                group_changes.append(
                    {"code": g.code, "action": "update", "before": dg.title, "after": g.title}
                )
        wanted_codes = {g.code for g in sp.groups}
        for code, dg in db_groups.items():
            if code not in wanted_codes:
                group_changes.append(
                    {"code": code, "action": "remove", "before": dg.title, "after": None}
                )

        counts = {"add": 0, "update": 0, "remove": 0, "unchanged": 0, "conflict": 0}
        seen: set[str] = set()
        for c in sp.controls:
            seen.add(c.id)
            want = _wanted(c)
            m = current.get(c.id)
            if m is None:
                item = _measure_item(
                    sp.id, c.id, "add", None, _fields(None, want, MEASURE_FIELDS), c.title, c.group
                )
            else:
                have = {f: getattr(m, f) for f in MEASURE_FIELDS}
                changed = _fields(have, want, MEASURE_FIELDS)
                if not changed:
                    counts["unchanged"] += 1
                    continue
                item = _measure_item(sp.id, c.id, "update", m, changed, m.title, m.group_code)
            items.append(item)
            counts[item["action"]] += 1
            counts["conflict"] += item["conflict"]
        for mid, m in current.items():
            if mid in seen:
                continue
            have = {f: getattr(m, f) for f in MEASURE_FIELDS}
            item = _measure_item(
                sp.id, mid, "remove", m, _fields(have, None, MEASURE_FIELDS), m.title, m.group_code
            )
            items.append(item)
            counts["remove"] += 1
            counts["conflict"] += item["conflict"]

        out_profiles.append(
            {
                "id": sp.id,
                "title": sp.short or sp.title,
                "status": "new"
                if dp is None
                else (
                    "changed"
                    if prof_fields
                    or group_changes
                    or any(counts[k] for k in ("add", "update", "remove"))
                    else "same"
                ),
                "fields": prof_fields,
                "groups": group_changes,
                "counts": counts,
                "total": len(sp.controls),
            }
        )

    in_response = {p.id for p in profiles}
    for pid, dp in sorted(db_profiles.items(), key=lambda kv: (kv[1].position, kv[0])):
        if pid not in in_response:
            out_profiles.append(
                {
                    "id": pid,
                    "title": dp.short,
                    "status": "missing",
                    "fields": [],
                    "groups": [],
                    "counts": {"add": 0, "update": 0, "remove": 0, "unchanged": 0, "conflict": 0},
                    "total": len(measures.get(pid, {})),
                }
            )

    db_checks = {c.id: c for c in session.scalars(select(RefCheck))}
    wanted_checks: dict[str, Any] = {}
    for sp in profiles:
        wanted_checks.update(sp.checks)
    checks_added, checks_changed = [], []
    for cid in sorted(wanted_checks):
        sc, dc = wanted_checks[cid], db_checks.get(cid)
        if dc is None:
            checks_added.append({"id": cid, "title": sc.title, "platform": sc.platform})
        elif (dc.title, dc.platform) != (sc.title, sc.platform):
            checks_changed.append(
                {
                    "id": cid,
                    "fields": _fields(
                        {"title": dc.title, "platform": dc.platform},
                        {"title": sc.title, "platform": sc.platform},
                        ("title", "platform"),
                    ),
                }
            )

    summary = {
        k: sum(p["counts"][k] for p in out_profiles)
        for k in ("add", "update", "remove", "unchanged", "conflict")
    }
    summary["verified_affected"] = sum(1 for i in items if i["verified"])
    summary["profiles_new"] = sum(p["status"] == "new" for p in out_profiles)
    summary["profiles_changed"] = sum(
        bool(p["fields"] or p["groups"]) for p in out_profiles if p["status"] != "new"
    )
    summary["profiles_missing"] = sum(p["status"] == "missing" for p in out_profiles)
    summary["checks_added"] = len(checks_added)
    summary["checks_changed"] = len(checks_changed)
    summary["has_changes"] = bool(
        items
        or summary["profiles_new"]
        or summary["profiles_changed"]
        or checks_added
        or checks_changed
    )
    return {
        "profiles": out_profiles,
        "items": items,
        "checks": {"added": checks_added, "changed": checks_changed},
        "summary": summary,
    }


@dataclass
class ApplyResult:
    added: int = 0
    updated: int = 0
    removed: int = 0
    skipped: int = 0
    conflicts_applied: int = 0
    profiles: int = 0
    groups: int = 0
    checks: int = 0

    def as_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


def _source_for(sp: ScannerProfile) -> dict[str, Any]:
    return {
        "document": sp.short or sp.title,
        "url": sp.url,
        "note": "Импорт из API «Сканера» (GET /compliance/profiles); состав мер и "
        "сопоставление с проверками не сверены методистом",
    }


def apply_diff(
    session: Session,
    profiles: list[ScannerProfile],
    diff: dict[str, Any],
    selected: set[str],
    *,
    user_id: uuid.UUID | None,
    user_name: str | None,
) -> ApplyResult:
    """Применяет разницу. Вызывающий отвечает за проверку отпечатка и commit."""
    res = ApplyResult()
    now = utcnow()
    by_key = {i["key"]: i for i in diff["items"]}
    res.skipped = sum(1 for k in by_key if k not in selected)

    changed_checks = {c["id"] for c in diff["checks"]["added"]} | {
        c["id"] for c in diff["checks"]["changed"]
    }
    for sp in profiles:
        for cid, sc in sp.checks.items():
            if cid not in changed_checks:
                continue
            row = session.get(RefCheck, cid)
            if row is None:
                row = RefCheck(id=cid, sources={}, remediation=None, doc=None)
            row.title, row.platform = sc.title, sc.platform
            session.add(row)
            changed_checks.discard(cid)
            res.checks += 1

    max_pos = session.scalar(select(func.max(RefProfile.position))) or 0
    for sp in profiles:
        prof = session.get(RefProfile, sp.id)
        if prof is None:
            prof = RefProfile(
                id=sp.id,
                source_hash="",
                imported_at=now,
                position=PROFILE_ORDER.index(sp.id) if sp.id in PROFILE_ORDER else max_pos + 1,
            )
        for f in PROFILE_FIELDS:
            setattr(prof, f, getattr(sp, f))
        prof.scanner_synced_at = now
        session.add(prof)
        session.flush()
        res.profiles += 1

        for gpos, g in enumerate(sp.groups):
            grp = session.get(RefGroup, (sp.id, g.code))
            if grp is None or grp.title != g.title:
                res.groups += 1
            grp = grp or RefGroup(profile_id=sp.id, code=g.code)
            grp.title, grp.position = g.title, gpos
            session.add(grp)

        positions: dict[str, int] = {}
        per_group: dict[str, int] = defaultdict(int)
        for c in sp.controls:
            positions[c.id] = per_group[c.group]
            per_group[c.group] += 1
        controls = {c.id: c for c in sp.controls}

        for key, item in by_key.items():
            if item["profile_id"] != sp.id or key not in selected:
                continue
            mid = item["measure_id"]
            m = session.get(RefMeasure, (sp.id, mid))
            res.conflicts_applied += bool(item["conflict"])
            if item["action"] == "add":
                session.add(
                    RefMeasure(
                        profile_id=sp.id,
                        id=mid,
                        position=positions[mid],
                        source=_source_for(sp),
                        origin="scanner",
                        revision=1,
                        updated_by=user_id,
                        **_wanted(controls[mid]),
                    )
                )
                res.added += 1
                continue
            session.add(
                RefRevision(
                    entity="measure",
                    entity_key=key,
                    revision=m.revision,
                    data=measure_snapshot(m),
                    changed_by=user_id,
                    changed_by_name=user_name,
                    comment="Удалена при обновлении из «Сканера»"
                    if item["action"] == "remove"
                    else "Обновление из «Сканера»: "
                    + ", ".join(f["field"] for f in item["fields"]),
                )
            )
            if item["action"] == "remove":
                session.delete(m)
                res.removed += 1
                continue
            for k, v in _wanted(controls[mid]).items():
                setattr(m, k, v)
            m.origin = "scanner"
            m.revision += 1
            m.updated_at = now
            m.updated_by = user_id
            m.verified_by = m.verified_by_name = m.verified_at = None
            res.updated += 1
        session.flush()

        for m in session.scalars(select(RefMeasure).where(RefMeasure.profile_id == sp.id)):
            if m.id in positions:
                m.position = positions[m.id]
        # Группу без мер, которой нет в ответе «Сканера», убираем; с мерами — оставляем.
        wanted_codes = {g.code for g in sp.groups}
        used = set(
            session.scalars(
                select(RefMeasure.group_code).where(RefMeasure.profile_id == sp.id).distinct()
            )
        )
        stale = [
            code
            for code in session.scalars(select(RefGroup.code).where(RefGroup.profile_id == sp.id))
            if code not in wanted_codes and code not in used
        ]
        if stale:
            session.execute(
                delete(RefGroup).where(RefGroup.profile_id == sp.id, RefGroup.code.in_(stale))
            )
            res.groups += len(stale)
    session.flush()
    return res
