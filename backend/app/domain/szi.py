"""СЗИ: разбор реестра сертифицированных СЗИ, сравнение и применение, состояние сертификата.

Реестр — «Государственный реестр сертифицированных средств защиты информации
N РОСС RU.0001.01БИ00» ФСТЭК России. Пользователь скачивает его с fstec.ru и
загружает как XLSX или CSV. Официальная раскладка столбцов в проект не загружена
(fstec.ru недоступен из среды разработки), поэтому заголовки распознаются по
ключевым словам, а не по точному тексту, — **требует сверки** с актуальным файлом.

Уровень доверия и профили защиты в реестре — часть свободного текста
«Наименования документов, требованиям которых соответствует средство»; они
выделяются эвристикой и тоже требуют сверки. Состояние «приостановлен/прекращён»
берётся из примечания, если такой столбец есть.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.db.models import SziCert, SziImport, utcnow
from app.integrations.bdu.xlsx import core_dates, excel_date, read_rows

# ---------- Виды СЗИ ----------

# Код → подпись. Перечень — по типам средств, на которые ФСТЭК утверждает требования;
# формулировки рабочие (не нормативный текст).
KINDS: dict[str, str] = {
    "fw": "Межсетевой экран",
    "ids": "Система обнаружения вторжений",
    "av": "Средство антивирусной защиты",
    "nsd": "Средство защиты от НСД",
    "boot": "Средство доверенной загрузки",
    "media": "Средство контроля съёмных машинных носителей",
    "os": "Операционная система",
    "vm": "Средство виртуализации",
    "scan": "Средство анализа защищённости",
    "siem": "Средство мониторинга и управления событиями",
    "crypto": "Средство криптографической защиты",
    "other": "Другое",
}

# ---------- Разбор файла ----------

PROFILE_RE = re.compile(r"ИТ\.[А-ЯЁA-Z0-9]+(?:\.[А-ЯЁA-Z0-9]+)*\.ПЗ", re.IGNORECASE)
_TRUST = [
    re.compile(r"(?:требования\s+доверия|уровень\s+доверия|уровня\s+доверия)\s*[(\-–—:]?\s*(\d)"),
    re.compile(r"(\d)\s*(?:-?го|-?му|-?й)?\s*уровн[а-я]*\s+доверия"),
    re.compile(r"\bУД\s*-?\s*(\d)\b"),
]
_DATE_IN_TEXT = re.compile(r"(\d{2}\.\d{2}\.\d{4})")
_NUMBER = re.compile(r"[№N#]?\s*(\d{1,6})")
_HEADER_SCAN = 15
_SKIPPED_LIST = 50
ITEMS_CAP = 2000
SHRINK_RATIO = 0.9


class SziFormatError(ValueError):
    """Файл не похож на реестр сертифицированных СЗИ; текст — для пользователя."""


@dataclass(frozen=True)
class Column:
    field: str
    title: str  # как в реестре ФСТЭК (требует сверки)
    keys: tuple[tuple[str, ...], ...]  # любой набор подстрок, все из набора — в заголовке
    required: bool = False
    important: bool = False

    def match(self, head: str) -> bool:
        return any(all(k in head for k in ks) for ks in self.keys)


# Порядок важен: более узкие шаблоны раньше («срок действия» до «срок … поддержки»).
COLUMNS: tuple[Column, ...] = (
    Column("cert_number", "№ сертификата", (("сертификат", "№"), ("номер", "сертификат"))),
    Column("registered_on", "Дата внесения в реестр", (("дата", "внесен"), ("дата", "реестр"))),
    Column("valid_to", "Срок действия сертификата", (("срок", "действия"),), important=True),
    Column(
        "name",
        "Наименование средства (шифр)",
        (("наименование", "средств"), ("наименование", "шифр")),
        required=True,
    ),
    Column(
        "requirements",
        "Наименования документов, требованиям которых соответствует средство",
        (("документ", "требовани"), ("соответств", "требовани")),
        important=True,
    ),
    Column("scheme", "Схема сертификации", (("схема",),)),
    Column("lab", "Испытательная лаборатория", (("лаборатор",),)),
    Column("cert_body", "Орган по сертификации", (("орган", "сертификац"),)),
    Column("applicant_details", "Реквизиты заявителя (индекс, адрес, телефон)", (("реквизит",),)),
    Column("applicant", "Заявитель", (("заявител",),)),
    Column("support_raw", "Информация об окончании срока технической поддержки", (("поддержк",),)),
    Column("note", "Примечание", (("примечан",), ("статус",), ("состояни",))),
)
FIELD_TITLES: dict[str, str] = {c.field: c.title for c in COLUMNS} | {
    "support_until": "Окончание технической поддержки",
    "trust_level": "Уровень доверия",
    "profiles": "Профили защиты",
    "cert_status": "Состояние сертификата",
    "valid_to_raw": "Срок действия (текст)",
}
# Поля записи реестра (хэш изменений считается по ним).
FIELDS: tuple[str, ...] = (
    "name",
    "registered_on",
    "valid_to",
    "valid_to_raw",
    "requirements",
    "scheme",
    "lab",
    "cert_body",
    "applicant",
    "applicant_details",
    "support_until",
    "support_raw",
    "note",
    "cert_status",
    "trust_level",
    "profiles",
)


def norm_header(s: str) -> str:
    return " ".join(s.replace("ё", "е").replace("Ё", "Е").lower().split())


def cert_number(raw: str | None) -> str | None:
    """«№ 4512», «4512», «4512.0» → «4512». Пусто или не номер — None."""
    s = (raw or "").strip()
    if not s:
        return None
    if re.fullmatch(r"\d+\.0", s):
        s = s[:-2]
    m = _NUMBER.fullmatch(s.replace(" ", " ").strip())
    if m:
        n = int(m.group(1))
        return str(n) if n > 0 else None
    # Номера с буквами встречаются в старых сертификатах — храним как есть.
    s = re.sub(r"^[№N#]\s*", "", s).strip().upper()
    ok = 0 < len(s) <= 32 and re.fullmatch(r"[\w./-]+", s) and re.search(r"\d", s)
    return s if ok else None


def text(raw: str | None) -> str | None:
    s = (raw or "").replace("\r\n", "\n").replace("_x000D_", "").strip()
    return s or None


def trust_level(requirements: str | None) -> int | None:
    s = (requirements or "").replace("ё", "е")
    low = s.lower()
    for i, rx in enumerate(_TRUST):
        m = rx.search(s if i == 2 else low)
        if m:
            n = int(m.group(1))
            if 1 <= n <= 6:
                return n
    return None


def profiles(requirements: str | None) -> list[str]:
    seen: dict[str, None] = {}
    for m in PROFILE_RE.finditer(requirements or ""):
        seen[m.group(0).upper()] = None
    return list(seen)


def cert_status(note: str | None) -> str:
    s = (note or "").lower().replace("ё", "е")
    if "прекращ" in s or "аннулир" in s or "отозван" in s:
        return "terminated"
    if "приостанов" in s:
        return "suspended"
    return "active"


def date_in(raw: str | None) -> date | None:
    """Дата из ячейки: сама дата, номер дня Excel или первая «дд.мм.гггг» в тексте."""
    s = (raw or "").strip()
    if not s:
        return None
    d = excel_date(s)
    if d is not None:
        return d
    m = _DATE_IN_TEXT.search(s)
    return excel_date(m.group(1)) if m else None


def row_hash(values: dict[str, Any]) -> str:
    data = {f: values.get(f) for f in FIELDS}
    blob = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


@dataclass
class Parsed:
    header_row: int
    columns: dict[str, str]
    missing: list[str]
    rows: dict[str, dict[str, Any]]
    total_rows: int = 0
    skipped: list[dict[str, Any]] = field(default_factory=list)
    skipped_count: int = 0
    duplicates: int = 0
    no_date: int = 0
    version: date | None = None
    version_source: str = "none"  # user | title | file | none
    title: str | None = None


def _csv_rows(path: Path) -> Iterable[list[str]]:
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        content = data.decode("cp1251", errors="replace")
    # Разделитель: «;» (так сохраняет русский Excel), затем табуляция, иначе «,».
    # Запятые есть и внутри текста ячеек, поэтому они проверяются последними.
    head = content.splitlines()[:_HEADER_SCAN]
    delimiter = next((d for d in ";\t" if any(line.count(d) >= 2 for line in head)), ",")
    yield from csv.reader(io.StringIO(content), delimiter=delimiter)


def file_rows(path: Path, ext: str) -> Iterable[list[str]]:
    return _csv_rows(path) if ext == "csv" else read_rows(path)


def _map_columns(heads: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for col in COLUMNS:
        for idx, h in enumerate(heads):
            if h and idx not in out.values() and col.match(h):
                out[col.field] = idx
                break
    return out


def parse_file(path: Path, ext: str) -> Parsed:
    rows = iter(file_rows(path, ext))
    above: list[list[str]] = []
    found: tuple[int, dict[str, int], list[str]] | None = None
    for i, row in enumerate(rows, start=1):
        heads = [norm_header(c) for c in row]
        idx = _map_columns(heads)
        if "name" in idx and "cert_number" in idx:
            found = (i, idx, heads)
            break
        above.append(row)
        if i >= _HEADER_SCAN:
            break
    if found is None:
        raise SziFormatError(
            "Не найдена строка заголовков реестра СЗИ. Ожидаются столбцы «№ сертификата» и "
            "«Наименование средства» в первых 15 строках"
        )
    header_row, idx, heads = found
    parsed = Parsed(
        header_row=header_row,
        columns={f: row_title for f, i in idx.items() if (row_title := heads[i])},
        missing=[c.title for c in COLUMNS if c.important and c.field not in idx],
        rows={},
    )
    title_texts = [" ".join(c for c in r if c).strip() for r in above]
    parsed.title = next((t for t in title_texts if t), None)
    for num, raw in enumerate(rows, start=header_row + 1):
        if not any((c or "").strip() for c in raw):
            continue
        cells = {f: (raw[i] if i < len(raw) else "") for f, i in idx.items()}
        parsed.total_rows += 1
        number = cert_number(cells.get("cert_number"))
        name = text(cells.get("name"))
        if number is None or not name:
            parsed.skipped_count += 1
            if len(parsed.skipped) < _SKIPPED_LIST:
                parsed.skipped.append(
                    {
                        "row": num,
                        "reason": "номер сертификата не распознан"
                        if number is None
                        else "нет наименования средства",
                    }
                )
            continue
        valid_raw = text(cells.get("valid_to"))
        valid_to = date_in(valid_raw)
        support_raw = text(cells.get("support_raw"))
        requirements = text(cells.get("requirements"))
        note = text(cells.get("note"))
        values: dict[str, Any] = {
            "name": name[:2000],
            "registered_on": date_in(cells.get("registered_on")),
            "valid_to": valid_to,
            # Текст сохраняется, только если в нём есть что-то кроме самой даты.
            "valid_to_raw": valid_raw[:500]
            if valid_raw and (valid_to is None or excel_date(valid_raw) is None)
            else None,
            "requirements": requirements,
            "scheme": text(cells.get("scheme")),
            "lab": text(cells.get("lab")),
            "cert_body": text(cells.get("cert_body")),
            "applicant": text(cells.get("applicant")),
            "applicant_details": text(cells.get("applicant_details")),
            "support_until": date_in(support_raw),
            "support_raw": support_raw[:1000] if support_raw else None,
            "note": note,
            "cert_status": cert_status(note),
            "trust_level": trust_level(requirements),
            "profiles": profiles(requirements),
        }
        if number in parsed.rows:
            parsed.duplicates += 1  # действует последняя строка
        values["_hash"] = row_hash(values)
        parsed.rows[number] = values
    if not parsed.rows:
        raise SziFormatError("В файле нет ни одной записи после строки заголовков")
    parsed.no_date = sum(1 for v in parsed.rows.values() if v["valid_to"] is None)
    for t in title_texts:
        if m := _DATE_IN_TEXT.search(t):
            if d := excel_date(m.group(1)):
                parsed.version, parsed.version_source = d, "title"
                return parsed
    if ext == "xlsx":
        props = core_dates(path)
        for key in ("modified", "created"):
            if key in props and (d := excel_date(props[key][:10])):
                parsed.version, parsed.version_source = d, "file"
                break
    return parsed


VERSION_SOURCES = {
    "user": "указана при загрузке",
    "title": "дата в заголовке файла",
    "file": "дата изменения файла (свойства документа)",
    "none": "не определена",
}


# ---------- Сравнение и применение ----------


def _plain(v: Any) -> Any:
    return v.isoformat() if isinstance(v, date) else v


def current_version(session: Session) -> SziImport | None:
    return session.scalar(
        select(SziImport)
        .where(SziImport.status == "applied")
        .order_by(SziImport.applied_at.desc())
        .limit(1)
    )


def _existing(session: Session) -> dict[str, SziCert]:
    return {c.cert_number: c for c in session.scalars(select(SziCert))}


def compute_diff(
    session: Session, parsed: Parsed, *, file_sha256: str | None = None
) -> dict[str, Any]:
    existing = _existing(session)
    keys = set(parsed.rows)
    add = sorted(keys - existing.keys(), key=_sort_key)
    update: list[str] = []
    restore: list[str] = []
    unchanged = 0
    for k in sorted(keys & existing.keys(), key=_sort_key):
        old = existing[k]
        if old.withdrawn_at is not None:
            restore.append(k)
        elif old.row_hash != parsed.rows[k]["_hash"]:
            update.append(k)
        else:
            unchanged += 1
    withdraw = sorted(
        (k for k, c in existing.items() if c.withdrawn_at is None and k not in keys),
        key=_sort_key,
    )
    items: list[dict[str, Any]] = []
    # Сначала то, что меняет срок или состояние сертификата: это видно на объектах.
    validity: list[str] = []
    for k in update + restore:
        old, new = existing[k], parsed.rows[k]
        changes = {
            f: [_plain(getattr(old, f)), _plain(new.get(f))]
            for f in FIELDS
            if getattr(old, f) != new.get(f)
        }
        crit = any(f in changes for f in ("valid_to", "cert_status"))
        if crit:
            validity.append(k)
        items.append(
            {
                "key": k,
                "change": "restore" if k in restore else "update",
                "title": new["name"],
                "fields": changes,
                "validity": crit,
            }
        )
    items.sort(key=lambda i: (not i["validity"], i["change"] != "update", _sort_key(i["key"])))
    for k in withdraw:
        items.append({"key": k, "change": "withdraw", "title": existing[k].name})
    for k in add:
        v = parsed.rows[k]
        items.append(
            {
                "key": k,
                "change": "add",
                "title": v["name"],
                "valid_to": _plain(v["valid_to"]),
                "trust_level": v["trust_level"],
            }
        )
    items_total = len(items)
    items = items[:ITEMS_CAP]
    active = sum(1 for c in existing.values() if c.withdrawn_at is None)
    summary = {
        "in_file": len(parsed.rows),
        "rows_in_file": parsed.total_rows,
        "add": len(add),
        "update": len(update),
        "restore": len(restore),
        "withdraw": len(withdraw),
        "unchanged": unchanged,
        "validity": len(validity),
        "skipped": parsed.skipped_count,
        "duplicates": parsed.duplicates,
        "no_date": parsed.no_date,
        "active_before": active,
        "has_changes": bool(add or update or restore or withdraw),
        "items_shown": len(items),
        "items_total": items_total,
        "header_row": parsed.header_row,
        "columns": parsed.columns,
        "title": parsed.title,
        "skipped_rows": parsed.skipped,
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


def _sort_key(k: str) -> tuple[int, int, str]:
    return (0, int(k), "") if k.isdigit() else (1, 0, k)


def _warnings(
    session: Session,
    parsed: Parsed,
    summary: dict[str, Any],
    active: int,
    file_sha256: str | None,
) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    cur = current_version(session)
    if cur is not None and file_sha256 and cur.file_sha256 == file_sha256:
        out.append({"code": "same_file", "text": "Этот файл уже загружен и применён"})
    if cur is not None and cur.export_version and parsed.version:
        if parsed.version < cur.export_version:
            out.append(
                {
                    "code": "older",
                    "text": f"Реестр от {parsed.version:%d.%m.%Y} старше загруженного "
                    f"({cur.export_version:%d.%m.%Y}): применение откатит данные назад",
                }
            )
    if parsed.version is None:
        out.append(
            {
                "code": "no_version",
                "text": "Дату реестра определить не удалось — укажите её при загрузке",
            }
        )
    if active and len(parsed.rows) < active * SHRINK_RATIO:
        out.append(
            {
                "code": "shrink",
                "text": f"В файле {len(parsed.rows)} сертификатов, а загружено {active}: "
                f"похоже, реестр неполный. {summary['withdraw']} записей будут "
                "отмечены как исключённые",
            }
        )
    if parsed.skipped_count:
        rows = ", ".join(str(s["row"]) for s in parsed.skipped[:10])
        out.append(
            {
                "code": "skipped",
                "text": f"Пропущено строк без номера сертификата или наименования: "
                f"{parsed.skipped_count} (строки {rows}"
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
    if parsed.no_date:
        out.append(
            {
                "code": "no_date",
                "text": f"У {parsed.no_date} сертификатов срок действия не распознан как "
                "дата: их истечение не отслеживается",
            }
        )
    return out


@dataclass
class ApplyResult:
    added: int = 0
    updated: int = 0
    restored: int = 0
    withdrawn: int = 0
    validity: int = 0

    def as_dict(self) -> dict[str, int]:
        return self.__dict__.copy()


def apply(session: Session, parsed: Parsed, row: SziImport, *, version: date | None) -> ApplyResult:
    """Применяет реестр: новые записи, изменения, исключённые. Ничего не удаляет."""
    now = utcnow()
    existing = _existing(session)
    res = ApplyResult()
    new_rows = []
    for k, v in parsed.rows.items():
        if k in existing:
            continue
        new_rows.append(
            {
                "cert_number": k,
                **{f: v.get(f) for f in FIELDS},
                "row_hash": v["_hash"],
                "first_version": version,
                "changed_version": version,
                "first_import_id": row.id,
                "changed_import_id": row.id,
                "updated_at": now,
            }
        )
    for i in range(0, len(new_rows), 500):
        session.execute(insert(SziCert), new_rows[i : i + 500])
    res.added = len(new_rows)
    for k, obj in existing.items():
        v = parsed.rows.get(k)
        if v is None:
            if obj.withdrawn_at is None:
                obj.withdrawn_at, obj.withdrawn_import_id, obj.updated_at = now, row.id, now
                res.withdrawn += 1
            continue
        if obj.withdrawn_at is None and obj.row_hash == v["_hash"]:
            continue
        if obj.valid_to != v["valid_to"] or obj.cert_status != v["cert_status"]:
            res.validity += 1
        if obj.withdrawn_at is not None:
            obj.withdrawn_at = obj.withdrawn_import_id = None
            res.restored += 1
        else:
            res.updated += 1
        for f in FIELDS:
            setattr(obj, f, v.get(f))
        obj.row_hash = v["_hash"]
        obj.changed_version, obj.changed_import_id, obj.updated_at = version, row.id, now
    session.flush()
    return res


# ---------- Состояние сертификата СЗИ объекта ----------

# Порядок — от худшего к лучшему; общее состояние — первое сработавшее.
STATES: dict[str, tuple[str, str]] = {
    # код: (подпись, уровень: bad | warn | ok | none)
    "expired": ("Срок истёк", "bad"),
    "terminated": ("Действие прекращено", "bad"),
    "suspended": ("Действие приостановлено", "bad"),
    "withdrawn": ("Исключён из реестра", "bad"),
    "expiring": ("Срок истекает", "warn"),
    "not_found": ("Нет в реестре", "warn"),
    "no_date": ("Срок не указан", "warn"),
    "valid": ("Действует", "ok"),
    "uncertified": ("Без сертификата", "none"),
}


@dataclass
class CertState:
    state: str
    level: str
    valid_to: date | None
    # registry — срок из реестра; manual — введён вручную; None — неизвестен.
    valid_to_source: str | None
    days_left: int | None
    # found | withdrawn | not_found | not_loaded | no_number
    registry: str
    trust_level: int | None
    support_ended: bool
    notes: list[str]


def cert_state(
    *,
    number: str | None,
    manual_valid_to: date | None,
    manual_trust: int | None,
    entry: SziCert | None,
    registry_loaded: bool,
    today: date,
    expiry_days: int,
) -> CertState:
    notes: list[str] = []
    if not number:
        return CertState(
            "uncertified", "none", manual_valid_to, "manual" if manual_valid_to else None,
            None, "no_number", manual_trust, False, notes,
        )  # fmt: skip
    if entry is not None:
        registry = "withdrawn" if entry.withdrawn_at is not None else "found"
        valid_to, source = (
            (entry.valid_to, "registry")
            if entry.valid_to
            else (manual_valid_to, "manual" if manual_valid_to else None)
        )
        if manual_valid_to and entry.valid_to and manual_valid_to != entry.valid_to:
            notes.append(
                f"Введённый срок {manual_valid_to:%d.%m.%Y} расходится с реестром "
                f"({entry.valid_to:%d.%m.%Y}); действует срок из реестра"
            )
        trust = entry.trust_level or manual_trust
        support_ended = bool(entry.support_until and entry.support_until < today)
    else:
        registry = "not_found" if registry_loaded else "not_loaded"
        valid_to, source = manual_valid_to, ("manual" if manual_valid_to else None)
        trust, support_ended = manual_trust, False
    days_left = (valid_to - today).days if valid_to else None
    if valid_to and valid_to < today:
        state = "expired"
    elif entry is not None and entry.cert_status != "active":
        state = entry.cert_status
    elif registry == "withdrawn":
        state = "withdrawn"
    elif valid_to and valid_to <= today + timedelta(days=expiry_days):
        state = "expiring"
    elif registry == "not_found":
        state = "not_found"
    elif valid_to is None:
        state = "no_date"
    else:
        state = "valid"
    return CertState(
        state, STATES[state][1], valid_to, source, days_left, registry, trust, support_ended, notes
    )


def registry_index(session: Session, numbers: Iterable[str | None]) -> dict[str, SziCert]:
    keys = sorted({n for n in numbers if n})
    if not keys:
        return {}
    return {
        c.cert_number: c
        for c in session.scalars(select(SziCert).where(SziCert.cert_number.in_(keys)))
    }


def registry_loaded(session: Session) -> bool:
    return session.scalar(select(SziCert.cert_number).limit(1)) is not None
