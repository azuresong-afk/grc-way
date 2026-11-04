"""Разбор выгрузок БДУ ФСТЭК России: угрозы (thrlist.xlsx) и уязвимости (vullist.xlsx).

Столбцы ищутся по заголовкам, а не по позициям: над заголовком в выгрузке бывают
строки с названием и датой, порядок и состав столбцов БДУ со временем меняется.
Формат, синонимы заголовков и правила нормализации описаны в docs/bdu-import.md.

Для Методики оценки уровня критичности уязвимостей (ФСТЭК, 30.06.2025) из
уязвимости берутся: базовый вектор и оценка CVSS 3.1 (п. 13), наличие эксплойта
и сведения об эксплуатации в реальных атаках (п. 16, таблица 1 строка 4), статус
устранения (п. 19). Изменение этих полей — «критичные изменения»: оценки уровня
критичности по такой уязвимости требуют пересчёта (п. 16, 19).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Literal

from app.domain.cvss import CvssError, base_score, normalize_vector, parse_vector
from app.integrations.bdu.xlsx import core_dates, excel_date, read_rows

Kind = Literal["threats", "vulns"]
KIND_TITLES = {"threats": "Угрозы (УБИ)", "vulns": "Уязвимости"}
FILE_NAMES = {"threats": "thrlist.xlsx", "vulns": "vullist.xlsx"}

# Сколько строк сверху просматривать в поисках заголовка таблицы.
_HEADER_SCAN = 15
# Сколько пропущенных строк перечислять поимённо.
_SKIPPED_LIST = 50


class BduFormatError(ValueError):
    """Файл не похож на выгрузку БДУ; текст — для пользователя."""


def norm_header(s: str) -> str:
    s = s.replace("ё", "е").replace("Ё", "Е").replace(" ", " ")
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s.rstrip(" :.*")


@dataclass(frozen=True)
class Column:
    field: str
    title: str  # заголовок в выгрузке БДУ (для сообщений и документации)
    match: Callable[[str], bool]
    required: bool = False
    # Без столбца разбор возможен, но о нём стоит предупредить.
    important: bool = False


def _eq(*names: str) -> Callable[[str], bool]:
    wanted = {norm_header(n) for n in names}
    return lambda h: h in wanted


def _starts(*prefixes: str) -> Callable[[str], bool]:
    ps = tuple(norm_header(p) for p in prefixes)
    return lambda h: h.startswith(ps)


THREAT_COLUMNS: tuple[Column, ...] = (
    Column("code", "Идентификатор УБИ", _eq("идентификатор уби", "идентификатор угрозы"), True),
    Column("title", "Наименование УБИ", _eq("наименование уби", "наименование угрозы"), True),
    Column("description", "Описание", _eq("описание", "описание угрозы"), important=True),
    Column("source", "Источник угрозы (характеристика и потенциал нарушителя)",
           _starts("источник угрозы")),
    Column("target", "Объект воздействия", _starts("объект воздействия")),
    Column("conf", "Нарушение конфиденциальности", _starts("нарушение конфиденциальности")),
    Column("integ", "Нарушение целостности", _starts("нарушение целостности")),
    Column("avail", "Нарушение доступности", _starts("нарушение доступности")),
    Column("published_on", "Дата включения угрозы в БнД УБИ", _starts("дата включения")),
    Column("changed_on", "Дата последнего изменения данных", _starts("дата последнего изменения")),
    Column("status", "Статус угрозы", _starts("статус")),
)  # fmt: skip

VULN_COLUMNS: tuple[Column, ...] = (
    Column("bdu_id", "Идентификатор", _eq("идентификатор", "идентификатор уязвимости"), True),
    Column("title", "Наименование уязвимости", _eq("наименование уязвимости"), True),
    Column("description", "Описание уязвимости", _eq("описание уязвимости")),
    Column("vendor", "Вендор ПО", _eq("вендор по", "вендор")),
    Column("product", "Название ПО", _eq("название по", "наименование по")),
    Column("product_version", "Версия ПО", _eq("версия по")),
    Column("sw_type", "Тип ПО", _eq("тип по")),
    Column("platform", "Наименование ОС и тип аппаратной платформы",
           _starts("наименование ос")),
    Column("vuln_class", "Класс уязвимости", _eq("класс уязвимости")),
    Column("identified_on", "Дата выявления", _eq("дата выявления")),
    Column("published_on", "Дата публикации", _eq("дата публикации")),
    Column("cvss2", "CVSS 2.0", _eq("cvss 2.0", "cvss2.0", "cvss 2")),
    Column("cvss3", "CVSS 3.0 / CVSS 3.1",
           _eq("cvss 3.0", "cvss 3.1", "cvss3.0", "cvss3.1", "cvss 3"), important=True),
    Column("cvss4", "CVSS 4.0", _eq("cvss 4.0", "cvss4.0", "cvss 4")),
    Column("severity", "Уровень опасности уязвимости", _starts("уровень опасности"),
           important=True),
    Column("measures", "Возможные меры по устранению", _starts("возможные меры")),
    Column("status", "Статус уязвимости", _eq("статус уязвимости"), important=True),
    Column("exploit_raw", "Наличие эксплойта", _eq("наличие эксплойта", "наличие эксплоита"),
           important=True),
    Column("fix_info", "Информация об устранении", _eq("информация об устранении")),
    Column("links", "Ссылки на источники", _starts("ссылки на источники")),
    Column("other_ids", "Идентификаторы других систем описаний уязвимости",
           _starts("идентификаторы других систем")),
    Column("other_info", "Прочая информация", _eq("прочая информация")),
    Column("in_wild_raw", "Эксплуатация в реальных атаках",
           _eq("эксплуатация в реальных атаках", "сведения об эксплуатации",
               "сведения об эксплуатации в реальных атаках"), important=True),
    Column("incidents_raw", "Связь с инцидентами ИБ", _starts("связь с инцидентами")),
    Column("exploit_method", "Способ эксплуатации", _eq("способ эксплуатации")),
    Column("fix_method", "Способ устранения", _eq("способ устранения")),
    Column("cwe_description", "Описание ошибки CWE", _eq("описание ошибки cwe")),
    Column("cwe_type", "Тип ошибки CWE", _eq("тип ошибки cwe")),
)  # fmt: skip

COLUMNS: dict[Kind, tuple[Column, ...]] = {"threats": THREAT_COLUMNS, "vulns": VULN_COLUMNS}

# Поля, которые хранятся в таблице и сравниваются между выгрузками.
THREAT_FIELDS = (
    "number", "title", "description", "source", "target", "conf", "integ", "avail",
    "published_on", "changed_on", "status",
)  # fmt: skip
VULN_FIELDS = (
    "title", "description", "vendor", "product", "product_version", "sw_type", "platform",
    "vuln_class", "identified_on", "published_on", "severity", "cvss3_vector", "cvss3_version",
    "cvss3_score", "cvss3_score_source", "cvss_other", "measures", "status", "exploit",
    "exploit_raw", "in_wild", "in_wild_raw", "fix_info", "links", "cve_ids", "cwe_ids",
    "other_ids", "other_info", "exploit_method", "fix_method",
)  # fmt: skip
FIELDS: dict[Kind, tuple[str, ...]] = {"threats": THREAT_FIELDS, "vulns": VULN_FIELDS}

# Поля, изменение которых требует пересчёта уровня критичности (Методика 2025, п. 16, 19).
CRITICAL_FIELDS = ("cvss3_vector", "cvss3_score", "exploit", "in_wild", "status")

FIELD_TITLES: dict[str, str] = {
    "number": "Номер",
    "title": "Наименование",
    "description": "Описание",
    "source": "Источник угрозы",
    "target": "Объект воздействия",
    "conf": "Конфиденциальность",
    "integ": "Целостность",
    "avail": "Доступность",
    "published_on": "Дата включения / публикации",
    "changed_on": "Дата изменения в БДУ",
    "status": "Статус",
    "vendor": "Вендор ПО",
    "product": "Название ПО",
    "product_version": "Версия ПО",
    "sw_type": "Тип ПО",
    "platform": "ОС и платформа",
    "vuln_class": "Класс уязвимости",
    "identified_on": "Дата выявления",
    "severity": "Уровень опасности",
    "cvss3_vector": "Вектор CVSS 3.x",
    "cvss3_version": "Версия CVSS 3.x",
    "cvss3_score": "Оценка CVSS 3.x",
    "cvss3_score_source": "Источник оценки CVSS",
    "cvss_other": "CVSS 2.0 / 4.0",
    "measures": "Меры по устранению",
    "exploit": "Наличие эксплойта",
    "exploit_raw": "Наличие эксплойта (текст БДУ)",
    "in_wild": "Эксплуатация в реальных атаках",
    "in_wild_raw": "Эксплуатация в реальных атаках (текст БДУ)",
    "fix_info": "Информация об устранении",
    "links": "Ссылки на источники",
    "cve_ids": "CVE",
    "cwe_ids": "CWE",
    "other_ids": "Идентификаторы других систем",
    "other_info": "Прочая информация",
    "exploit_method": "Способ эксплуатации",
    "fix_method": "Способ устранения",
}

# ---------- Нормализация значений ----------

_UBI = re.compile(r"(?:УБИ|UBI)?\s*[.\-]?\s*0*(\d{1,4})", re.IGNORECASE)
_BDU = re.compile(r"BDU\s*:\s*(\d{4})\s*-\s*(\d{4,6})", re.IGNORECASE)
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)
_DATE_IN_TEXT = re.compile(r"\b(\d{2}\.\d{2}\.\d{4})\b")
_SCORE_IN_SEVERITY = re.compile(
    r"CVSS\s*(2\.0|3\.0|3\.1|4\.0)\D{0,40}?(\d{1,2}(?:[.,]\d)?)", re.IGNORECASE
)
_VECTOR_IN_CELL = re.compile(r"(?:CVSS:3\.[01]/)?AV:[NALP]/AC:[LH]/\S+", re.IGNORECASE)


def threat_code(raw: str) -> tuple[str, int] | None:
    """«1», «1.0», «УБИ.001», «УБИ.1» → («УБИ.001», 1)."""
    s = raw.strip()
    if not s:
        return None
    if re.fullmatch(r"\d+(?:[.,]0+)?", s):  # число из Excel: «1» или «1.0»
        n = int(re.split(r"[.,]", s)[0])
    elif m := _UBI.fullmatch(s):
        n = int(m.group(1))
    else:
        return None
    if not 0 < n < 10_000:
        return None
    return f"УБИ.{n:03d}", n


def bdu_id(raw: str) -> str | None:
    m = _BDU.fullmatch(raw.strip())
    return f"BDU:{m.group(1)}-{m.group(2)}" if m else None


def flag(raw: str) -> bool | None:
    s = raw.strip().lower()
    if s in ("1", "1.0", "да", "true", "+", "x", "х"):
        return True
    if s in ("0", "0.0", "нет", "false", "-", ""):
        return False if s else None
    return None


def text(raw: str) -> str | None:
    s = raw.replace("\r\n", "\n").replace("_x000D_", "").strip()
    return s or None


def exploit_state(raw: str | None) -> str | None:
    """Наличие эксплойта → public | exists | unknown | none | other."""
    if not raw:
        return None
    s = raw.strip().lower().replace("ё", "е")
    if "уточня" in s:
        return "unknown"
    if "отсутств" in s or s in ("нет", "не существует"):
        return "none"
    if "открытом доступе" in s:
        return "public"
    if "существует" in s or "имеется" in s or s == "да":
        return "exists"
    return "other"


def in_wild_state(raw: str | None) -> str | None:
    """Сведения об эксплуатации в реальных атаках → yes | no | unknown | other."""
    if not raw:
        return None
    s = raw.strip().lower().replace("ё", "е")
    if "уточня" in s:
        return "unknown"
    if s.startswith("нет") or "не выявл" in s or "отсутств" in s or "не эксплуат" in s:
        return "no"
    if s.startswith("да") or "эксплуатир" in s or "выявлен" in s or "имеются" in s:
        return "yes"
    return "other"


def e_level(exploit: str | None, in_wild: str | None) -> str:
    """Строка таблицы 1 (показатель E) по сведениям БДУ; наибольшее из значений (п. 16).

    in_wild — «Эксплуатируется в реальных атаках»; exploit — «Имеются сведения о
    наличии средств эксплуатации»; none — «Отсутствуют сведения». Окончательно
    показатель выбирает специалист при оценке (задача 2.8).
    """
    if in_wild == "yes":
        return "in_wild"
    if exploit in ("public", "exists"):
        return "exploit"
    return "none"


def _score(raw: str) -> float | None:
    try:
        v = float(raw.replace(",", "."))
    except ValueError:
        return None
    return v if 0 <= v <= 10 else None


def severity_scores(severity: str | None) -> dict[str, float]:
    """«Критический уровень опасности (базовая оценка CVSS 3.1 составляет 9,8)» → {"3.1": 9.8}."""
    out: dict[str, float] = {}
    for m in _SCORE_IN_SEVERITY.finditer(severity or ""):
        if (v := _score(m.group(2))) is not None:
            out.setdefault(m.group(1), v)
    return out


@dataclass
class CvssResult:
    vector: str | None = None
    version: str | None = None
    score: float | None = None
    score_source: str | None = None  # bdu | computed
    mismatch: bool = False
    problem: str | None = None


def cvss3(cell: str, header: str, scores: dict[str, float]) -> CvssResult:
    """Вектор CVSS 3.x из ячейки, версия — из префикса или заголовка, оценка — из
    «Уровня опасности», иначе вычисляется по вектору."""
    res = CvssResult()
    s = (cell or "").strip()
    if not s:
        for ver in ("3.1", "3.0"):
            if ver in scores:
                res.version, res.score, res.score_source = ver, scores[ver], "bdu"
                break
        return res
    m = _VECTOR_IN_CELL.search(s.replace(" ", ""))
    if not m:
        res.problem = "вектор CVSS 3.x не распознан"
        return res
    raw = m.group(0)
    try:
        prefix_version, _ = parse_vector(raw)
        # Без префикса в векторе версию подсказывает «Уровень опасности» («CVSS 3.1
        # составляет …»), затем заголовок столбца.
        in_severity = [v for v in ("3.1", "3.0") if v in scores]
        version = (
            prefix_version
            or (in_severity[0] if len(in_severity) == 1 else None)
            or ("3.1" if "3.1" in header else "3.0")
        )
        res.vector = normalize_vector(raw, version)
        res.version = version
        computed = base_score(raw)
    except CvssError as e:
        res.problem = f"вектор CVSS 3.x: {e}"
        res.vector = None
        return res
    given = scores.get(version)
    if given is None:
        # Оценка в «Уровне опасности» могла быть указана для другой подверсии 3.x.
        other = "3.0" if version == "3.1" else "3.1"
        given = scores.get(other)
    if given is not None:
        res.score, res.score_source = given, "bdu"
        res.mismatch = abs(given - computed) > 0.05
    else:
        res.score, res.score_source = computed, "computed"
    return res


def _other_cvss(cell: str, version: str, scores: dict[str, float]) -> dict[str, Any] | None:
    s = (cell or "").strip()
    if not s and version not in scores:
        return None
    out: dict[str, Any] = {}
    if s:
        out["vector"] = s
    if version in scores:
        out["score"] = scores[version]
    return out


def _ids(pattern: re.Pattern[str], *texts: str | None) -> list[str]:
    seen: dict[str, None] = {}
    for t in texts:
        for m in pattern.finditer(t or ""):
            seen[m.group(0).upper()] = None
    return list(seen)


# ---------- Разбор файла ----------


@dataclass
class Parsed:
    kind: Kind
    header_row: int
    columns: dict[str, str]  # поле → заголовок в файле
    missing: list[str]  # важные, но отсутствующие столбцы (заголовки БДУ)
    rows: dict[str, dict[str, Any]]
    total_rows: int
    skipped: list[dict[str, Any]] = field(default_factory=list)
    skipped_count: int = 0
    duplicates: int = 0
    problems: dict[str, int] = field(default_factory=dict)  # вид проблемы → число строк
    cvss_mismatch: list[str] = field(default_factory=list)
    version: date | None = None
    version_source: str = "none"  # user | title | rows | file | none
    title: str | None = None


def _locate_header(rows: Iterable[list[str]]) -> tuple[Kind, int, list[str], list[list[str]]]:
    above: list[list[str]] = []
    for i, row in enumerate(rows, start=1):
        heads = [norm_header(c) for c in row]
        for kind, cols in COLUMNS.items():
            req = [c for c in cols if c.required]
            if all(any(c.match(h) for h in heads) for c in req):
                return kind, i, heads, above
        above.append(row)
        if i >= _HEADER_SCAN:
            break
    raise BduFormatError(
        "Не найдена строка заголовков выгрузки БДУ. Ожидаются столбцы «Идентификатор УБИ» и "
        "«Наименование УБИ» (thrlist.xlsx) или «Идентификатор» и «Наименование уязвимости» "
        "(vullist.xlsx) в первых 15 строках"
    )


def _map_columns(kind: Kind, heads: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for col in COLUMNS[kind]:
        for idx, h in enumerate(heads):
            if h and col.match(h) and idx not in out.values():
                out[col.field] = idx
                break
    return out


def row_hash(values: dict[str, Any], fields: Iterable[str]) -> str:
    data = {f: values.get(f) for f in fields}
    blob = json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def _threat_row(cells: dict[str, str]) -> tuple[str, dict[str, Any]] | str:
    code = threat_code(cells.get("code", ""))
    if code is None:
        return "идентификатор УБИ не распознан"
    title = text(cells.get("title", ""))
    if not title:
        return "нет наименования угрозы"
    return code[0], {
        "number": code[1],
        "title": title[:1000],
        "description": text(cells.get("description", "")),
        "source": text(cells.get("source", "")),
        "target": text(cells.get("target", "")),
        "conf": flag(cells.get("conf", "")),
        "integ": flag(cells.get("integ", "")),
        "avail": flag(cells.get("avail", "")),
        "published_on": excel_date(cells.get("published_on", "")),
        "changed_on": excel_date(cells.get("changed_on", "")),
        "status": text(cells.get("status", "")),
    }


def _vuln_row(
    cells: dict[str, str], cvss3_header: str
) -> tuple[str, dict[str, Any], CvssResult] | str:
    vid = bdu_id(cells.get("bdu_id", ""))
    if vid is None:
        return "идентификатор BDU не распознан"
    title = text(cells.get("title", ""))
    if not title:
        return "нет наименования уязвимости"
    severity = text(cells.get("severity", ""))
    scores = severity_scores(severity)
    c3 = cvss3(cells.get("cvss3", ""), cvss3_header, scores)
    other: dict[str, Any] = {}
    if v2 := _other_cvss(cells.get("cvss2", ""), "2.0", scores):
        other["cvss2"] = v2
    if v4 := _other_cvss(cells.get("cvss4", ""), "4.0", scores):
        other["cvss4"] = v4
    exploit_raw = text(cells.get("exploit_raw", ""))
    in_wild_raw = text(cells.get("in_wild_raw", "")) or text(cells.get("incidents_raw", ""))
    other_ids = text(cells.get("other_ids", ""))
    return (
        vid,
        {
            "title": title[:2000],
            "description": text(cells.get("description", "")),
            "vendor": text(cells.get("vendor", "")),
            "product": text(cells.get("product", "")),
            "product_version": text(cells.get("product_version", "")),
            "sw_type": text(cells.get("sw_type", "")),
            "platform": text(cells.get("platform", "")),
            "vuln_class": text(cells.get("vuln_class", "")),
            "identified_on": excel_date(cells.get("identified_on", "")),
            "published_on": excel_date(cells.get("published_on", "")),
            "severity": severity,
            "cvss3_vector": c3.vector,
            "cvss3_version": c3.version,
            "cvss3_score": c3.score,
            "cvss3_score_source": c3.score_source,
            "cvss_other": other or None,
            "measures": text(cells.get("measures", "")),
            "status": text(cells.get("status", "")),
            "exploit": exploit_state(exploit_raw),
            "exploit_raw": exploit_raw[:500] if exploit_raw else None,
            "in_wild": in_wild_state(in_wild_raw),
            "in_wild_raw": in_wild_raw[:500] if in_wild_raw else None,
            "fix_info": text(cells.get("fix_info", "")),
            "links": text(cells.get("links", "")),
            "cve_ids": _ids(_CVE, other_ids, cells.get("links", "")),
            "cwe_ids": _ids(_CWE, cells.get("cwe_type", ""), cells.get("cwe_description", "")),
            "other_ids": other_ids,
            "other_info": text(cells.get("other_info", "")),
            "exploit_method": text(cells.get("exploit_method", "")),
            "fix_method": text(cells.get("fix_method", "")),
        },
        c3,
    )


def parse_file(path: Path, *, expect: Kind | None = None) -> Parsed:
    """Разбирает выгрузку; вид (угрозы или уязвимости) определяется по заголовкам."""
    rows = read_rows(path)
    kind, header_row, heads, above = _locate_header(rows)
    if expect and kind != expect:
        raise BduFormatError(
            f"Ожидалась выгрузка «{KIND_TITLES[expect]}» ({FILE_NAMES[expect]}), "
            f"а в файле — «{KIND_TITLES[kind]}»"
        )
    idx = _map_columns(kind, heads)
    by_field = {c.field: c for c in COLUMNS[kind]}
    missing = [
        by_field[f].title
        for f in (c.field for c in COLUMNS[kind] if c.important)
        if f not in idx and not (f == "in_wild_raw" and "incidents_raw" in idx)
    ]
    cvss3_header = heads[idx["cvss3"]] if "cvss3" in idx else ""
    parsed = Parsed(
        kind=kind,
        header_row=header_row,
        columns={f: heads[i] for f, i in idx.items()},
        missing=missing,
        rows={},
        total_rows=0,
    )
    title_texts = [" ".join(c for c in r if c).strip() for r in above]
    parsed.title = next((t for t in title_texts if t), None)
    fields = FIELDS[kind]
    for num, raw in enumerate(rows, start=header_row + 1):
        if not any(c.strip() for c in raw):
            continue
        cells = {f: (raw[i] if i < len(raw) else "") for f, i in idx.items()}
        parsed.total_rows += 1
        res = _threat_row(cells) if kind == "threats" else _vuln_row(cells, cvss3_header)
        if isinstance(res, str):
            parsed.skipped_count += 1
            if len(parsed.skipped) < _SKIPPED_LIST:
                parsed.skipped.append({"row": num, "reason": res})
            continue
        key, values = res[0], res[1]
        if kind == "vulns":
            c3: CvssResult = res[2]  # type: ignore[misc]
            if c3.problem:
                parsed.problems[c3.problem.split(":")[0]] = (
                    parsed.problems.get(c3.problem.split(":")[0], 0) + 1
                )
            if c3.mismatch:
                parsed.cvss_mismatch.append(key)
        if key in parsed.rows:
            parsed.duplicates += 1  # в выгрузке БДУ последняя строка — актуальная
        values["_hash"] = row_hash(values, fields)
        if kind == "vulns":
            values["_crit"] = row_hash(values, CRITICAL_FIELDS)
        parsed.rows[key] = values
    if not parsed.rows:
        raise BduFormatError("В выгрузке нет ни одной записи после строки заголовков")
    _detect_version(parsed, path, title_texts)
    return parsed


def _detect_version(parsed: Parsed, path: Path, title_texts: list[str]) -> None:
    """Версия выгрузки: дата в заголовке листа → наибольшая дата изменения записей
    (угрозы) → дата изменения файла в свойствах документа."""
    for t in title_texts:
        if m := _DATE_IN_TEXT.search(t):
            if d := excel_date(m.group(1)):
                parsed.version, parsed.version_source = d, "title"
                return
    if parsed.kind == "threats":
        dates = [r["changed_on"] for r in parsed.rows.values() if r.get("changed_on")]
        if dates:
            parsed.version, parsed.version_source = max(dates), "rows"
            return
    props = core_dates(path)
    for key in ("modified", "created"):
        if key in props and (d := excel_date(props[key][:10])):
            parsed.version, parsed.version_source = d, "file"
            return


VERSION_SOURCES = {
    "user": "указана при загрузке",
    "title": "дата в заголовке выгрузки",
    "rows": "наибольшая «Дата последнего изменения данных»",
    "file": "дата изменения файла (свойства документа)",
    "none": "не определена",
}
