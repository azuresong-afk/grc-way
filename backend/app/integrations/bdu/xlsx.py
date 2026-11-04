"""Потоковое чтение и простая запись XLSX без сторонних библиотек.

Выгрузка уязвимостей БДУ — около 100 тысяч строк; общие библиотеки читают её
минуты и держат в памяти весь лист. Здесь лист разбирается потоком (iterparse),
в памяти — только таблица общих строк. Внешние сущности XML не разрешаются
(xml.etree их не загружает), защита от «миллиарда смехов» есть во встроенном expat.

Запись нужна для образцов выгрузок (тесты, демо): строки пишутся как inlineStr.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Iterator, Sequence
from datetime import date, datetime, timedelta
from pathlib import Path
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_M = f"{{{_NS_MAIN}}}"
_REF = re.compile(r"([A-Z]+)(\d+)")
_EXCEL_EPOCH = date(1899, 12, 30)


class XlsxError(ValueError):
    """Файл не читается как книга Excel; текст — для пользователя."""


def _col_index(letters: str) -> int:
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _text(el: ET.Element) -> str:
    # <si><t>…</t></si> или <si><r><t>…</t></r>…</si>; фонетика (rPh) не нужна.
    parts: list[str] = []
    for child in el:
        if child.tag == f"{_M}t":
            parts.append(child.text or "")
        elif child.tag == f"{_M}r":
            t = child.find(f"{_M}t")
            parts.append(t.text or "" if t is not None else "")
    return "".join(parts)


def _shared_strings(z: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in z.namelist():
        return []
    out: list[str] = []
    with z.open("xl/sharedStrings.xml") as f:
        for _, el in ET.iterparse(f):  # noqa: S314 — см. описание модуля
            if el.tag == f"{_M}si":
                out.append(_text(el))
                el.clear()
    return out


def _first_sheet(z: zipfile.ZipFile) -> str:
    names = set(z.namelist())
    try:
        wb = ET.fromstring(z.read("xl/workbook.xml"))  # noqa: S314
        sheet = wb.find(f"{_M}sheets/{_M}sheet")
        rid = sheet.get(f"{{{_NS_REL}}}id") if sheet is not None else None
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))  # noqa: S314
        for rel in rels.iter(f"{{{_NS_PKG_REL}}}Relationship"):
            if rel.get("Id") == rid:
                target = (rel.get("Target") or "").lstrip("/")
                path = target if target.startswith("xl/") else f"xl/{target}"
                if path in names:
                    return path
    except (KeyError, ET.ParseError):
        pass
    if "xl/worksheets/sheet1.xml" in names:
        return "xl/worksheets/sheet1.xml"
    raise XlsxError("В книге нет листа с данными")


def core_dates(path: Path) -> dict[str, str]:
    """Даты из свойств документа (docProps/core.xml): created, modified — ISO-строки."""
    out: dict[str, str] = {}
    try:
        with zipfile.ZipFile(path) as z:
            if "docProps/core.xml" not in z.namelist():
                return out
            root = ET.fromstring(z.read("docProps/core.xml"))  # noqa: S314
    except (zipfile.BadZipFile, ET.ParseError, OSError):
        return out
    for el in root:
        name = el.tag.rsplit("}", 1)[-1]
        if name in ("created", "modified") and el.text:
            out[name] = el.text.strip()
    return out


def read_rows(path: Path) -> Iterator[list[str]]:
    """Строки первого листа как списки строк. Пустые ячейки — "", числа — как в файле."""
    try:
        z = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as e:
        raise XlsxError("Файл повреждён: архив XLSX не читается") from e
    with z:
        shared = _shared_strings(z)
        sheet = _first_sheet(z)
        try:
            with z.open(sheet) as f:
                row: dict[int, str] = {}
                next_row = 1
                for _, el in ET.iterparse(f, events=("end",)):  # noqa: S314
                    if el.tag == f"{_M}c":
                        ref = el.get("r") or ""
                        m = _REF.match(ref)
                        col = _col_index(m.group(1)) if m else len(row)
                        row[col] = _cell_value(el, shared)
                    elif el.tag == f"{_M}row":
                        num = int(el.get("r") or next_row)
                        # Пропущенные строки листа — пустые, чтобы номера совпадали с Excel.
                        while next_row < num:
                            yield []
                            next_row += 1
                        width = max(row) + 1 if row else 0
                        yield [row.get(i, "") for i in range(width)]
                        next_row = num + 1
                        row = {}
                        el.clear()
        except ET.ParseError as e:
            raise XlsxError("Лист книги повреждён: XML не разбирается") from e


def _cell_value(c: ET.Element, shared: list[str]) -> str:
    t = c.get("t")
    if t == "inlineStr":
        is_ = c.find(f"{_M}is")
        return _text(is_) if is_ is not None else ""
    v = c.find(f"{_M}v")
    raw = v.text if v is not None and v.text is not None else ""
    if t == "s":
        try:
            return shared[int(raw)]
        except (ValueError, IndexError):
            return ""
    if t == "b":
        return "1" if raw == "1" else "0"
    return raw


def excel_date(value: str) -> date | None:
    """Дата из ячейки: «дд.мм.гггг», ISO или порядковый номер дня Excel."""
    s = value.strip()
    if not s:
        return None
    for fmt in ("%d.%m.%Y", "%Y-%m-%d", "%d.%m.%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s[:19], fmt).date()
        except ValueError:
            continue
    try:
        serial = float(s.replace(",", "."))
    except ValueError:
        return None
    if 1 <= serial < 200_000:
        return _EXCEL_EPOCH + timedelta(days=int(serial))
    return None


# ---------- Запись (образцы выгрузок) ----------


def _col_letters(i: int) -> str:
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def write_xlsx(rows: Sequence[Sequence[object]], *, modified: str | None = None) -> bytes:
    """Книга из одного листа; все значения — строки (inlineStr), None — пустая ячейка."""
    sheet_rows = []
    for r, values in enumerate(rows, start=1):
        cells = []
        for c, v in enumerate(values):
            if v is None or v == "":
                continue
            text = escape(str(v))
            cells.append(
                f'<c r="{_col_letters(c)}{r}" t="inlineStr"><is><t xml:space="preserve">'
                f"{text}</t></is></c>"
            )
        sheet_rows.append(f'<row r="{r}">{"".join(cells)}</row>')
    sheet = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<worksheet xmlns="{_NS_MAIN}"><sheetData>{"".join(sheet_rows)}</sheetData></worksheet>'
    )
    workbook = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<workbook xmlns="{_NS_MAIN}" xmlns:r="{_NS_REL}"><sheets>'
        f'<sheet name="Лист1" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    rels = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{_NS_PKG_REL}"><Relationship Id="rId1" '
        f'Type="{_NS_REL}/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'
    )
    root_rels = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{_NS_PKG_REL}"><Relationship Id="rId1" '
        f'Type="{_NS_REL}/officeDocument" Target="xl/workbook.xml"/>'
        + (
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/'
            'relationships/metadata/core-properties" Target="docProps/core.xml"/>'
            if modified
            else ""
        )
        + "</Relationships>"
    )
    ct = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/'
        'vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        + (
            '<Override PartName="/docProps/core.xml" '
            'ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
            if modified
            else ""
        )
        + "</Types>"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", rels)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
        if modified:
            z.writestr(
                "docProps/core.xml",
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
                'metadata/core-properties" xmlns:dcterms="http://purl.org/dc/terms/" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                f'<dcterms:modified xsi:type="dcterms:W3CDTF">{escape(modified)}'
                "</dcterms:modified></cp:coreProperties>",
            )
    return buf.getvalue()
