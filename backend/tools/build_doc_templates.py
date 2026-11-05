"""Сборка шаблонов документов templates/docx/*.docx (docxtpl).

Шаблоны лежат в репозитории как DOCX — их можно открыть и поправить в Word
или LibreOffice, а пользователь сможет загрузить свой (задача 3.2). Этот
скрипт — воспроизводимый исходник встроенных шаблонов: правка оформления
делается здесь, затем

    python tools/build_doc_templates.py

и пересобранный DOCX коммитится вместе со скриптом.

Поля — Jinja: {{ object.name }}; строки таблиц — {%tr for h in hosts %};
абзацы-условия — {%p if hosts %}. Что лежит в контексте — app/docs_gen/context.py,
пустые поля заменяются заглушками (app/docs_gen/fieldmap.py), для пустых
списков заглушка — в empty.<путь>.
"""

from __future__ import annotations

import sys
from pathlib import Path

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

OUT = Path(__file__).resolve().parents[2] / "templates" / "docx"
FONT = "Times New Roman"
GREY = RGBColor(0x55, 0x55, 0x55)


def _base() -> Document:
    doc = Document()
    sec = doc.sections[0]
    sec.orientation = WD_ORIENT.PORTRAIT
    sec.page_width, sec.page_height = Cm(21), Cm(29.7)
    sec.left_margin, sec.right_margin = Cm(2.5), Cm(1.5)
    sec.top_margin, sec.bottom_margin = Cm(2), Cm(2)
    st = doc.styles["Normal"]
    st.font.name = FONT
    st.font.size = Pt(12)
    st.element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
    st.paragraph_format.space_after = Pt(4)
    for name, size in (("Heading 1", 14), ("Heading 2", 12), ("Title", 18)):
        h = doc.styles[name]
        h.font.name = FONT
        h.font.size = Pt(size)
        h.font.bold = True
        h.font.color.rgb = RGBColor(0, 0, 0)
        rpr = h.element.get_or_add_rPr()
        rpr.rFonts.set(qn("w:ascii"), FONT)
        rpr.rFonts.set(qn("w:hAnsi"), FONT)
        rpr.rFonts.set(qn("w:eastAsia"), FONT)
        rpr.rFonts.set(qn("w:cs"), FONT)
        # Шрифты темы (Calibri Light) перекрывают явные — убираем их.
        for attr in ("asciiTheme", "hAnsiTheme", "eastAsiaTheme", "cstheme"):
            rpr.rFonts.attrib.pop(qn(f"w:{attr}"), None)
        h.paragraph_format.space_before = Pt(12)
        h.paragraph_format.space_after = Pt(6)
    _footer(doc)
    return doc


def _field(run, code: str) -> None:
    for kind, text in (("begin", None), (None, code), ("separate", None), ("end", None)):
        if kind:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = text
        run._r.append(el)


def _footer(doc: Document) -> None:
    p = doc.sections[0].footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run("{{ doc.title }} · версия {{ doc.version }} · {{ doc.status_title }} · стр. ")
    r.font.size = Pt(9)
    r.font.color.rgb = GREY
    r2 = p.add_run()
    r2.font.size = Pt(9)
    _field(r2, "PAGE")


def _p(doc: Document, text: str = "", *, bold: bool = False, size: int | None = None,
       align=None, color=None):  # fmt: skip
    p = doc.add_paragraph()
    if text:
        r = p.add_run(text)
        r.bold = bold
        if size:
            r.font.size = Pt(size)
        if color is not None:
            r.font.color.rgb = color
    if align is not None:
        p.alignment = align
    return p


def _borders(table) -> None:
    tbl_pr = table._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        el = OxmlElement(f"w:{edge}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), "4")
        el.set(qn("w:color"), "808080")
        borders.append(el)
    tbl_pr.append(borders)


def _shade(cell, fill: str = "EDEDED") -> None:
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    cell._tc.get_or_add_tcPr().append(shd)


def _cell(cell, text: str, *, bold: bool = False, size: int = 11) -> None:
    cell.text = ""
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(0)
    r = p.add_run(text)
    r.bold = bold
    r.font.size = Pt(size)


def kv_table(doc: Document, rows: list[tuple[str, str]]) -> None:
    t = doc.add_table(rows=len(rows), cols=2)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    _borders(t)
    for i, (k, v) in enumerate(rows):
        _cell(t.cell(i, 0), k)
        _shade(t.cell(i, 0), "F4F4F4")
        _cell(t.cell(i, 1), v)
        t.cell(i, 0).width, t.cell(i, 1).width = Cm(6), Cm(11)


def loop_table(doc: Document, heads: list[str], loop: str, cells: list[str],
               widths: list[float]) -> None:  # fmt: skip
    """Таблица: шапка, строка-цикл {%tr for %}, строка значений, {%tr endfor %}."""
    t = doc.add_table(rows=4, cols=len(heads))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    _borders(t)
    for j, h in enumerate(heads):
        _cell(t.cell(0, j), h, bold=True, size=10)
        _shade(t.cell(0, j))
    # Повтор шапки на каждой странице.
    tr_pr = t.rows[0]._tr.get_or_add_trPr()
    hdr = OxmlElement("w:tblHeader")
    tr_pr.append(hdr)
    _cell(t.cell(1, 0), "{%tr " + loop + " %}", size=10)
    for j, c in enumerate(cells):
        _cell(t.cell(2, j), c, size=10)
    _cell(t.cell(3, 0), "{%tr endfor %}", size=10)
    for row in t.rows:
        for j, w in enumerate(widths):
            row.cells[j].width = Cm(w)


def optional_table(doc: Document, key: str, empty_key: str, build) -> None:
    """Таблица, если список не пуст; иначе — заглушка из empty.<путь>."""
    _p(doc, "{%p if " + key + " %}")
    build()
    _p(doc, "{%p else %}")
    _p(doc, "{{ " + empty_key + " }}", color=RGBColor(0xB0, 0x00, 0x20))
    _p(doc, "{%p endif %}")


def tech_passport() -> Document:
    doc = _base()
    # Титульный лист.
    _p(doc, "{{ customer.name }}", align=WD_ALIGN_PARAGRAPH.CENTER, size=12)
    for _ in range(8):
        _p(doc)
    _p(doc, "ТЕХНИЧЕСКИЙ ПАСПОРТ", bold=True, size=20, align=WD_ALIGN_PARAGRAPH.CENTER)
    _p(doc, "{{ object.name }}", bold=True, size=14, align=WD_ALIGN_PARAGRAPH.CENTER)
    _p(doc, "{{ object.kind_title }}", align=WD_ALIGN_PARAGRAPH.CENTER, color=GREY)
    for _ in range(10):
        _p(doc)
    _p(doc, "Версия {{ doc.version }} от {{ doc.generated }}", align=WD_ALIGN_PARAGRAPH.CENTER)
    _p(doc, "{{ doc.status_title }}", align=WD_ALIGN_PARAGRAPH.CENTER, color=GREY)
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    doc.add_heading("1. Общие сведения", level=1)
    kv_table(
        doc,
        [
            ("Заказчик", "{{ customer.name }}"),
            ("ИНН", "{{ customer.inn }}"),
            ("Адрес", "{{ customer.address }}"),
            ("Договор", "{{ project.contract_ref }}"),
            ("Наименование объекта", "{{ object.name }}"),
            ("Тип объекта", "{{ object.kind_title }}"),
            ("Нормативный режим", "{{ object.regime_title }}"),
            ("Класс / уровень / категория", "{{ classification.result_label }}"),
            ("Классификация утверждена", "{{ classification.approved }}"),
            ("Подключение к сети «Интернет»", "{{ object.internet_title }}"),
        ],
    )
    doc.add_heading("1.1. Назначение", level=2)
    _p(doc, "{{ object.purpose }}")
    doc.add_heading("1.2. Границы объекта", level=2)
    _p(doc, "{{ object.boundaries }}")

    doc.add_heading("2. Ответственные лица", level=1)
    optional_table(
        doc,
        "object.responsible",
        "empty.object.responsible",
        lambda: loop_table(
            doc,
            ["ФИО", "Должность", "Роль", "Контакты"],
            "for r in object.responsible",
            [
                "{{ r.name }}",
                "{{ r.position or '—' }}",
                "{{ r.role or '—' }}",
                "{{ r.phone or '' }} {{ r.email or '' }}",
            ],
            [4.5, 4.5, 4, 4],
        ),
    )

    doc.add_heading("3. Взаимодействие с другими системами", level=1)
    _p(doc, "{%p if object.interconnections %}")
    loop_table(
        doc,
        ["Система", "Владелец", "Направление", "Канал", "Описание"],
        "for i in object.interconnections",
        [
            "{{ i.system }}",
            "{{ i.owner or '—' }}",
            "{{ i.direction_title }}",
            "{{ i.channel or '—' }}",
            "{{ i.description or '' }}",
        ],
        [3.5, 3, 2.5, 3, 5],
    )
    _p(doc, "{%p else %}")
    _p(doc, "Взаимодействие с другими системами не указано.")
    _p(doc, "{%p endif %}")

    doc.add_heading("4. Состав объекта", level=1)
    doc.add_heading("4.1. Сегменты", level=2)
    _p(doc, "{%p if segments %}")
    loop_table(
        doc,
        ["Сегмент", "Описание", "Хостов"],
        "for s in segments",
        ["{{ s.name }}", "{{ s.description or '' }}", "{{ s.host_count }}"],
        [5, 10, 2],
    )
    _p(doc, "{%p else %}")
    _p(doc, "Сегменты не выделены.")
    _p(doc, "{%p endif %}")
    doc.add_heading("4.2. Хосты", level=2)
    optional_table(
        doc,
        "hosts",
        "empty.hosts",
        lambda: loop_table(
            doc,
            ["Адрес", "Имя", "Назначение", "ОС", "Сегмент", "Источник"],
            "for h in hosts",
            [
                "{{ h.address }}",
                "{{ h.hostname }}",
                "{{ h.role }}",
                "{{ h.os }}",
                "{{ h.segment }}",
                "{{ h.source_title }}",
            ],
            [2.6, 2.8, 3.4, 3.4, 2.6, 2.2],
        ),
    )

    doc.add_heading("5. Средства защиты информации", level=1)
    optional_table(
        doc,
        "szi",
        "empty.szi",
        lambda: loop_table(
            doc,
            ["Наименование", "Вид", "Сертификат", "Действует до", "Состояние", "Размещение"],
            "for z in szi",
            [
                "{{ z.name }}{% if z.version %} {{ z.version }}{% endif %}",
                "{{ z.kind_title }}",
                "{{ z.cert_number }}",
                "{{ z.valid_to }}",
                "{{ z.state_title }}",
                "{{ z.placement }}",
            ],
            [3.6, 3, 2.2, 2.4, 2.4, 3.4],
        ),
    )

    _p(doc, "{%p if unverified %}")
    doc.add_heading("Записи справочников, не сверенные методистом", level=1)
    _p(
        doc,
        "Документ собран с использованием записей справочников, которые ещё не сверены "
        "методистом. До сверки документ остаётся проектом.",
        color=GREY,
    )
    _p(doc, "{%p for u in unverified %}")
    _p(doc, "— {{ u.title }} ({{ u.note }})")
    _p(doc, "{%p endfor %}")
    _p(doc, "{%p endif %}")
    return doc


TEMPLATES = {"tech-passport.docx": tech_passport}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for name, build in TEMPLATES.items():
        doc = build()
        # Фиксированные свойства: пересборка без изменений даёт тот же текст.
        props = doc.core_properties
        props.author = "Аттестация"
        props.title = name.removesuffix(".docx")
        props.last_modified_by = "Аттестация"
        doc.save(str(OUT / name))
        print(f"{OUT / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
