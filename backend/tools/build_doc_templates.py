"""Сборка шаблонов документов templates/docx/*.docx (docxtpl).

Шаблоны лежат в репозитории как DOCX — их можно открыть и поправить в Word
или LibreOffice; пользователь может загрузить свой шаблон на вкладке
«Документы» (задача 3.2, описание полей — docs/document-templates.md).
Шрифт стилей здесь — Times New Roman: при формировании он заменяется на
выбранный для объекта (PT Astra Serif или Inter, app/docs_gen/render.py). Этот
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


# Статус на титуле; у утверждённого — дата и кто утвердил (задача 3.3).
STATUS_LINE = (
    "{{ doc.status_title }}{% if doc.approved %} {{ doc.approved }}"
    "{% if doc.approved_by %}, {{ doc.approved_by }}{% endif %}{% endif %}"
)


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


def _widths(table, widths: list[float]) -> None:
    """Ширины столбцов: сетка таблицы (её читает LibreOffice) и ячейки (Word)."""
    table.autofit = False
    for j, w in enumerate(widths):
        table.columns[j].width = Cm(w)
    for row in table.rows:
        for j, w in enumerate(widths):
            row.cells[j].width = Cm(w)


def kv_table(doc: Document, rows: list[tuple[str, str]]) -> None:
    t = doc.add_table(rows=len(rows), cols=2)
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    _borders(t)
    for i, (k, v) in enumerate(rows):
        _cell(t.cell(i, 0), k)
        _shade(t.cell(i, 0), "F4F4F4")
        _cell(t.cell(i, 1), v)
    _widths(t, [6, 11])


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
    _widths(t, widths)


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
    _p(doc, STATUS_LINE, align=WD_ALIGN_PARAGRAPH.CENTER, color=GREY)
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


# ---------- Общие блоки документов комплекта (задача 3.2) ----------

RED = RGBColor(0xB0, 0x00, 0x20)


def page_break(doc: Document) -> None:
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


def heading(doc: Document, text: str, level: int = 1, *, new_page: bool = False):
    h = doc.add_heading(text, level=level)
    if new_page:
        h.paragraph_format.page_break_before = True
    return h


def cover(doc: Document, title: str, *, subtitle: str = "{{ object.name }}") -> None:
    """Титульный лист: заказчик, гриф утверждения, заголовок, версия."""
    _p(doc, "{{ customer.name }}", align=WD_ALIGN_PARAGRAPH.CENTER)
    _p(doc)
    for line in (
        "УТВЕРЖДАЮ",
        "Руководитель",
        "______________ / ______________",
        "«___» ____________ 20___ г.",
    ):
        _p(doc, line, align=WD_ALIGN_PARAGRAPH.RIGHT)
    for _ in range(6):
        _p(doc)
    _p(doc, title, bold=True, size=18, align=WD_ALIGN_PARAGRAPH.CENTER)
    _p(doc, subtitle, bold=True, size=14, align=WD_ALIGN_PARAGRAPH.CENTER)
    _p(doc, "{{ object.kind_title }}", align=WD_ALIGN_PARAGRAPH.CENTER, color=GREY)
    for _ in range(9):
        _p(doc)
    _p(doc, "Версия {{ doc.version }} от {{ doc.generated }}", align=WD_ALIGN_PARAGRAPH.CENTER)
    _p(doc, STATUS_LINE, align=WD_ALIGN_PARAGRAPH.CENTER, color=GREY)
    page_break(doc)


def note(doc: Document, text: str) -> None:
    _p(doc, text, color=GREY, size=10)


def if_else(doc: Document, cond: str, build, otherwise: str, *, red: bool = False) -> None:
    """Блок, если условие верно; иначе — строка текста (или заглушка)."""
    _p(doc, "{%p if " + cond + " %}")
    build()
    _p(doc, "{%p else %}")
    _p(doc, otherwise, color=RED if red else None)
    _p(doc, "{%p endif %}")


def object_rows(*extra: tuple[str, str]) -> list[tuple[str, str]]:
    return [
        ("Заказчик (оператор)", "{{ customer.name }}"),
        ("Наименование объекта", "{{ object.name }}"),
        ("Тип объекта", "{{ object.kind_title }}"),
        ("Нормативный режим", "{{ object.regime_title or '—' }}"),
        *extra,
    ]


def normative_block(doc: Document) -> None:
    _p(doc, "{%p for n in normative %}")
    _p(
        doc,
        "— {{ n.title }}{% if n.issuer %} ({{ n.issuer }}{% if n.issued %}, {{ n.issued }}"
        "{% endif %}{% if n.number %}, № {{ n.number }}{% endif %}){% endif %}.",
    )
    _p(doc, "{%p endfor %}")


def responsible_table(doc: Document, *, signature: bool = False) -> None:
    heads = ["ФИО", "Должность", "Роль"]
    cells = ["{{ r.name or '—' }}", "{{ r.position or '—' }}", "{{ r.role or '—' }}"]
    widths = [5, 5, 4]
    if signature:
        heads.append("Подпись")
        cells.append("")
        widths = [4.5, 4.5, 4, 3]
    optional_table(
        doc,
        "object.responsible",
        "empty.object.responsible",
        lambda: loop_table(doc, heads, "for r in object.responsible", cells, widths),
    )


def unverified_block(doc: Document) -> None:
    _p(doc, "{%p if unverified %}")
    heading(doc, "Записи справочников, не сверенные методистом")
    note(
        doc,
        "Документ собран с использованием записей справочников, которые ещё не сверены "
        "методистом. До сверки документ остаётся проектом.",
    )
    _p(doc, "{%p for u in unverified %}")
    _p(doc, "— {{ u.title }} ({{ u.note }})")
    _p(doc, "{%p endfor %}")
    _p(doc, "{%p endif %}")


def measure_groups(doc: Document, heads: list[str], cells: list[str], widths: list[float]) -> None:
    """Таблица мер по каждой группе набора объекта."""
    _p(doc, "{%p for g in measures.groups %}")
    doc.add_heading("{{ g.code }}. {{ g.title }}", level=2)
    loop_table(doc, heads, "for m in g.rows", cells, widths)
    _p(doc)
    _p(doc, "{%p endfor %}")


def levels_table(doc: Document) -> None:
    loop_table(
        doc,
        ["Уровень критичности", "Значение V", "Срок устранения (п. 21)"],
        "for lv in vulns.levels",
        ["{{ lv.title }}", "{{ lv.condition }}", "{{ lv.deadline }}"],
        [4, 3.5, 9.5],
    )


def methodology_ref(doc: Document) -> None:
    _p(
        doc,
        "Уровень критичности уязвимостей определяется по документу «{{ vulns.methodology.title }}» "
        "({{ vulns.methodology.issuer or 'ФСТЭК России' }}, {{ vulns.methodology.issued or '—' }}; "
        "версия справочника {{ vulns.methodology.version }}): "
        "{{ vulns.methodology.formula }}. Уровень и срок устранения — по таблице:",
    )


def vulns_table(doc: Document, *, deadline: bool = True) -> None:
    heads = ["Идентификатор БДУ", "Уязвимость", "Хосты", "V", "Уровень"]
    cells = [
        "{{ v.bdu_id }}",
        "{{ v.title }}{% if v.cve %} ({{ v.cve }}){% endif %}",
        "{{ v.hosts or '—' }}",
        "{{ v.v or '—' }}",
        "{{ v.level_title or v.state_title }}",
    ]
    widths = [2.8, 5.2, 3, 1.4, 2.2]
    if deadline:
        heads.append("Устранить до")
        cells.append("{{ v.deadline or '—' }}")
        widths = [2.6, 4.6, 2.8, 1.3, 2.1, 2.6]
    if_else(
        doc,
        "vulns.rows",
        lambda: loop_table(doc, heads, "for v in vulns.rows", cells, widths),
        "Уязвимостей в реестре объекта нет (текущий снимок «Сканера» и результаты контроля "
        "защищённости).",
    )


def signatures(doc: Document, rows: list[str]) -> None:
    t = doc.add_table(rows=len(rows), cols=3)
    for i, role in enumerate(rows):
        _cell(t.cell(i, 0), role)
        _cell(t.cell(i, 1), "______________")
        _cell(t.cell(i, 2), "/ ______________ /")
    _widths(t, [8, 4, 5])


# ---------- 1. Акт классификации ----------


def classification_act() -> Document:
    doc = _base()
    cover(doc, "{{ doc.title|upper }}")
    heading(doc, "1. Общие сведения")
    kv_table(
        doc,
        object_rows(
            ("Назначение", "{{ object.purpose }}"),
            ("Договор", "{{ project.contract_ref or '—' }}"),
        ),
    )
    heading(doc, "2. Исходные данные")
    _p(doc, "Исходные данные для определения класса (уровня защищённости, категории):")
    if_else(
        doc,
        "classification.inputs",
        lambda: loop_table(
            doc,
            ["Показатель", "Значение"],
            "for i in classification.inputs",
            ["{{ i.name }}", "{{ i.value or '—' }}"],
            [10, 7],
        ),
        "{{ empty.classification.steps or 'Исходные данные не внесены.' }}",
        red=True,
    )
    heading(doc, "3. Расчёт")
    _p(
        doc,
        "Расчёт выполнен по таблице классификации «Аттестации» (версия "
        "{{ classification.table_version or '—' }}); для каждого шага указана сработавшая "
        "строка таблицы и источник.",
    )
    optional_table(
        doc,
        "classification.steps",
        "empty.classification.steps",
        lambda: loop_table(
            doc,
            ["Шаг", "Результат", "Основание (строка таблицы)", "Источник"],
            "for s in classification.steps",
            [
                "{{ s.label }}",
                "{{ s.value or '—' }}",
                "{{ s.matched or '—' }}",
                "{{ s.source or '—' }}",
            ],
            [4, 2.5, 6, 4.5],
        ),
    )
    heading(doc, "4. Результат")
    _p(
        doc,
        "По результатам классификации для объекта «{{ object.name }}» установлен(а): "
        "{{ classification.result_label }}.",
        bold=True,
    )
    _p(doc, "Обоснование: {{ classification.justification }}")
    _p(
        doc,
        "Классификация утверждена {{ classification.approved }}, "
        "утвердил: {{ classification.approved_by }}.",
    )
    heading(doc, "5. Комиссия")
    responsible_table(doc, signature=True)
    unverified_block(doc)
    return doc


# ---------- 2. Модель угроз ----------


def threat_model() -> Document:
    doc = _base()
    cover(doc, "МОДЕЛЬ УГРОЗ БЕЗОПАСНОСТИ ИНФОРМАЦИИ")
    heading(doc, "1. Общие положения")
    _p(
        doc,
        "Модель угроз разработана по Методике оценки угроз безопасности информации "
        "(ФСТЭК России, 05.02.2021) с использованием банка данных угроз безопасности "
        "информации ФСТЭК России (БДУ). Нормативные документы:",
    )
    normative_block(doc)
    kv_table(
        doc,
        [
            ("Версия модели угроз", "{{ threat_model.version }}"),
            ("Состояние", "{{ threat_model.status_title or '—' }}"),
            ("Утверждена", "{{ threat_model.approved }}"),
            ("Утвердил", "{{ threat_model.approved_by or '—' }}"),
        ],
    )
    heading(doc, "2. Описание объекта")
    kv_table(
        doc,
        object_rows(("Класс / уровень / категория", "{{ classification.result_label or '—' }}")),
    )
    heading(doc, "2.1. Назначение", level=2)
    _p(doc, "{{ object.purpose }}")
    heading(doc, "2.2. Границы", level=2)
    _p(doc, "{{ object.boundaries }}")
    heading(doc, "2.3. Состав", level=2)
    _p(
        doc,
        "Хостов в составе объекта: {{ hosts|length }}; сегменты: "
        "{% for s in segments %}{{ s.name }} ({{ s.host_count }}){% if not loop.last %}, "
        "{% endif %}{% else %}не выделены{% endfor %}.",
    )
    _p(doc, "{%p if object.interconnections %}")
    loop_table(
        doc,
        ["Взаимодействующая система", "Направление", "Канал"],
        "for i in object.interconnections",
        ["{{ i.system }}", "{{ i.direction_title }}", "{{ i.channel or '—' }}"],
        [8, 4, 5],
    )
    _p(doc, "{%p endif %}")

    heading(doc, "3. Возможные негативные последствия")
    optional_table(
        doc,
        "threat_model.consequences",
        "empty.threat_model.consequences",
        lambda: loop_table(
            doc,
            ["Код", "Негативное последствие", "Обоснование"],
            "for c in threat_model.consequences",
            ["{{ c.code }}", "{{ c.title }}", "{{ c.justification or '—' }}"],
            [1.8, 7.2, 8],
        ),
    )
    heading(doc, "4. Объекты воздействия")
    optional_table(
        doc,
        "threat_model.objects",
        "empty.threat_model.objects",
        lambda: loop_table(
            doc,
            ["Объект воздействия", "Хосты", "Виды воздействия", "Последствия"],
            "for o in threat_model.objects",
            [
                "{{ o.name }}{% if o.description %} — {{ o.description }}{% endif %}",
                "{{ o.hosts or '—' }}",
                "{{ o.impacts or '—' }}",
                "{{ o.consequences or '—' }}",
            ],
            [4.5, 3.5, 6, 3],
        ),
    )
    heading(doc, "5. Источники угроз (нарушители)")
    optional_table(
        doc,
        "threat_model.intruders",
        "empty.threat_model.intruders",
        lambda: loop_table(
            doc,
            ["Код", "Вид нарушителя", "Актуальность", "Возможности", "Обоснование"],
            "for i in threat_model.intruders",
            [
                "{{ i.code }}",
                "{{ i.title }}",
                "{{ i.relevant_title }}",
                "{{ i.capability or '—' }}",
                "{{ i.justification or '—' }}",
            ],
            [1.5, 4, 2.5, 3.5, 5.5],
        ),
    )
    heading(doc, "6. Способы реализации угроз")
    optional_table(
        doc,
        "threat_model.methods",
        "empty.threat_model.methods",
        lambda: loop_table(
            doc,
            ["Код", "Способ", "Интерфейсы", "Объекты", "Нарушители"],
            "for m in threat_model.methods",
            [
                "{{ m.code }}",
                "{{ m.title }}",
                "{{ m.interfaces or '—' }}",
                "{{ m.objects or '—' }}",
                "{{ m.intruders or '—' }}",
            ],
            [1.5, 4, 5, 4, 2.5],
        ),
    )
    heading(doc, "7. Сценарии реализации угроз")
    optional_table(
        doc,
        "threat_model.scenarios",
        "empty.threat_model.scenarios",
        lambda: loop_table(
            doc,
            ["Тактика", "Наименование", "Техники", "Примечание"],
            "for s in threat_model.scenarios",
            ["{{ s.tactic }}", "{{ s.title }}", "{{ s.techniques or '—' }}", "{{ s.note or '' }}"],
            [1.8, 5.2, 5, 5],
        ),
    )
    heading(doc, "8. Актуальные угрозы безопасности информации")
    _p(
        doc,
        "Рассмотрено угроз БДУ: {{ threat_model.counts.total }}, актуальных: "
        "{{ threat_model.counts.relevant }}, неактуальных: {{ threat_model.counts.not_relevant }}, "
        "без решения: {{ threat_model.counts.undecided }}.",
    )
    optional_table(
        doc,
        "threat_model.relevant_threats",
        "empty.threat_model.relevant_threats",
        lambda: loop_table(
            doc,
            ["Угроза БДУ", "Нарушители", "Объекты", "Способы", "Обоснование"],
            "for t in threat_model.relevant_threats",
            [
                "{{ t.code }} {{ t.title }}",
                "{{ t.intruders or '—' }}",
                "{{ t.objects or '—' }}",
                "{{ t.methods or '—' }}",
                "{{ t.justification }}{% if t.findings %} Подтверждено находками «Сканера»: "
                "{{ t.findings }}.{% endif %}",
            ],
            [4.5, 2.2, 3.3, 1.8, 5.2],
        ),
    )
    heading(doc, "9. Перечень рассмотренных угроз")
    _p(doc, "{%p if threat_model.threats %}")
    loop_table(
        doc,
        ["Угроза БДУ", "Решение", "Обоснование"],
        "for t in threat_model.threats",
        ["{{ t.code }} {{ t.title }}", "{{ t.relevant_title }}", "{{ t.justification }}"],
        [6.5, 3, 7.5],
    )
    _p(doc, "{%p else %}")
    _p(doc, "Угрозы БДУ не рассмотрены.", color=RED)
    _p(doc, "{%p endif %}")
    unverified_block(doc)
    return doc


# ---------- 3. Частное техническое задание ----------


def protection_spec() -> Document:
    doc = _base()
    cover(
        doc,
        "ЧАСТНОЕ ТЕХНИЧЕСКОЕ ЗАДАНИЕ",
        subtitle="на создание системы защиты информации {{ object.name }}",
    )
    heading(doc, "1. Общие сведения")
    kv_table(
        doc,
        object_rows(
            ("Класс / уровень / категория", "{{ classification.result_label }}"),
            ("Договор", "{{ project.contract_ref or '—' }}"),
            (
                "Базовый набор мер",
                "{{ measures.profile or '—' }}"
                "{% if measures.level %}, {{ measures.level }}{% endif %}",
            ),
            (
                "Адаптация набора мер",
                "версия {{ measures.adaptation.version or '—' }}, "
                "{{ measures.adaptation.status_title or 'не выполнена' }}, утверждена "
                "{{ measures.adaptation.approved }}",
            ),
        ),
    )
    heading(doc, "2. Назначение и границы объекта")
    _p(doc, "{{ object.purpose }}")
    _p(doc, "{{ object.boundaries }}")
    _p(doc, "{%p if object.interconnections %}")
    _p(doc, "Взаимодействие с другими системами:")
    loop_table(
        doc,
        ["Система", "Направление", "Канал", "Описание"],
        "for i in object.interconnections",
        [
            "{{ i.system }}",
            "{{ i.direction_title }}",
            "{{ i.channel or '—' }}",
            "{{ i.description or '' }}",
        ],
        [4, 3, 4, 6],
    )
    _p(doc, "{%p endif %}")
    heading(doc, "3. Нормативные документы")
    normative_block(doc)
    heading(doc, "4. Актуальные угрозы безопасности информации")
    _p(
        doc,
        "Система защиты информации должна нейтрализовать угрозы, признанные актуальными "
        "в модели угроз (версия {{ threat_model.version or '—' }}, "
        "{{ threat_model.status_title or 'не разработана' }}):",
    )
    optional_table(
        doc,
        "threat_model.relevant_threats",
        "empty.threat_model.relevant_threats",
        lambda: loop_table(
            doc,
            ["Угроза БДУ", "Наименование"],
            "for t in threat_model.relevant_threats",
            ["{{ t.code }}", "{{ t.title }}"],
            [3, 14],
        ),
    )
    heading(doc, "5. Требования к мерам защиты информации")
    _p(
        doc,
        "В системе защиты информации должны быть реализованы меры набора объекта после адаптации:",
    )
    _p(doc, "{%p if measures.groups %}")
    measure_groups(
        doc,
        ["Мера", "Содержание меры", "Адаптация"],
        [
            "{{ m.id }}",
            "{{ m.title }}",
            "{{ m.adaptation_title or '—' }}{% if m.compensating %} (компенсирующие: "
            "{{ m.compensating }}){% endif %}",
        ],
        [2, 11, 4],
    )
    _p(doc, "{%p else %}")
    _p(doc, "{{ empty.measures.groups }}", color=RED)
    _p(doc, "{%p endif %}")
    heading(doc, "5.1. Исключённые меры", level=2)
    if_else(
        doc,
        "measures.excluded",
        lambda: loop_table(
            doc,
            ["Мера", "Содержание меры", "Обоснование исключения"],
            "for m in measures.excluded",
            ["{{ m.id }}", "{{ m.title }}", "{{ m.reason or '—' }}"],
            [2, 7, 8],
        ),
        "Меры базового набора не исключались.",
    )
    heading(doc, "5.2. Компенсирующие меры", level=2)
    if_else(
        doc,
        "measures.compensated",
        lambda: loop_table(
            doc,
            ["Мера", "Компенсирующие меры", "Обоснование"],
            "for m in measures.compensated",
            ["{{ m.id }} {{ m.title }}", "{{ m.compensating or '—' }}", "{{ m.reason or '—' }}"],
            [6, 3, 8],
        ),
        "Компенсирующие меры не применяются.",
    )
    heading(doc, "6. Требования к средствам защиты информации")
    _p(
        doc,
        "Для реализации мер применяются средства защиты информации, сертифицированные "
        "по требованиям безопасности информации; срок действия сертификата и поддержки "
        "должен покрывать срок эксплуатации системы.",
    )
    optional_table(
        doc,
        "szi",
        "empty.szi",
        lambda: loop_table(
            doc,
            ["СЗИ", "Вид", "Сертификат", "Действует до", "Меры"],
            "for z in szi",
            [
                "{{ z.name }}{% if z.version %} {{ z.version }}{% endif %}",
                "{{ z.kind_title }}",
                "{{ z.cert_number or '—' }}",
                "{{ z.valid_to or '—' }}",
                "{{ z.measures or '—' }}",
            ],
            [4.2, 3.5, 2.6, 2.4, 4.3],
        ),
    )
    unverified_block(doc)
    return doc


# ---------- 5. ОРД ----------


def org_docs() -> Document:
    doc = _base()
    cover(
        doc,
        "ОРГАНИЗАЦИОННО-РАСПОРЯДИТЕЛЬНЫЕ ДОКУМЕНТЫ",
        subtitle="по защите информации {{ object.name }}",
    )
    heading(doc, "Состав комплекта")
    _p(doc, "{%p for s in org.sections %}")
    _p(doc, "{{ s.number }}. {{ s.title }}")
    _p(doc, "{%p endfor %}")
    _p(doc, "{%p if not org.sections %}")
    _p(doc, "{{ empty.org.sections }}", color=RED)
    _p(doc, "{%p endif %}")
    heading(doc, "Ответственные лица")
    responsible_table(doc)
    note(
        doc,
        "Текст документов — типовые формулировки «Аттестации». Перед утверждением методист "
        "приводит их в соответствие с порядками оператора.",
    )

    _p(doc, "{%p for s in org.sections %}")
    heading(doc, "{{ s.number }}. {{ s.title|upper }}", new_page=True)
    _p(doc, "{{ s.purpose }}")
    _p(doc, "{%p for p in s.paragraphs %}")
    _p(doc, "{{ s.number }}.{{ loop.index }}. {{ p }}")
    _p(doc, "{%p endfor %}")
    _p(doc, "{%p if s.code == 'vulns' %}")
    doc.add_heading("Оценка критичности и сроки устранения уязвимостей", level=2)
    methodology_ref(doc)
    levels_table(doc)
    _p(doc)
    _p(
        doc,
        "Текущие оценки уязвимостей объекта (реестр «Аттестации», снимок «Сканера» "
        "№ {{ vulns.snapshot or '—' }}):",
    )
    vulns_table(doc)
    _p(doc, "{%p endif %}")
    _p(doc, "{%p if s.measures %}")
    doc.add_heading("Меры, которые регламентирует документ", level=2)
    loop_table(
        doc,
        ["Мера", "Содержание", "Текущий статус"],
        "for m in s.measures",
        ["{{ m.id }}", "{{ m.title }}", "{{ m.status_title }}"],
        [2, 11, 4],
    )
    _p(doc, "{%p endif %}")
    _p(doc, "{%p endfor %}")
    unverified_block(doc)
    return doc


# ---------- 6. Программа и методики испытаний ----------


def test_program() -> Document:
    doc = _base()
    cover(doc, "ПРОГРАММА И МЕТОДИКИ АТТЕСТАЦИОННЫХ ИСПЫТАНИЙ")
    heading(doc, "1. Общие положения")
    _p(
        doc,
        "Аттестационные испытания проводятся для проверки соответствия системы защиты "
        "информации объекта «{{ object.name }}» требованиям по защите информации для "
        "класса (уровня защищённости, категории) {{ classification.result_label }}.",
    )
    kv_table(
        doc,
        object_rows(
            ("Договор", "{{ project.contract_ref }}"),
            ("Сроки испытаний", "{{ project.period_from }} — {{ project.period_to }}"),
            ("Хостов в составе", "{{ hosts|length }}"),
        ),
    )
    heading(doc, "2. Нормативные документы")
    normative_block(doc)
    heading(doc, "3. Исходные данные")
    for line in (
        "— акт классификации (определения уровня защищённости, категорирования);",
        "— модель угроз безопасности информации;",
        "— частное техническое задание на систему защиты информации;",
        "— технический паспорт объекта;",
        "— организационно-распорядительные документы по защите информации;",
        "— сертификаты на средства защиты информации.",
    ):
        _p(doc, line)
    heading(doc, "4. Средства контроля")
    _p(
        doc,
        "Технические меры проверяются автоматически программным комплексом «Сканер» на всех "
        "хостах объекта (модули прогона: {{ snapshot.modules or 'определяются при запуске' }}); "
        "результат фиксируется неизменяемым снимком на дату оценки. Организационные меры "
        "проверяются вручную: анализ документов, интервью с персоналом, осмотр.",
    )
    heading(doc, "5. Методика оценки")
    for line in (
        "— мера «Реализована», если по ней нет нарушений ни на одном проверенном хосте и "
        "(для организационных мер) есть подтверждающее доказательство;",
        "— мера «Реализована частично», если нарушения есть на части хостов; в проценте "
        "реализации она учитывается с весом {{ measures.stats.partial_weight or '0,5' }};",
        "— мера «Не реализована», если нарушения на всех проверенных хостах или "
        "доказательство отсутствует;",
        "— компенсированная мера оценивается по худшему статусу компенсирующих мер;",
        "— итоговый статус каждой меры подтверждает эксперт.",
    ):
        _p(doc, line)
    heading(doc, "6. Перечень проверок")
    _p(doc, "{%p if measures.groups %}")
    measure_groups(
        doc,
        ["Мера", "Содержание меры", "Метод проверки"],
        ["{{ m.id }}", "{{ m.title }}", "{{ m.method_title }}"],
        [2, 10.5, 4.5],
    )
    _p(doc, "{%p else %}")
    _p(doc, "{{ empty.measures.groups }}", color=RED)
    _p(doc, "{%p endif %}")
    heading(doc, "7. Средства защиты информации, подлежащие проверке")
    optional_table(
        doc,
        "szi",
        "empty.szi",
        lambda: loop_table(
            doc,
            ["СЗИ", "Сертификат", "Действует до", "Размещение"],
            "for z in szi",
            [
                "{{ z.name }}",
                "{{ z.cert_number or '—' }}",
                "{{ z.valid_to or '—' }}",
                "{{ z.placement or '—' }}",
            ],
            [5, 3, 3, 6],
        ),
    )
    heading(doc, "8. Состав комиссии")
    responsible_table(doc, signature=True)
    unverified_block(doc)
    return doc


# ---------- 7. Протоколы испытаний ----------


def test_protocols() -> Document:
    doc = _base()
    cover(doc, "ПРОТОКОЛЫ АТТЕСТАЦИОННЫХ ИСПЫТАНИЙ")
    heading(doc, "Общие сведения")
    kv_table(
        doc,
        object_rows(
            ("Класс / уровень / категория", "{{ classification.result_label }}"),
            (
                "Снимок «Сканера»",
                "№ {{ snapshot.number }}, прогон № {{ snapshot.run_id or '—' }} "
                "«{{ snapshot.run_name or '—' }}», завершён {{ snapshot.run_finished or '—' }}",
            ),
            ("Процент «Сканера» по прогону", "{{ snapshot.percent or '—' }}"),
            (
                "Реализация мер",
                "всего {{ measures.stats.percent or '—' }} (автоматически "
                "{{ measures.stats.auto_percent or '—' }}, вручную "
                "{{ measures.stats.manual_percent or '—' }})",
            ),
        ),
    )
    _p(doc, "{%p for g in measures.groups %}")
    heading(doc, "Протокол № {{ loop.index }}. {{ g.code }} — {{ g.title }}", new_page=True)
    _p(
        doc,
        "Мер в группе: {{ g.rows|length }}; реализовано: {{ g.implemented }}; с нарушениями: "
        "{{ g.nonconforming }}; не оценено: {{ g.unassessed }}.",
    )
    loop_table(
        doc,
        ["Мера", "Результат", "Автоматическая проверка", "Ручная проверка", "Подтверждено"],
        "for m in g.rows",
        [
            "{{ m.id }} {{ m.title }}",
            "{{ m.status_title }}{% if m.adaptation_title %} ({{ m.adaptation_title|lower }}"
            "{% if m.compensating %}: {{ m.compensating }}{% endif %}){% endif %}",
            "{{ m.auto or '—' }}{% if m.failed_hosts %}. Хосты с нарушениями: "
            "{{ m.failed_hosts }}{% endif %}",
            "{{ m.manual or '—' }}",
            "{{ m.confirmed or 'нет' }}",
        ],
        [4, 2.4, 4.6, 3.8, 2.2],
    )
    _p(doc, "{%p endfor %}")
    _p(doc, "{%p if not measures.groups %}")
    _p(doc, "{{ empty.measures.groups }}", color=RED)
    _p(doc, "{%p endif %}")

    heading(doc, "Протокол анализа уязвимостей", new_page=True)
    methodology_ref(doc)
    levels_table(doc)
    _p(doc)
    _p(
        doc,
        "Обнаружено уязвимостей: {{ vulns.counts.total }} (критических "
        "{{ vulns.counts.critical }}, высоких {{ vulns.counts.high }}, средних "
        "{{ vulns.counts.medium }}, низких {{ vulns.counts.low }}; не оценено "
        "{{ vulns.counts.not_assessed }}).",
    )
    vulns_table(doc)
    heading(doc, "Подписи")
    signatures(doc, ["Эксперт", "Эксперт", "Представитель оператора"])
    unverified_block(doc)
    return doc


# ---------- 8. Заключение и проект аттестата ----------


def conclusion() -> Document:
    doc = _base()
    _p(doc, "{{ customer.name }}", align=WD_ALIGN_PARAGRAPH.CENTER, color=GREY)
    _p(doc, "ЗАКЛЮЧЕНИЕ", bold=True, size=18, align=WD_ALIGN_PARAGRAPH.CENTER)
    _p(
        doc,
        "по результатам аттестационных испытаний объекта «{{ object.name }}»",
        bold=True,
        align=WD_ALIGN_PARAGRAPH.CENTER,
    )
    _p(doc, "{{ doc.generated }}", align=WD_ALIGN_PARAGRAPH.RIGHT)
    heading(doc, "1. Общие сведения")
    kv_table(
        doc,
        object_rows(
            ("Адрес", "{{ customer.address }}"),
            ("Договор", "{{ project.contract_ref }}"),
            ("Класс / уровень / категория", "{{ classification.result_label }}"),
            ("Классификация утверждена", "{{ classification.approved }}"),
            ("Модель угроз утверждена", "{{ threat_model.approved }}"),
        ),
    )
    heading(doc, "2. Результаты испытаний")
    _p(
        doc,
        "Испытания проведены по программе и методикам аттестационных испытаний; "
        "автоматические проверки — по снимку «Сканера» № {{ snapshot.number }} "
        "(прогон № {{ snapshot.run_id or '—' }}, {{ snapshot.run_finished or '—' }}).",
    )
    kv_table(
        doc,
        [
            ("Мер в наборе (после адаптации)", "{{ measures.stats.total or '—' }}"),
            ("Реализовано", "{{ measures.stats.implemented }}"),
            ("Реализовано частично", "{{ measures.stats.partial }}"),
            ("Не реализовано", "{{ measures.stats.not_implemented }}"),
            ("Не оценено", "{{ measures.stats.unassessed }}"),
            ("Исключено при адаптации", "{{ measures.stats.excluded }}"),
            (
                "Процент реализации",
                "{{ measures.stats.percent or '—' }} (автоматически "
                "{{ measures.stats.auto_percent or '—' }}, вручную "
                "{{ measures.stats.manual_percent or '—' }})",
            ),
            ("Подтверждено экспертом", "{{ measures.stats.confirmed }}"),
            (
                "Уязвимости (Методика 2025)",
                "{{ vulns.counts.total }}: критических {{ vulns.counts.critical }}, высоких "
                "{{ vulns.counts.high }}, средних {{ vulns.counts.medium }}, низких "
                "{{ vulns.counts.low }}, не оценено {{ vulns.counts.not_assessed }}",
            ),
        ],
    )
    heading(doc, "2.1. Средства защиты информации", level=2)
    optional_table(
        doc,
        "szi",
        "empty.szi",
        lambda: loop_table(
            doc,
            ["СЗИ", "Сертификат", "Действует до", "Состояние"],
            "for z in szi",
            ["{{ z.name }}", "{{ z.cert_number }}", "{{ z.valid_to }}", "{{ z.state_title }}"],
            [5.5, 3, 3, 5.5],
        ),
    )
    heading(doc, "3. Выводы")
    _p(
        doc,
        "{%p if measures.stats.total and not measures.stats.not_implemented and "
        "not measures.stats.partial and not measures.stats.unassessed and "
        "not vulns.counts.critical and not vulns.counts.high and not vulns.counts.not_assessed %}",
    )
    _p(
        doc,
        "Все меры набора объекта реализованы и подтверждены испытаниями, критических и "
        "высоких уязвимостей не выявлено. Комиссия считает возможным выдать аттестат "
        "соответствия (проект — в приложении).",
    )
    _p(doc, "{%p else %}")
    _p(
        doc,
        "По результатам испытаний выявлены несоответствия: не реализовано мер — "
        "{{ measures.stats.not_implemented or 0 }}, реализовано частично — "
        "{{ measures.stats.partial or 0 }}, не оценено — {{ measures.stats.unassessed or 0 }}; "
        "критических и высоких уязвимостей — "
        "{{ (vulns.counts.critical or 0) + (vulns.counts.high or 0) }}. "
        "Аттестат соответствия может быть выдан после устранения несоответствий по плану "
        "мероприятий и повторных испытаний.",
    )
    _p(doc, "{%p endif %}")
    note(doc, "Вывод сформирован по данным испытаний и подлежит проверке председателем комиссии.")
    heading(doc, "4. Подписи")
    signatures(doc, ["Председатель комиссии", "Член комиссии", "Член комиссии"])

    heading(doc, "Приложение. Проект аттестата соответствия", new_page=True)
    _p(doc, "АТТЕСТАТ СООТВЕТСТВИЯ № ______", bold=True, size=14, align=WD_ALIGN_PARAGRAPH.CENTER)
    _p(doc, "требованиям по защите информации", align=WD_ALIGN_PARAGRAPH.CENTER)
    kv_table(
        doc,
        [
            ("Объект", "{{ object.name }}"),
            ("Владелец (оператор)", "{{ customer.name }}, {{ customer.address }}"),
            ("Требования", "{{ object.regime_title or '—' }}"),
            ("Класс / уровень / категория", "{{ classification.result_label }}"),
            (
                "Выдан на основании",
                "заключения по результатам аттестационных испытаний от {{ doc.generated }}",
            ),
            ("Срок действия", "______________"),
            ("Дата выдачи", "«___» ____________ 20___ г."),
        ],
    )
    _p(doc)
    _p(doc, "Применяемые средства защиты информации:")
    _p(doc, "{%p for z in szi %}")
    _p(doc, "— {{ z.name }}, сертификат № {{ z.cert_number }}, действует до {{ z.valid_to }};")
    _p(doc, "{%p endfor %}")
    _p(doc)
    signatures(doc, ["Руководитель органа по аттестации"])
    unverified_block(doc)
    return doc


# ---------- 9. План устранения несоответствий ----------


def remediation_plan() -> Document:
    doc = _base()
    _p(doc, "{{ customer.name }}", align=WD_ALIGN_PARAGRAPH.CENTER, color=GREY)
    _p(doc, "ПЛАН", bold=True, size=18, align=WD_ALIGN_PARAGRAPH.CENTER)
    _p(
        doc,
        "мероприятий по устранению несоответствий объекта «{{ object.name }}»",
        bold=True,
        align=WD_ALIGN_PARAGRAPH.CENTER,
    )
    _p(
        doc,
        "Класс / уровень / категория: {{ classification.result_label }}. "
        "Версия {{ doc.version }} от {{ doc.generated }}.",
        align=WD_ALIGN_PARAGRAPH.CENTER,
        color=GREY,
    )
    heading(doc, "1. Несоответствия по мерам защиты информации")
    note(
        doc,
        "Меры со статусом «Не реализована» и «Реализована частично». Сроки по умолчанию "
        "не указываются (п. 9 ТЗ) — при необходимости их вносит ответственный.",
    )
    if_else(
        doc,
        "nonconformities",
        lambda: loop_table(
            doc,
            ["№", "Мера", "Несоответствие", "Мероприятие", "Ответственный"],
            "for n in nonconformities",
            [
                "{{ loop.index }}",
                "{{ n.ref }} {{ n.title }}",
                "{{ n.status_title }}. {{ n.details }}",
                "{{ n.action }}",
                "",
            ],
            [0.8, 4, 5.2, 4.5, 2.5],
        ),
        "Несоответствий по мерам не выявлено.",
    )
    heading(doc, "2. Уязвимости")
    _p(
        doc,
        "Уязвимости с оценкой по Методике оценки уровня критичности уязвимостей (ФСТЭК России, "
        "30.06.2025); срок устранения — по п. 21 от даты оценки. Способ устранения — "
        "обновление или компенсирующие меры.",
    )
    if_else(
        doc,
        "vuln_plan",
        lambda: loop_table(
            doc,
            ["№", "Уязвимость", "Уровень", "Мероприятие", "Устранить до", "Ответственный"],
            "for v in vuln_plan",
            [
                "{{ loop.index }}",
                "{{ v.ref }} {{ v.title }}{% if v.details %} ({{ v.details }}){% endif %}",
                "{{ v.status_title }}",
                "{{ v.action }}",
                "{{ v.deadline or '—' }}",
                "",
            ],
            [0.8, 5, 2.6, 3.6, 2.6, 2.4],
        ),
        "Оценённых уязвимостей нет.",
    )
    heading(doc, "3. Ответственные лица")
    responsible_table(doc, signature=True)
    unverified_block(doc)
    return doc


TEMPLATES = {
    "classification-act.docx": classification_act,
    "threat-model.docx": threat_model,
    "protection-spec.docx": protection_spec,
    "tech-passport.docx": tech_passport,
    "org-docs.docx": org_docs,
    "test-program.docx": test_program,
    "test-protocols.docx": test_protocols,
    "conclusion.docx": conclusion,
    "remediation-plan.docx": remediation_plan,
}


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
