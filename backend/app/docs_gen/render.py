"""Рендер шаблона docxtpl и водяной знак «Проект».

Шаблон — обычный DOCX с полями Jinja (docxtpl). Автоэкранирование включено:
значения из данных не могут вставить разметку в документ. Водяной знак —
фигура VML в колонтитуле каждого раздела, как его вставляет Word
(«Конструктор → Подложка»); LibreOffice переносит его в PDF.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import jinja2
from docx.oxml import parse_xml
from docxtpl import DocxTemplate

WATERMARK_TEXT = "ПРОЕКТ"

_VML = (
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:v="urn:schemas-microsoft-com:vml" '
    'xmlns:o="urn:schemas-microsoft-com:office:office" '
    'xmlns:w10="urn:schemas-microsoft-com:office:word"'
)


class RenderError(ValueError):
    """Шаблон не собрался; текст — для пользователя."""


def _watermark_run(text: str, n: int) -> Any:
    return parse_xml(
        f"<w:r {_VML}><w:pict>"
        '<v:shapetype id="_x0000_t136" coordsize="21600,21600" o:spt="136" adj="10800" '
        'path="m@7,l@8,m@5,21600l@6,21600e">'
        '<v:path textpathok="t" o:connecttype="custom"/>'
        '<v:textpath on="t" fitshape="t"/>'
        '<o:lock v:ext="edit" text="t" shapetype="t"/>'
        "</v:shapetype>"
        f'<v:shape id="PowerPlusWaterMarkObject{n}" o:spid="_x0000_s20{50 + n}" '
        'type="#_x0000_t136" '
        'style="position:absolute;margin-left:0;margin-top:0;width:460pt;height:115pt;'
        "rotation:315;z-index:-251654144;mso-position-horizontal:center;"
        "mso-position-horizontal-relative:margin;mso-position-vertical:center;"
        'mso-position-vertical-relative:margin" o:allowincell="f" fillcolor="#c8c8c8" '
        'stroked="f">'
        '<v:fill opacity=".45"/>'
        f'<v:textpath style="font-family:&quot;Liberation Sans&quot;;font-size:1pt" '
        f'string="{text}"/>'
        '<w10:wrap anchorx="margin" anchory="margin"/>'
        "</v:shape></w:pict></w:r>"
    )


def add_watermark(doc: Any, text: str = WATERMARK_TEXT) -> None:
    """Подложка в основном колонтитуле каждого раздела документа python-docx."""
    for n, section in enumerate(doc.sections, start=1):
        header = section.header
        header.is_linked_to_previous = False
        p = header.paragraphs[0] if header.paragraphs else header.add_paragraph()
        p._p.append(_watermark_run(text, n))


def render(template: Path, context: dict[str, Any], *, watermark: bool) -> bytes:
    """DOCX по шаблону и контексту (с заглушками на месте пустых полей)."""
    tpl = DocxTemplate(str(template))
    env = jinja2.Environment(autoescape=True, undefined=jinja2.StrictUndefined)
    try:
        tpl.render(context, jinja_env=env)
    except jinja2.TemplateError as e:
        raise RenderError(f"Шаблон {template.name} не собрался: {e}") from e
    if watermark:
        add_watermark(tpl.docx)
    buf = io.BytesIO()
    tpl.save(buf)
    return buf.getvalue()


def template_variables(template: Path) -> set[str]:
    """Имена верхнего уровня, которые использует шаблон (для проверки каталога)."""
    return set(DocxTemplate(str(template)).get_undeclared_template_variables())
