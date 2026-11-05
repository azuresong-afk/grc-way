"""Рендер шаблона docxtpl, шрифт комплекта и водяной знак «Проект».

Шаблон — обычный DOCX с полями Jinja (docxtpl). Автоэкранирование включено:
значения из данных не могут вставить разметку в документ. Jinja работает в
песочнице (SandboxedEnvironment): свой шаблон, загруженный пользователем, не
может обратиться к внутренностям Python (`__class__`, `__globals__` и т. п.).
Шрифт встроенных шаблонов (PT Astra Serif или Inter) подставляется в стили
документа при формировании. Водяной знак —
фигура VML в колонтитуле каждого раздела, как его вставляет Word
(«Конструктор → Подложка»); LibreOffice переносит его в PDF.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import jinja2
from docx.oxml import parse_xml
from docx.oxml.ns import qn
from docxtpl import DocxTemplate
from jinja2.sandbox import SandboxedEnvironment

WATERMARK_TEXT = "ПРОЕКТ"
# Шрифты комплекта для встроенных шаблонов (ТЗ: «Inter / PT Astra Serif на выбор»).
FONTS = {"astra": "PT Astra Serif", "inter": "Inter"}
DEFAULT_FONT = "astra"
_FONT_ATTRS = ("ascii", "hAnsi", "cs", "eastAsia")
_THEME_ATTRS = ("asciiTheme", "hAnsiTheme", "cstheme", "eastAsiaTheme")

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


def apply_font(doc: Any, family: str) -> None:
    """Шрифт во всех стилях и в умолчаниях документа (стили встроенных шаблонов
    задают шрифт явно, у прогонов текста своего шрифта нет)."""
    styles = doc.styles.element
    defaults = styles.find(qn("w:docDefaults"))
    nodes = list(styles.iter(qn("w:rFonts")))
    if defaults is not None and not any(True for _ in defaults.iter(qn("w:rFonts"))):
        rpr_default = defaults.find(qn("w:rPrDefault"))
        if rpr_default is not None:
            rpr = rpr_default.find(qn("w:rPr"))
            if rpr is not None:
                el = rpr.makeelement(qn("w:rFonts"), {})
                rpr.insert(0, el)
                nodes.append(el)
    for el in nodes:
        for attr in _THEME_ATTRS:
            el.attrib.pop(qn(f"w:{attr}"), None)
        for attr in _FONT_ATTRS:
            el.set(qn(f"w:{attr}"), family)


def _env() -> jinja2.Environment:
    return SandboxedEnvironment(autoescape=True, undefined=jinja2.StrictUndefined)


def render(
    template: Path, context: dict[str, Any], *, watermark: bool, font: str | None = None
) -> bytes:
    """DOCX по шаблону и контексту (с заглушками на месте пустых полей).

    font — код шрифта (FONTS) для встроенного шаблона; None — шрифты шаблона.
    """
    tpl = DocxTemplate(str(template))
    try:
        tpl.render(context, jinja_env=_env())
    except jinja2.exceptions.SecurityError as e:
        raise RenderError(f"Шаблон {template.name}: недопустимое выражение — {e}") from e
    except jinja2.TemplateError as e:
        raise RenderError(f"Шаблон {template.name} не собрался: {e}") from e
    except (KeyError, AttributeError, TypeError, ValueError, IndexError) as e:
        raise RenderError(f"Шаблон {template.name} не собрался: {e}") from e
    if font:
        apply_font(tpl.docx, FONTS[font])
    if watermark:
        add_watermark(tpl.docx)
    buf = io.BytesIO()
    tpl.save(buf)
    return buf.getvalue()


_vars_cache: dict[str, frozenset[str]] = {}


def template_variables(template: Path, sha256: str | None = None) -> frozenset[str]:
    """Имена верхнего уровня, которые использует шаблон (кэш по sha256 файла)."""
    if sha256 and sha256 in _vars_cache:
        return _vars_cache[sha256]
    tpl = DocxTemplate(str(template))
    try:
        names = frozenset(tpl.get_undeclared_template_variables(jinja_env=_env()))
    except jinja2.TemplateError as e:
        raise RenderError(f"Шаблон {template.name}: ошибка в полях — {e}") from e
    if sha256:
        _vars_cache[sha256] = names
    return names
