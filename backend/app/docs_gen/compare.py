"""Сравнение двух версий документа (задача 3.3).

Три уровня:
- сведения о версии: шаблон, шрифт, статус, несверенные записи;
- карта полей: какие поля изменили значение или состояние;
- текст документа: абзацы и строки таблиц тела DOCX (без колонтитулов, где
  номер версии и страницы), построчное сравнение difflib с контекстом.
"""

from __future__ import annotations

import difflib
import io
from dataclasses import dataclass, field
from typing import Any

from docx import Document
from docx.table import Table
from docx.text.paragraph import Paragraph

# Строк контекста вокруг изменения и предел вывода (длинные протоколы).
CONTEXT_LINES = 2
MAX_LINES = 1500


def text_lines(docx: bytes) -> list[str]:
    """Текст тела документа по порядку: абзацы и строки таблиц («ячейка | ячейка»)."""
    doc = Document(io.BytesIO(docx))
    out: list[str] = []
    body = doc.element.body
    for child in body.iterchildren():
        tag = child.tag.rsplit("}", 1)[-1]
        if tag == "p":
            text = Paragraph(child, doc).text.strip()
            if text:
                out.append(text)
        elif tag == "tbl":
            for row in Table(child, doc).rows:
                cells: list[str] = []
                prev = None
                for cell in row.cells:
                    # Объединённые ячейки python-docx отдаёт повторно — берём один раз.
                    if prev is not None and cell._tc is prev:
                        continue
                    prev = cell._tc
                    cells.append(" ".join(p.text.strip() for p in cell.paragraphs).strip())
                line = " | ".join(cells).strip(" |")
                if line:
                    out.append(line)
    return out


@dataclass
class Hunk:
    # Строки «было» и «стало» начинаются с old_start / new_start (с 1).
    old_start: int
    new_start: int
    lines: list[dict[str, str]] = field(default_factory=list)


def text_diff(old: list[str], new: list[str]) -> tuple[list[Hunk], dict[str, int], bool]:
    """Изменения текста: фрагменты с контекстом, счётчики, обрезан ли вывод."""
    sm = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
    hunks: list[Hunk] = []
    stats = {"added": 0, "removed": 0}
    shown = 0
    truncated = False
    for group in sm.get_grouped_opcodes(CONTEXT_LINES):
        if shown >= MAX_LINES:
            truncated = True
            break
        h = Hunk(old_start=group[0][1] + 1, new_start=group[0][3] + 1)
        for op, i1, i2, j1, j2 in group:
            if op == "equal":
                h.lines += [{"op": "same", "text": t} for t in old[i1:i2]]
                continue
            if op in ("delete", "replace"):
                h.lines += [{"op": "del", "text": t} for t in old[i1:i2]]
                stats["removed"] += i2 - i1
            if op in ("insert", "replace"):
                h.lines += [{"op": "add", "text": t} for t in new[j1:j2]]
                stats["added"] += j2 - j1
        shown += len(h.lines)
        hunks.append(h)
    return hunks, stats, truncated


def field_changes(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Поля карты, у которых изменилось значение или состояние (в порядке новой версии)."""
    before = {f["key"]: f for f in old}
    after = {f["key"]: f for f in new}
    keys = [f["key"] for f in new] + [k for k in before if k not in after]
    out = []
    for k in keys:
        a, b = before.get(k), after.get(k)

        def summary(f: dict[str, Any] | None) -> str | None:
            if f is None:
                return None
            if f.get("total") is not None:
                total, missing = f.get("total") or 0, f.get("missing") or 0
                return f"записей: {total}" + (f", не заполнено у {missing}" if missing else "")
            return f.get("value")

        sa, sb = summary(a), summary(b)
        state_a = a["state"] if a else None
        state_b = b["state"] if b else None
        if sa == sb and state_a == state_b:
            continue
        ref = b or a
        assert ref is not None  # noqa: S101 — ключ есть хотя бы в одной версии
        out.append(
            {
                "key": k,
                "title": ref["title"],
                "tab": ref.get("tab"),
                "before": sa,
                "after": sb,
                "state_before": state_a,
                "state_after": state_b,
            }
        )
    return out
