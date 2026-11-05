"""Карта «из каких данных собран документ» и заглушки на месте пустых полей."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from typing import Any

from app.docs_gen.catalog import DocType, FieldSpec

# Сколько символов значения показывать в карте.
_PREVIEW = 160
MISSING_ITEM = "[не указано]"


def placeholder(title: str) -> str:
    return f"[не заполнено: {title}]"


def is_empty(v: Any) -> bool:
    return v is None or v == "" or v == [] or v == {}


def _get(ctx: dict[str, Any], path: str) -> Any:
    cur: Any = ctx
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _set(ctx: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur = ctx
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


def _preview(v: Any) -> str | None:
    if is_empty(v):
        return None
    if isinstance(v, list):
        return f"{len(v)} шт."
    s = str(v)
    return s if len(s) <= _PREVIEW else s[: _PREVIEW - 1] + "…"


@dataclass
class FieldState:
    key: str
    title: str
    source: str
    tab: str
    required: bool
    # filled — заполнено; empty — пусто; partial — у части элементов списка;
    # na — список пуст, проверять нечего.
    state: str
    value: str | None
    # Для поля элементов списка: сколько элементов и у скольких поле пустое.
    total: int | None = None
    missing: int | None = None
    # Примеры элементов без значения (адрес хоста, имя СЗИ).
    missing_examples: list[str] | None = None


def _item_label(item: dict[str, Any]) -> str:
    for k in ("address", "name", "system"):
        if item.get(k):
            return str(item[k])
    return "?"


def _state(ctx: dict[str, Any], f: FieldSpec) -> FieldState:
    base = {"key": f.key, "title": f.title, "source": f.source, "tab": f.tab}
    if f.is_item_field:
        list_key, item_key = f.key.split("[].")
        items = _get(ctx, list_key) or []
        missing = [it for it in items if is_empty(it.get(item_key))]
        if not items:
            state = "na"
        elif not missing:
            state = "filled"
        elif len(missing) == len(items):
            state = "empty"
        else:
            state = "partial"
        return FieldState(
            **base,
            required=f.required,
            state=state,
            value=None,
            total=len(items),
            missing=len(missing),
            missing_examples=[_item_label(it) for it in missing[:5]],
        )
    v = _get(ctx, f.key)
    return FieldState(
        **base,
        required=f.required,
        state="empty" if is_empty(v) else "filled",
        value=_preview(v),
    )


def field_map(ctx: dict[str, Any], doc: DocType) -> list[FieldState]:
    return [_state(ctx, f) for f in doc.fields]


def map_out(states: list[FieldState]) -> list[dict[str, Any]]:
    return [asdict(s) for s in states]


def counts(states: list[FieldState]) -> dict[str, int]:
    """Сводка карты: всего полей, пустых, пустых обязательных."""
    gaps = [s for s in states if s.state in ("empty", "partial")]
    return {
        "total": len(states),
        "empty": len(gaps),
        "required_empty": sum(1 for s in gaps if s.required),
    }


def fill_placeholders(ctx: dict[str, Any], doc: DocType) -> dict[str, Any]:
    """Копия контекста для шаблона: на месте пустых полей — заметные заглушки.

    Пустое скалярное поле получает «[не заполнено: …]», пустое поле элемента
    списка — «[не указано]». Для пустых списков заглушка кладётся в
    `empty.<путь>`: шаблон выводит её вместо таблицы.
    """
    out = copy.deepcopy(ctx)
    empty: dict[str, Any] = {}
    for f in doc.fields:
        if f.is_item_field:
            list_key, item_key = f.key.split("[].")
            for it in _get(out, list_key) or []:
                if is_empty(it.get(item_key)):
                    it[item_key] = MISSING_ITEM
            continue
        v = _get(out, f.key)
        if isinstance(v, list) or (v is None and _is_list_field(doc, f)):
            if not v:
                _set(empty, f.key, placeholder(f.title))
                _set(out, f.key, [])
        elif is_empty(v):
            _set(out, f.key, placeholder(f.title))
    out["empty"] = empty
    return out


def _is_list_field(doc: DocType, f: FieldSpec) -> bool:
    return any(o.is_item_field and o.key.startswith(f.key + "[]") for o in doc.fields)
