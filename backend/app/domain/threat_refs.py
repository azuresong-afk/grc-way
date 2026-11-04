"""Справочник Методики оценки угроз 2021: разбор файла и правила целостности.

Файл reference/threats/methodology-2021.yaml описывает разделы (виды записей) и
записи; здесь он превращается в плоский список записей с родителями, порядком и
полным источником. Те же правила проверяют правку и добавление в интерфейсе.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

KINDS = ("consequence_type", "consequence", "capability", "intruder", "tactic", "technique")
# Вид записи → вид её родителя (у остальных родителя нет).
PARENT_KIND = {"consequence": "consequence_type", "technique": "tactic"}
KIND_TITLES = {
    "consequence_type": "Вид негативных последствий",
    "consequence": "Негативное последствие",
    "capability": "Уровень возможностей нарушителя",
    "intruder": "Вид нарушителя",
    "tactic": "Тактика",
    "technique": "Техника",
}
INTRUDER_CATEGORIES = ("внешний", "внутренний")
_ITEM_KEYS = {"code", "title", "description", "source", "attrs", "children"}
_CODE = re.compile(r"^[0-9A-Za-zА-Яа-яЁё][0-9A-Za-zА-Яа-яЁё._-]{0,31}$")


class ThreatRefError(ValueError):
    """Справочник или правка нарушают правила."""


def item_hash(item: dict[str, Any]) -> str:
    keys = ("kind", "parent_code", "position", "title", "description", "attrs", "source")
    raw = json.dumps({k: item.get(k) for k in keys}, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _source(document: dict[str, Any], *layers: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(document)
    for layer in layers:
        out.update({k: v for k, v in (layer or {}).items() if v not in (None, "")})
    return out


def parse(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Плоский список записей файла в порядке файла; проверяет целостность."""
    document = data.get("document") or {}
    if not document.get("document"):
        raise ThreatRefError("в файле не указан документ-источник (document.document)")
    origin = data.get("origin") or "stub"
    items: list[dict[str, Any]] = []
    for section in data.get("sections") or []:
        kind = section.get("kind")
        child_kind = section.get("child_kind")
        for pos, raw in enumerate(section.get("items") or []):
            # Лишний ключ — почти всегда запятая в наименовании без кавычек в
            # записи вида {code: …, title: …}: YAML режет наименование.
            if extra := set(raw) - _ITEM_KEYS:
                raise ThreatRefError(
                    f"{raw.get('code')}: лишние ключи {sorted(map(str, extra))} — "
                    "возьмите наименование в кавычки"
                )
            item = {
                "code": str(raw["code"]),
                "kind": kind,
                "parent_code": None,
                "position": pos,
                "title": raw["title"],
                "description": raw.get("description"),
                "attrs": dict(raw.get("attrs") or {}),
                "source": _source(document, section.get("source"), raw.get("source")),
                "origin": origin,
            }
            items.append(item)
            children = raw.get("children") or []
            if children and not child_kind:
                raise ThreatRefError(f"{item['code']}: у раздела {kind} не указан child_kind")
            for cpos, child in enumerate(children, start=1):
                c = child if isinstance(child, dict) else {"title": child}
                items.append(
                    {
                        "code": str(c.get("code") or f"{item['code']}.{cpos}"),
                        "kind": child_kind,
                        "parent_code": item["code"],
                        "position": cpos,
                        "title": c["title"],
                        "description": c.get("description"),
                        "attrs": dict(c.get("attrs") or {}),
                        "source": _source(
                            document, section.get("source"), raw.get("source"), c.get("source")
                        ),
                        "origin": origin,
                    }
                )
    validate(items)
    return items


def validate_item(item: dict[str, Any], kinds_by_code: dict[str, str]) -> None:
    code, kind = item["code"], item["kind"]
    if kind not in KINDS:
        raise ThreatRefError(f"{code}: неизвестный вид записи «{kind}»")
    if not _CODE.match(code):
        raise ThreatRefError(f"{code}: код — буквы, цифры, точка, дефис; до 32 знаков")
    if not (item.get("title") or "").strip():
        raise ThreatRefError(f"{code}: не указано наименование")
    want_parent = PARENT_KIND.get(kind)
    parent = item.get("parent_code")
    if want_parent:
        if kinds_by_code.get(parent or "") != want_parent:
            raise ThreatRefError(
                f"{code}: родителем должна быть запись вида «{KIND_TITLES[want_parent]}»"
            )
    elif parent:
        raise ThreatRefError(f"{code}: у записи вида «{KIND_TITLES[kind]}» нет родителя")
    if kind == "intruder":
        attrs = item.get("attrs") or {}
        cap = attrs.get("capability")
        if cap is not None and kinds_by_code.get(cap) != "capability":
            raise ThreatRefError(f"{code}: неизвестный уровень возможностей «{cap}»")
        cat = attrs.get("category")
        if cat is not None and cat not in INTRUDER_CATEGORIES:
            raise ThreatRefError(f"{code}: категория — «внешний» или «внутренний»")


def validate(items: list[dict[str, Any]]) -> None:
    kinds_by_code: dict[str, str] = {}
    for item in items:
        if item["code"] in kinds_by_code:
            raise ThreatRefError(f"{item['code']}: код повторяется")
        kinds_by_code[item["code"]] = item["kind"]
    for item in items:
        validate_item(item, kinds_by_code)
