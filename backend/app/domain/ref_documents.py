"""Справочник нормативных документов: разбор файла и правила целостности.

Файл reference/normative/documents.yaml — список документов с реквизитами и
статусом. Те же правила проверяют правку в интерфейсе.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from typing import Any

STATUSES = ("active", "not_applicable")
STATUS_TITLES = {"active": "Применяется", "not_applicable": "Не применяется"}
FIELDS = (
    "position",
    "short",
    "title",
    "issuer",
    "issued",
    "number",
    "url",
    "status",
    "replaced_by",
    "source",
)
_KEYS = {"code", "origin", *FIELDS} - {"position"}
_CODE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class DocumentError(ValueError):
    """Справочник документов или правка нарушают правила."""


def doc_hash(doc: dict[str, Any]) -> str:
    data = {k: doc.get(k) for k in FIELDS}
    if isinstance(data["issued"], date):
        data["issued"] = data["issued"].isoformat()
    raw = json.dumps(data, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _issued(value: Any, code: str) -> date | None:
    if value in (None, ""):
        return None
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except ValueError as e:
        raise DocumentError(f"{code}: дата утверждения — ГГГГ-ММ-ДД") from e


def parse(data: dict[str, Any]) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for pos, raw in enumerate(data.get("documents") or []):
        code = str(raw.get("code") or "")
        if extra := set(raw) - _KEYS:
            raise DocumentError(f"{code}: лишние ключи {sorted(map(str, extra))}")
        docs.append(
            {
                "code": code,
                "position": pos,
                "short": raw.get("short") or raw.get("title"),
                "title": raw.get("title"),
                "issuer": raw.get("issuer"),
                "issued": _issued(raw.get("issued"), code),
                "number": str(raw["number"]) if raw.get("number") is not None else None,
                "url": raw.get("url"),
                "status": raw.get("status") or "active",
                "replaced_by": raw.get("replaced_by"),
                "source": dict(raw.get("source") or {}),
                "origin": raw.get("origin") or "stub",
            }
        )
    validate(docs)
    return docs


def validate_doc(doc: dict[str, Any], codes: set[str]) -> None:
    code = doc["code"]
    if not _CODE.match(code):
        raise DocumentError(f"{code}: код — строчные латинские буквы, цифры, точка, дефис")
    if not (doc.get("title") or "").strip() or not (doc.get("short") or "").strip():
        raise DocumentError(f"{code}: не указано наименование")
    if doc.get("status") not in STATUSES:
        raise DocumentError(f"{code}: статус — active или not_applicable")
    replaced = doc.get("replaced_by")
    if replaced:
        if replaced == code or replaced not in codes:
            raise DocumentError(f"{code}: заменивший документ «{replaced}» не найден")
        if doc["status"] != "not_applicable":
            raise DocumentError(f"{code}: заменённый документ должен иметь статус «не применяется»")
    src = doc.get("source") or {}
    if doc["status"] == "not_applicable" and not (src.get("document") and src.get("clause")):
        raise DocumentError(
            f"{code}: для статуса «не применяется» укажите основание — документ и пункт"
        )


def validate(docs: list[dict[str, Any]]) -> None:
    codes: set[str] = set()
    for d in docs:
        if d["code"] in codes:
            raise DocumentError(f"{d['code']}: код повторяется")
        codes.add(d["code"])
    for d in docs:
        validate_doc(d, codes)
