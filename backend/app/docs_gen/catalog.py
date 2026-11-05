"""Каталог документов комплекта: reference/documents/catalog.yaml.

Каталог — данные: какие документы есть, из какого шаблона они собираются и
какие поля контекста в них попадают (карта «из каких данных собран»). Код
каталога не содержит; проверка при загрузке ловит опечатки в путях полей.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

TABS = (
    "project",
    "description",
    "classification",
    "composition",
    "szi",
    "measures",
    "threats",
    "vulns",
)
# «a.b.c» — поле; «a.b[].c» — поле у каждого элемента списка a.b.
_KEY = re.compile(r"^[a-z_]+(\.[a-z_]+)*(\[\]\.[a-z_]+)?$")


class CatalogError(ValueError):
    """Ошибка в файле каталога; текст — для журнала запуска и тестов."""


@dataclass(frozen=True)
class FieldSpec:
    key: str
    title: str
    source: str
    tab: str
    required: bool = False

    @property
    def is_item_field(self) -> bool:
        """Поле у каждого элемента списка: «hosts[].os»."""
        return "[]." in self.key


@dataclass(frozen=True)
class DocType:
    code: str
    title: str
    description: str
    template: str
    regimes: tuple[str | None, ...]
    fields: tuple[FieldSpec, ...]
    # Заголовок по режиму: акт классификации ГИС, УЗ ПДн, сведения о категорировании.
    titles: tuple[tuple[str, str], ...] = ()

    def applies_to(self, regime: str | None) -> bool:
        return regime in self.regimes

    def title_for(self, regime: str | None) -> str:
        return dict(self.titles).get(regime or "", self.title)


def _field(doc: str, raw: dict[str, Any]) -> FieldSpec:
    try:
        spec = FieldSpec(
            key=str(raw["key"]),
            title=str(raw["title"]),
            source=str(raw["source"]),
            tab=str(raw["tab"]),
            required=bool(raw.get("required", False)),
        )
    except KeyError as e:
        raise CatalogError(f"{doc}: у поля нет «{e.args[0]}»") from e
    if not _KEY.match(spec.key):
        raise CatalogError(f"{doc}: неверный путь поля «{spec.key}»")
    if spec.tab not in TABS:
        raise CatalogError(f"{doc}: {spec.key}: неизвестная вкладка «{spec.tab}»")
    return spec


def parse(data: dict[str, Any]) -> dict[str, DocType]:
    out: dict[str, DocType] = {}
    for raw in data.get("documents") or []:
        code = str(raw.get("code") or "")
        if not code or code in out:
            raise CatalogError(f"Пустой или повторный код документа «{code}»")
        fields = tuple(_field(code, f) for f in raw.get("fields") or [])
        keys = [f.key for f in fields]
        if len(keys) != len(set(keys)):
            raise CatalogError(f"{code}: поле указано дважды")
        for f in fields:
            # У поля элемента списка должен быть описан и сам список.
            if f.is_item_field and f.key.split("[]")[0] not in keys:
                raise CatalogError(f"{code}: {f.key}: не описан список {f.key.split('[]')[0]}")
        out[code] = DocType(
            code=code,
            title=str(raw["title"]),
            description=str(raw.get("description") or "").strip(),
            template=str(raw["template"]),
            regimes=tuple(None if r is None else str(r) for r in raw.get("regimes") or []),
            fields=fields,
            titles=tuple((str(k), str(v)) for k, v in (raw.get("titles") or {}).items()),
        )
    return out


_cache: dict[Path, tuple[float, dict[str, DocType]]] = {}


def load(reference_dir: Path) -> dict[str, DocType]:
    """Каталог из файла; перечитывается, если файл изменился."""
    path = reference_dir / "documents" / "catalog.yaml"
    mtime = path.stat().st_mtime
    hit = _cache.get(path)
    if hit and hit[0] == mtime:
        return hit[1]
    docs = parse(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
    _cache[path] = (mtime, docs)
    return docs


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
