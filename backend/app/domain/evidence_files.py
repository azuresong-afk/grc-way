"""Файлы доказательств: белый список типов, проверка сигнатуры, хранение в томе.

Файл принимается, только если его содержимое соответствует заявленному расширению
из белого списка. Тип определяется по байтам, а не по тому, что прислал браузер.
Документы с макросами (vbaProject.bin в OOXML, Basic/ и Scripts/ в ODF) не
принимаются. Файлы хранятся в томе под именем sha256 содержимого (одинаковые
файлы — одна копия) и отдаются только на скачивание, никогда не исполняются
и не показываются как HTML.
"""

from __future__ import annotations

import codecs
import hashlib
import json
import os
import re
import tempfile
import unicodedata
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


class EvidenceFileError(ValueError):
    """Файл не принят; текст — для пользователя."""

    def __init__(self, detail: str, code: str = "file_rejected") -> None:
        super().__init__(detail)
        self.code = code


# Расширение → MIME, с которым файл будет отдаваться.
ALLOWED: dict[str, str] = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "odt": "application/vnd.oasis.opendocument.text",
    "png": "image/png",
    "jpg": "image/jpeg",
    "txt": "text/plain; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    "json": "application/json",
    "xml": "application/xml",
    "zip": "application/zip",
}
ALIASES = {"jpeg": "jpg", "log": "txt", "conf": "txt", "cfg": "txt"}
ALLOWED_TEXT = ", ".join(ALLOWED)

_ZIP_SIG = b"PK\x03\x04"
_ODT_MIME = b"application/vnd.oasis.opendocument.text"
# Сколько первых байт хватает для проверки текстовых файлов.
_TEXT_PROBE = 1 << 20


@dataclass(frozen=True)
class StoredFile:
    sha256: str
    size: int
    ext: str
    mime: str
    path: Path


def extension(name: str) -> str:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ALIASES.get(ext, ext)


def clean_name(name: str) -> str:
    """Имя для показа и заголовка Content-Disposition: без пути и управляющих символов."""
    base = re.split(r"[\\/]", name or "")[-1]
    base = "".join(ch for ch in base if unicodedata.category(ch)[0] != "C").strip(" .")
    if len(base) > 200:
        stem, dot, ext = base.rpartition(".")
        base = f"{stem[: 200 - len(ext) - 1]}.{ext}" if dot and len(ext) <= 8 else base[:200]
    return base or "file"


def _zip_names(path: Path) -> list[str]:
    try:
        with zipfile.ZipFile(path) as z:
            return z.namelist()
    except (zipfile.BadZipFile, OSError, ValueError) as e:
        raise EvidenceFileError("Файл повреждён: архив не читается") from e


def _check_ooxml(path: Path, part: str, title: str) -> None:
    names = _zip_names(path)
    if "[Content_Types].xml" not in names or part not in names:
        raise EvidenceFileError(f"Содержимое файла не похоже на документ {title}")
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        raise EvidenceFileError("Документы с макросами не принимаются", "file_macros")


def _check_odt(path: Path, head: bytes) -> None:
    # Первая запись ODF-архива — несжатый файл mimetype с типом документа.
    if _ODT_MIME not in head[:100]:
        raise EvidenceFileError("Содержимое файла не похоже на документ ODT")
    names = _zip_names(path)
    if any(n.startswith(("Basic/", "Scripts/")) for n in names):
        raise EvidenceFileError("Документы с макросами не принимаются", "file_macros")


def _decode_text(data: bytes) -> str:
    if b"\x00" in data:
        raise EvidenceFileError("Файл не текстовый: в нём есть двоичные данные")
    if data.startswith(codecs.BOM_UTF8):
        data = data[3:]
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        # Обрыв многобайтового символа на границе пробы — не ошибка.
        if e.start >= len(data) - 3 and len(data) >= _TEXT_PROBE:
            return data[: e.start].decode("utf-8")
    try:
        return data.decode("cp1251")
    except UnicodeDecodeError as e:
        raise EvidenceFileError("Текст должен быть в кодировке UTF-8 или Windows-1251") from e


def detect(path: Path, ext: str) -> str:
    """Проверяет, что содержимое соответствует расширению; возвращает MIME для отдачи."""
    if ext not in ALLOWED:
        raise EvidenceFileError(
            f"Тип файла «.{ext or '?'}» не принимается. Разрешены: {ALLOWED_TEXT}", "file_type"
        )
    with path.open("rb") as f:
        head = f.read(_TEXT_PROBE)
    if not head:
        raise EvidenceFileError("Файл пустой")
    if ext == "pdf":
        if not head.lstrip(b"\r\n\t ")[:5] == b"%PDF-":
            raise EvidenceFileError("Содержимое файла не похоже на PDF")
    elif ext == "png":
        if not head.startswith(b"\x89PNG\r\n\x1a\n"):
            raise EvidenceFileError("Содержимое файла не похоже на PNG")
    elif ext == "jpg":
        if not head.startswith(b"\xff\xd8\xff"):
            raise EvidenceFileError("Содержимое файла не похоже на JPEG")
    elif ext in ("docx", "xlsx", "odt", "zip"):
        if not head.startswith(_ZIP_SIG):
            raise EvidenceFileError(f"Содержимое файла не похоже на {ext.upper()}")
        if ext == "docx":
            _check_ooxml(path, "word/document.xml", "Word (DOCX)")
        elif ext == "xlsx":
            _check_ooxml(path, "xl/workbook.xml", "Excel (XLSX)")
        elif ext == "odt":
            _check_odt(path, head)
        else:
            _zip_names(path)
    else:
        text = _decode_text(head)
        if ext == "json":
            if path.stat().st_size > len(head):
                raise EvidenceFileError("JSON больше 1 МБ — приложите его в архиве ZIP")
            try:
                json.loads(text)
            except ValueError as e:
                raise EvidenceFileError("Файл не является корректным JSON") from e
        elif ext == "xml" and not text.lstrip("﻿ \r\n\t").startswith("<"):
            raise EvidenceFileError("Содержимое файла не похоже на XML")
    return ALLOWED[ext]


def store(chunks: Iterable[bytes], name: str, directory: Path, max_bytes: int) -> StoredFile:
    """Пишет поток во временный файл тома, проверяет размер и тип, кладёт под sha256."""
    ext = extension(name)
    if ext not in ALLOWED:
        raise EvidenceFileError(
            f"Тип файла «.{ext or '?'}» не принимается. Разрешены: {ALLOWED_TEXT}", "file_type"
        )
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    fd, tmp_name = tempfile.mkstemp(prefix=".upload-", dir=directory)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out:
            for chunk in chunks:
                size += len(chunk)
                if size > max_bytes:
                    raise EvidenceFileError(
                        f"Файл больше {max_bytes // (1024 * 1024)} МБ", "file_too_large"
                    )
                digest.update(chunk)
                out.write(chunk)
        mime = detect(tmp, ext)
        sha = digest.hexdigest()
        target = directory / sha
        if target.exists():
            tmp.unlink()
        else:
            os.chmod(tmp, 0o640)
            os.replace(tmp, target)
        return StoredFile(sha, size, ext, mime, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
