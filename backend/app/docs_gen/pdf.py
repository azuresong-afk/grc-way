"""DOCX → PDF через LibreOffice headless.

Каждое преобразование — во временном каталоге со своим профилем LibreOffice:
параллельные запросы не мешают друг другу, после работы ничего не остаётся.
Сеть LibreOffice не нужна. Если LibreOffice не установлен (тесты, стенд без
него), DOCX формируется, а PDF — нет, с понятной причиной.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path


class PdfError(RuntimeError):
    """PDF не получен; текст — для пользователя."""


def converter_path(setting: str) -> str | None:
    """Путь к soffice или None, если преобразование выключено или недоступно."""
    if not setting or setting == "none":
        return None
    return shutil.which(setting)


def convert(docx: bytes, *, soffice: str, timeout: float) -> bytes:
    with tempfile.TemporaryDirectory(prefix="grc-pdf-") as tmp:
        work = Path(tmp)
        src = work / "document.docx"
        src.write_bytes(docx)
        cmd = [
            soffice,
            f"-env:UserInstallation={(work / 'profile').as_uri()}",
            "--headless",
            "--norestore",
            "--nolockcheck",
            "--convert-to",
            "pdf:writer_pdf_Export",
            "--outdir",
            str(work),
            str(src),
        ]
        try:
            proc = subprocess.run(  # noqa: S603 — путь к soffice из настроек, аргументы свои
                cmd, capture_output=True, timeout=timeout, check=False, cwd=work
            )
        except subprocess.TimeoutExpired as e:
            raise PdfError(f"LibreOffice не уложился в {timeout:.0f} с") from e
        except OSError as e:
            raise PdfError(f"LibreOffice не запустился: {e}") from e
        out = work / "document.pdf"
        if proc.returncode != 0 or not out.is_file():
            tail = (proc.stderr or proc.stdout or b"").decode(errors="replace").strip()[-300:]
            raise PdfError(f"LibreOffice не преобразовал документ (код {proc.returncode}) {tail}")
        return out.read_bytes()
