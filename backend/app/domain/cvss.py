"""Базовая оценка CVSS 3.x по вектору (спецификация FIRST CVSS v3.1, раздел 7).

Нужна, когда в выгрузке БДУ есть вектор, но нет числовой оценки. Формулы базовой
оценки 3.0 и 3.1 совпадают, кроме округления; здесь — округление 3.1 (Roundup из
приложения A спецификации), как в калькуляторе БДУ bdu.fstec.ru/calc31.
"""

from __future__ import annotations

import math
import re

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_BASE = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_PREFIX = re.compile(r"^\(?\s*CVSS:(3\.[01])/", re.IGNORECASE)


class CvssError(ValueError):
    pass


def roundup(x: float) -> float:
    """Наименьшее число с одним знаком после запятой, не меньшее x (без ошибок float)."""
    i = round(x * 100_000)
    if i % 10_000 == 0:
        return i / 100_000
    return (math.floor(i / 10_000) + 1) / 10


def parse_vector(vector: str) -> tuple[str | None, dict[str, str]]:
    """«CVSS:3.1/AV:N/…» или «AV:N/…» → (версия из префикса или None, метрики)."""
    s = vector.strip().strip("()").strip()
    version = None
    if m := _PREFIX.match(s):
        version = m.group(1)
        s = s[m.end() :]
    metrics: dict[str, str] = {}
    for part in s.split("/"):
        if not part:
            continue
        key, sep, val = part.partition(":")
        if not sep:
            raise CvssError(f"Неверная метрика «{part}»")
        metrics[key.strip().upper()] = val.strip().upper()
    missing = [k for k in _BASE if k not in metrics]
    if missing:
        raise CvssError(f"Нет базовых метрик: {', '.join(missing)}")
    return version, metrics


def base_score(vector: str) -> float:
    _, m = parse_vector(vector)
    try:
        changed = {"U": False, "C": True}[m["S"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        pr = (_PR_C if changed else _PR_U)[m["PR"]]
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except KeyError as e:
        raise CvssError(f"Неверное значение метрики {e.args[0]}") from e
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + expl), 10))
    return roundup(min(impact + expl, 10))


def normalize_vector(vector: str, version: str) -> str:
    """Вектор с префиксом версии и метриками в порядке спецификации."""
    _, m = parse_vector(vector)
    return f"CVSS:{version}/" + "/".join(f"{k}:{m[k]}" for k in _BASE)
