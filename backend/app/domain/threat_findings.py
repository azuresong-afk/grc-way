"""Находки «Сканера» с идентификаторами БДУ как подтверждение актуальности угроз (задача 2.4).

Находка, которую «Сканер» нашёл на хосте объекта и связал с уязвимостью БДУ,
показывает, что способ реализации угрозы на объекте есть. Методист привязывает
такие находки к угрозам модели; связь хранится по ``dedup_key`` — ключ «Сканера»
sha256(host|port|vuln_id|module), стабильный между прогонами. Поэтому по каждому
новому снимку видно, осталась ли привязанная находка или исчезла (устранена либо
хост не проверялся).

Связи «уязвимость БДУ → угроза БДУ» в выгрузках БДУ нет, поэтому привязку делает
методист. Подсказка берётся из самой модели: угрозы, у которых среди объектов
воздействия есть объект с хостом находки. Это не правило Методики.

Что проверяется (шаг «Угрозы БДУ»):

- угроза признана неактуальной, а к ней привязаны находки из текущего снимка —
  проблема, мешает утверждению (подтверждение противоречит решению);
- находки текущего снимка, не привязанные ни к одной угрозе, — предупреждение;
- привязанные находки, которых нет в текущем снимке, — предупреждение;
- текущий снимок сделан до импорта находок — предупреждение.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

# Поля находки «Сканера», которые сохраняются в снимке и в привязке.
FINDING_FIELDS = (
    "dedup_key",
    "module",
    "host",
    "port",
    "finding_type",
    "title",
    "severity",
    "vuln_id",
    "cve_ids",
    "bdu_ids",
    "cvss",
    "status",
    "detected_at",
    "software",
    "software_version",
)
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def canonical_host(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw.strip()))
    except ValueError:
        return raw.strip().lower()


def object_findings(findings: list[dict[str, Any]], hosts: list[str]) -> list[dict[str, Any]]:
    """Находки с БДУ на хостах объекта: поля из FINDING_FIELDS, без повторов dedup_key.

    Порядок: сначала опасные, затем по хосту и порту — чтобы снимок и его хэш не
    зависели от порядка ответа «Сканера».
    """
    allowed = {canonical_host(h) for h in hosts}
    seen: dict[str, dict[str, Any]] = {}
    for f in findings:
        if not f.get("bdu_ids"):
            continue
        host = canonical_host(str(f.get("host") or ""))
        if host not in allowed or f["dedup_key"] in seen:
            continue
        row = {k: f.get(k) for k in FINDING_FIELDS}
        row["host"] = host
        row["cve_ids"] = sorted(set(row.get("cve_ids") or []))
        row["bdu_ids"] = sorted(set(row.get("bdu_ids") or []))
        seen[f["dedup_key"]] = row
    return sorted(
        seen.values(),
        key=lambda r: (
            SEVERITY_ORDER.get(str(r.get("severity")), 9),
            r["host"],
            r.get("port") or 0,
            r["dedup_key"],
        ),
    )


@dataclass
class FindingsView:
    """Находки текущего снимка объекта: от них считается, подтверждена ли угроза."""

    snapshot_id: str | None
    snapshot_number: int | None
    # Снимок есть и находки в нём импортированы (снимки до 2.4 — без находок).
    imported: bool
    by_key: dict[str, dict[str, Any]]

    @classmethod
    def empty(cls) -> FindingsView:
        return cls(None, None, False, {})

    @classmethod
    def of(cls, snapshot_id: str, number: int, findings: list | None) -> FindingsView:
        rows = list(findings or [])
        return cls(snapshot_id, number, findings is not None, {f["dedup_key"]: f for f in rows})

    def state(self, dedup_key: str) -> str:
        """present — находка есть в текущем снимке; absent — нет; unknown — не с чем сравнить."""
        if not self.imported:
            return "unknown"
        return "present" if dedup_key in self.by_key else "absent"


def link_entry(
    finding: dict[str, Any], *, snapshot_number: int, at: str, by: str | None
) -> dict[str, Any]:
    """Запись привязки: ключ и описание находки на момент привязки."""
    return {
        "dedup_key": finding["dedup_key"],
        "host": finding.get("host"),
        "port": finding.get("port"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "vuln_id": finding.get("vuln_id"),
        "bdu_ids": list(finding.get("bdu_ids") or []),
        "cve_ids": list(finding.get("cve_ids") or []),
        "cvss": finding.get("cvss"),
        "snapshot_number": snapshot_number,
        "linked_at": at,
        "linked_by_name": by,
    }


def present_links(links: list[dict[str, Any]], view: FindingsView) -> list[dict[str, Any]]:
    return [x for x in links if view.state(x["dedup_key"]) == "present"]


def suggested_threats(
    finding: dict[str, Any],
    threats: list[dict[str, Any]],
    host_objects: dict[str, list[str]],
) -> list[str]:
    """Угрозы модели, у которых среди объектов воздействия есть объект с хостом находки.

    ``threats`` — {code, relevant, objects}; неактуальные не предлагаются.
    """
    objs = set(host_objects.get(finding.get("host") or "", []))
    if not objs:
        return []
    return [
        t["code"]
        for t in threats
        if t.get("relevant") is not False and objs & set(t.get("objects") or [])
    ]


def host_objects(steps: dict[str, Any]) -> dict[str, list[str]]:
    """Хост → ключи объектов воздействия шага 2, в которые он входит."""
    out: dict[str, list[str]] = {}
    for o in (steps.get("objects") or {}).get("items") or []:
        for h in o.get("hosts") or []:
            out.setdefault(canonical_host(h), []).append(o["key"])
    return out


def check(threats: list[dict[str, Any]], view: FindingsView) -> tuple[list[str], list[str]]:
    """Проблемы (мешают утверждению) и предупреждения по привязкам находок.

    ``threats`` — {code, relevant, linked_findings}.
    """
    problems: list[str] = []
    warnings: list[str] = []
    if view.snapshot_number is None:
        return problems, warnings
    n = view.snapshot_number
    if not view.imported:
        warnings.append(
            f"Снимок «Сканера» №{n} сделан до импорта находок: импортируйте прогон заново, "
            "чтобы проверить подтверждение угроз"
        )
        return problems, warnings
    linked: set[str] = set()
    for t in threats:
        links = list(t.get("linked_findings") or [])
        linked.update(x["dedup_key"] for x in links)
        present = present_links(links, view)
        if t.get("relevant") is False and present:
            problems.append(
                f"{t['code']}: признана неактуальной, но подтверждена находками «Сканера» "
                f"({len(present)} в снимке №{n}) — пересмотрите решение или отвяжите находки"
            )
        gone = len(links) - len(present)
        if gone:
            warnings.append(
                f"{t['code']}: привязанных находок нет в снимке №{n} ({gone}) — "
                "устранены или хост не проверялся"
            )
    unlinked = [k for k in view.by_key if k not in linked]
    if unlinked:
        warnings.append(
            f"Находки «Сканера» с БДУ из снимка №{n} не привязаны к угрозам: {len(unlinked)}"
        )
    return problems, warnings
