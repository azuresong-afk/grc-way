"""Сборка фикстур прогонов «Сканера» для демо и тестов (задача 1.9).

Фикстуры повторяют ответы «Сканера»:

- `engagement_runs.json` — `GET /engagements/{id}/runs` (RunOut);
- `run_<id>_coverage.json` — `GET /runs/{id}/coverage` (CoverageOut);
- `run_<id>_compliance_<profile>.json` — `GET /runs/{id}/compliance` (сводка
  `scanner.compliance.engine.summarize`) **по всем мерам профиля**: у каждой
  меры дополнительно `levels`, по которым FixtureScannerClient отбирает меры
  уровня, как это делает «Сканер».

Статусы проверок задаются здесь явно (кто где провален), а не случайно: демо
должно показывать все случаи — реализовано, частично, не реализовано, не
проверено (нет модуля, хост недоступен, нет учётной записи), провал на хосте
вне объекта. Запуск: `python tools/make_run_fixtures.py` из каталога backend.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "reference" / "profiles"
OUT = ROOT / "backend" / "app" / "integrations" / "scanner" / "fixtures"

ASSETS = json.loads((OUT / "engagement_assets.json").read_text(encoding="utf-8"))
OS = {a["address"]: a.get("os_family") for a in ASSETS}

MODULES = ["discovery", "vuln", "auth_inventory", "win_inventory", "config_audit"]
LINUX_GIS = [
    "10.10.1.10",
    "10.10.1.11",
    "10.10.1.12",
    "10.10.2.5",
    "10.10.2.6",
    "10.10.3.103",
    "10.10.3.104",
]

RUNS = [
    {
        "id": 6,
        "name": "Первичное обнаружение",
        "status": "failed",
        "started_at": "2026-10-20T08:00:00Z",
        "finished_at": "2026-10-20T08:04:12Z",
        "error_message": "Ни один хост не ответил: проверьте маршрут до сети 10.10.0.0/16",
        "modules": ["discovery"],
    },
    {
        "id": 7,
        "name": "Плановый прогон ГИС «Учёт»",
        "status": "done",
        "started_at": "2026-10-28T09:00:00Z",
        "finished_at": "2026-10-28T11:42:30Z",
        "modules": MODULES,
    },
    {
        "id": 8,
        "name": "Повторный прогон после исправлений",
        "status": "partial",
        "started_at": "2026-11-02T13:10:00Z",
        "finished_at": "2026-11-02T14:30:05Z",
        "modules": MODULES,
        "warnings": [
            {"code": "coverage_gaps", "message": "Есть хосты и модули, которые не проверены"}
        ],
    },
    {
        "id": 9,
        "name": "Ночной прогон",
        "status": "running",
        "started_at": "2026-11-04T19:00:00Z",
        "finished_at": None,
        "modules": MODULES,
    },
]

# Кто где провален: run -> check -> адреса.
FAILS: dict[int, dict[str, list[str]]] = {
    7: {
        "password_length": ["10.10.3.103", "10.10.3.104"],
        "password_complexity": ["10.10.3.103"],
        "ssh_root_login": ["10.10.2.5"],
        "session_timeout": LINUX_GIS,
        "no_critical_vulns": ["10.10.2.5", "10.10.1.10"],
        "security_updates": ["10.10.2.5", "10.10.2.6", "10.10.3.101"],
        "smb1_disabled": ["10.10.3.101", "10.10.3.102"],
        "antimalware": ["10.10.3.103"],
        "audit_storage": ["10.10.1.10"],
        # Хост «Бухгалтерии» — вне объекта «ГИС»: его провал объект не задевает.
        "rdp_nla": ["10.20.0.15"],
    },
    8: {
        "password_length": ["10.10.3.104"],
        "session_timeout": LINUX_GIS,
        "no_critical_vulns": ["10.10.1.10"],
        "smb1_disabled": ["10.10.3.102"],
        "rdp_nla": ["10.20.0.15"],
    },
}

# Покрытие: run -> host -> module -> (status, reason).
GAPS: dict[int, dict[str, dict[str, tuple[str, str | None]]]] = {
    6: {
        a["address"]: {"discovery": ("unreachable", "Хост не ответил на обнаружение")}
        for a in ASSETS
    },
    7: {"10.20.0.16": {m: ("unreachable", "Хост не ответил на обнаружение") for m in MODULES}},
    8: {
        "10.20.0.16": {m: ("unreachable", "Хост не ответил на обнаружение") for m in MODULES},
        "10.10.3.103": {m: ("unreachable", "Хост не ответил на обнаружение") for m in MODULES},
        "10.10.1.20": {
            "win_inventory": ("no_credentials", "Нет учётной записи WinRM для хоста"),
        },
    },
}

LABELS = {
    "completed": "выполнено",
    "not_applicable": "неприменимо",
    "skipped": "пропущено",
    "unreachable": "хост недоступен",
    "no_credentials": "нет учётной записи",
    "timeout": "таймаут",
    "error": "ошибка",
}


def _ip(h: str):
    return int(ipaddress.ip_address(h))


def check_modules(check: dict) -> set[str]:
    out: set[str] = set()
    if any(check.get(k) for k in ("openscap", "lynis", "password_policy")):
        out.add("config_audit")
    if check.get("windows"):
        out.add("win_inventory")
    if check.get("vulns"):
        out.update(check["vulns"].get("modules") or ())
    if check.get("services"):
        out.add("discovery")
    if check.get("cred_audit"):
        out.add("cred_audit")
    return out


def coverage(run_id: int) -> dict:
    gaps = GAPS.get(run_id, {})
    modules = next(r["modules"] for r in RUNS if r["id"] == run_id)
    entries, hosts = [], []
    for a in sorted(ASSETS, key=lambda x: _ip(x["address"])):
        h, os_family = a["address"], a.get("os_family")
        per = {}
        for m in modules:
            status, reason = "completed", None
            if m == "win_inventory" and os_family != "windows":
                status = "not_applicable"
            if m in ("auth_inventory", "config_audit") and os_family == "windows":
                status = "not_applicable"
            if m in gaps.get(h, {}):
                status, reason = gaps[h][m]
            per[m] = {"status": status, "label": LABELS[status], "reason": reason}
            entries.append({"host": h, "module": m, **per[m]})
        statuses = {v["status"] for v in per.values()} - {"not_applicable"}
        host_status = (
            "unreachable"
            if statuses == {"unreachable"}
            else "checked"
            if statuses == {"completed"}
            else "partial"
        )
        hosts.append({"host": h, "status": host_status, "modules": per})
    counts = dict.fromkeys(LABELS, 0)
    for e in entries:
        counts[e["status"]] += 1
    gap_n = sum(1 for e in entries if e["status"] not in ("completed", "not_applicable"))
    return {
        "scan_run_id": run_id,
        "status": next(r["status"] for r in RUNS if r["id"] == run_id),
        "summary": {
            "hosts": len(hosts),
            "hosts_checked": sum(1 for x in hosts if x["status"] == "checked"),
            "hosts_partial": sum(1 for x in hosts if x["status"] == "partial"),
            "hosts_unreachable": sum(1 for x in hosts if x["status"] == "unreachable"),
            "hosts_not_checked": 0,
            "counts": counts,
            "gaps": gap_n,
            "auth_gaps": sum(
                1
                for e in entries
                if e["status"] not in ("completed", "not_applicable")
                and e["module"] in ("auth_inventory", "win_inventory", "config_audit")
            ),
        },
        "hosts": hosts,
        "entries": entries,
        "legacy": False,
    }


def failure_items(check: dict, host: str) -> list[dict]:
    if check.get("vulns"):
        return [
            {
                "kind": "finding",
                "key": f"demo-{check['id']}-{host}",
                "vuln_id": "CVE-2024-6387",
                "title": "OpenSSH: удалённое выполнение кода (regreSSHion)",
                "severity": "high",
            }
        ]
    if check.get("windows"):
        key = check["windows"][0]["key"] if isinstance(check["windows"], list) else check["id"]
        return [{"kind": "fact", "title": f"параметр {key} не соответствует требованию"}]
    if check.get("openscap"):
        return [{"kind": "fact", "title": f"правило {check['openscap'][0]} — fail"}]
    if check.get("lynis"):
        return [{"kind": "fact", "title": f"Lynis {check['lynis'][0]} — предупреждение"}]
    return [{"kind": "fact", "title": "нарушение"}]


def compliance(run_id: int, profile_id: str) -> dict:
    profile = yaml.safe_load((PROFILES / f"{profile_id}.yaml").read_text(encoding="utf-8"))
    catalog = {
        c["id"]: c
        for c in yaml.safe_load((PROFILES / "checks.yaml").read_text(encoding="utf-8"))["checks"]
    }
    cov = coverage(run_id)
    done = {(e["host"], e["module"]) for e in cov["entries"] if e["status"] == "completed"}
    fails = FAILS.get(run_id, {})
    hosts = [a["address"] for a in sorted(ASSETS, key=lambda x: _ip(x["address"]))]
    controls, manual = [], []
    for g in profile["groups"]:
        for c in g["controls"]:
            base = {
                "id": c["id"],
                "title": c["title"],
                "group": g["code"],
                "group_title": g["title"],
                "levels": c.get("levels") or [],
            }
            if not c.get("checks"):
                manual.append(base)
                continue
            per_host: dict[str, str] = {}
            failed_hosts = []
            for h in hosts:
                results = []
                for cid in c["checks"]:
                    ch = catalog[cid]
                    plat = ch.get("platform", "any")
                    if plat != "any" and plat != OS.get(h):
                        results.append({"id": cid, "status": "na"})
                        continue
                    if not any((h, m) in done for m in check_modules(ch)):
                        results.append({"id": cid, "status": "na"})
                        continue
                    if h in fails.get(cid, ()):
                        results.append(
                            {
                                "id": cid,
                                "status": "failed",
                                "failures": failure_items(ch, h),
                                "more": 0,
                            }
                        )
                    else:
                        results.append({"id": cid, "status": "passed"})
                st = {r["status"] for r in results}
                hs = "failed" if "failed" in st else "passed" if "passed" in st else "na"
                if hs != "na" or any((h, m) in done for m in MODULES):
                    per_host[h] = hs
                if hs == "failed":
                    failed_hosts.append(
                        {
                            "host": h,
                            "checks": [
                                {"id": r["id"], "failures": r["failures"], "more": 0}
                                for r in results
                                if r["status"] == "failed"
                            ],
                        }
                    )
            values = set(per_host.values())
            status = "failed" if "failed" in values else "passed" if "passed" in values else "na"
            counts = {
                k: sum(1 for v in per_host.values() if v == k)
                for k in ("passed", "failed", "manual", "na")
            }
            item = {**base, "status": status, "hosts": counts, "added": False}
            if status == "failed":
                item["failed_hosts"] = failed_hosts
                failed_checks = sorted({x["id"] for fh in failed_hosts for x in fh["checks"]})
                item["recommendations"] = [
                    {
                        "check": cid,
                        "title": catalog[cid]["title"],
                        "remediation": catalog[cid].get("remediation"),
                        "doc": catalog[cid].get("doc"),
                    }
                    for cid in failed_checks
                ]
            controls.append(item)
    return {
        "profile": {
            "id": profile["id"],
            "title": profile["title"],
            "short": profile["short"],
            "document": profile.get("document"),
            "url": profile.get("url"),
            "level_label": profile.get("level_label"),
            "levels": profile.get("levels") or [],
        },
        "level": profile.get("default_level"),
        "adapted": {"excluded": [], "added": []},
        # Сводные поля пересчитывает FixtureScannerClient по выбранному уровню.
        "percent": None,
        "counts": {},
        "hosts": [],
        "groups": [],
        "controls": controls,
        "failures": [],
        "manual": manual,
        "run_id": run_id,
        "has_results": next(r for r in RUNS if r["id"] == run_id)["status"] != "failed",
        "run_status": next(r["status"] for r in RUNS if r["id"] == run_id),
    }


def run_out(r: dict) -> dict:
    return {
        "id": r["id"],
        "engagement_id": 1,
        "modules": r["modules"],
        "rate_profile": "normal",
        "credential_ids": [],
        "cred_set_ids": [],
        "name": r["name"],
        "targets": ["10.10.0.0/16", "10.20.0.0/24"],
        "schedule_id": None,
        "status": r["status"],
        "started_by": 1,
        "started_at": r["started_at"],
        "finished_at": r["finished_at"],
        "created_at": r["started_at"],
        "error_message": r.get("error_message"),
        "retry_of": None,
        "options": {},
        "warnings": r.get("warnings", []),
        "progress": None,
    }


def dump(name: str, data: object) -> None:
    (OUT / name).write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def main() -> None:
    # Новые сверху — как отдаёт «Сканер» с order=desc.
    dump("engagement_runs.json", [run_out(r) for r in sorted(RUNS, key=lambda r: -r["id"])])
    for r in RUNS:
        if r["status"] in ("pending", "running"):
            continue
        dump(f"run_{r['id']}_coverage.json", coverage(r["id"]))
        dump(f"run_{r['id']}_compliance_fstec-117.json", compliance(r["id"], "fstec-117"))


if __name__ == "__main__":
    main()
