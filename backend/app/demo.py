"""Демо-данные «Аттестации» (задача 1.11, `make demo`).

Создаёт проект с объектом «ГИС, класс К2» из 10 хостов и проводит его по всему
пути MVP через собственный API — с теми же проверками прав, разделением
обязанностей и журналом аудита, что и в интерфейсе:

1. заказчик, проект (engagement №1 «Сканера»), участники;
2. объект ГИС: 10 хостов из активов «Сканера», классификация К2 (методист
   считает, утверждающий утверждает);
3. базовый набор мер по К2 и адаптация: исключения с обоснованием, одна
   компенсированная мера; утверждение адаптации;
4. импорт прогонов «Сканера» №6 и №7 — два снимка, старый сохраняется;
   прогон №8 (хост 10.10.3.103 недоступен) остаётся для импорта вручную;
5. одна организационная мера оценена вручную (интервью) и подтверждена,
   остальные организационные ждут ручной оценки;
6. второй объект — ИСПДн «Бухгалтерия» из 2 хостов, ещё не классифицирован.

«Сканер» всегда берётся из фикстур (`GET /runs/{id}/compliance` и `/coverage`
прогонов №6–8), даже если GRC_SCANNER_MODE=live: демо не ходит в сеть.

Запуск: `python -m app.demo` (в Docker — `make demo`). Повторный запуск ничего
не меняет, если демо-проект уже есть. Пароль демо-пользователей — из
GRC_DEMO_PASSWORD, иначе случайный; он печатается в конце.
"""

from __future__ import annotations

import os
import secrets
import sys
import warnings
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password, password_problem
from app.db.models import Project, RefProfile, User
from app.db.session import get_engine
from app.integrations.scanner.client import FixtureScannerClient, get_scanner_client

DEMO_PROJECT = "Аттестация ГИС «Учёт» (демо)"
DEMO_CUSTOMER = "ГБУ «Центр учёта» (демо)"
DEMO_OBJECT = "ГИС «Учёт»"

# username → (отображаемое имя, роли)
DEMO_USERS: dict[str, tuple[str, tuple[str, ...]]] = {
    "demo-meth": ("Иванова А. А. (методист)", ("methodologist",)),
    "demo-exp": ("Козлов К. К. (эксперт)", ("assessor",)),
    "demo-boss": ("Смирнов С. С. (утверждающий)", ("viewer", "approve")),
    "demo-viewer": ("Орлова О. О. (наблюдатель)", ("viewer",)),
}

GIS_HOSTS = [
    "10.10.1.10",
    "10.10.1.11",
    "10.10.1.12",
    "10.10.1.20",
    "10.10.2.5",
    "10.10.2.6",
    "10.10.3.101",
    "10.10.3.102",
    "10.10.3.103",
    "10.10.3.104",
]
PDN_HOSTS = ["10.20.0.15", "10.20.0.16"]

# Исходные данные классификации ГИС по №117, дающие К2.
GIS_K2 = {
    "damage_confidentiality": "medium",
    "damage_integrity": "low",
    "damage_availability": "low",
    "scale": "regional",
}

EXCLUSIONS = {
    "В ГИС не используются контейнерные среды (описание объекта, раздел 3)": [
        f"ЗКО.{i}" for i in range(1, 9)
    ],
    "Беспроводной доступ к ГИС не предусмотрен: точки доступа отсутствуют (акт обследования)": [
        "БД",
        *(f"ЗБД.{i}" for i in range(1, 7)),
    ],
}
COMPENSATED = (
    "УПД.7",
    ["УПД.8"],
    "Число параллельных сеансов ограничить штатно нельзя (прикладное ПО); риск снижается "
    "блокированием сеанса при неактивности",
)


class DemoError(RuntimeError):
    pass


@dataclass
class Result:
    created: bool
    password: str | None = None
    project_id: str | None = None
    object_id: str | None = None
    notes: list[str] = field(default_factory=list)


def _check(r: Any, expected: int = 200) -> Any:
    if r.status_code != expected:
        raise DemoError(f"{r.request.method} {r.request.url.path}: {r.status_code} {r.text}")
    return r.json() if r.content else None


def _ensure_users(session: Session, password: str) -> None:
    for username, (name, roles) in DEMO_USERS.items():
        u = session.scalars(select(User).where(User.username == username)).first()
        if u is None:
            u = User(username=username, display_name=name)
            session.add(u)
        u.display_name = name
        u.password_hash = hash_password(password)
        u.is_active = True
        u.set_roles(set(roles))
    session.commit()


def run(app: FastAPI, session: Session, password: str | None = None) -> Result:
    """Создать демо-данные. Ничего не делает, если демо-проект уже есть."""
    existing = session.scalars(select(Project).where(Project.name == DEMO_PROJECT)).first()
    if existing is not None:
        return Result(created=False, project_id=str(existing.id))
    if session.get(RefProfile, "fstec-117") is None:
        raise DemoError("справочник fstec-117 не загружен: выполните python -m app.refs.loader")

    password = password or os.environ.get("GRC_DEMO_PASSWORD") or secrets.token_urlsafe(12)
    problem = password_problem(password)
    if problem:
        raise DemoError(f"GRC_DEMO_PASSWORD: {problem}")
    _ensure_users(session, password)

    with warnings.catch_warnings():
        # TestClient — штатный способ вызвать свой API в процессе; предупреждения
        # о версиях starlette/httpx к демо отношения не имеют.
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

    app.dependency_overrides[get_scanner_client] = FixtureScannerClient
    try:
        return _populate(TestClient(app), password)
    finally:
        app.dependency_overrides.pop(get_scanner_client, None)


def _populate(c: Any, password: str) -> Result:
    h: dict[str, dict[str, str]] = {}
    for username in DEMO_USERS:
        tok = _check(c.post("/auth/token", json={"username": username, "password": password}))
        h[username] = {"Authorization": f"Bearer {tok['access_token']}"}
    meth, exp, boss = h["demo-meth"], h["demo-exp"], h["demo-boss"]

    # 1. Заказчик, проект, участники.
    customer = _check(c.post("/customers", headers=meth, json={"name": DEMO_CUSTOMER}), 201)
    project = _check(
        c.post(
            "/projects",
            headers=meth,
            json={
                "customer_id": customer["id"],
                "name": DEMO_PROJECT,
                "contract_ref": "Договор № 17-ДЕМО от 01.10.2026",
                "scanner_engagement_id": 1,
            },
        ),
        201,
    )
    pid = project["id"]
    names = {n for n, _ in DEMO_USERS.values()}
    members = [
        u["id"]
        for u in _check(c.get("/directory/users", headers=meth))
        if u["display_name"] in names
    ]
    _check(c.put(f"/projects/{pid}/members", headers=meth, json={"user_ids": members}))

    # 2. Объект ГИС: состав из «Сканера», классификация К2.
    gis = _check(
        c.post(
            f"/projects/{pid}/objects",
            headers=meth,
            json={
                "kind": "gis",
                "name": DEMO_OBJECT,
                "regime": "117",
                "purpose": "Учёт обращений граждан и выдача справок",
                "boundaries": "Серверный сегмент, ДМЗ и АРМ пользователей в здании заказчика",
                "internet": True,
            },
        ),
        201,
    )
    oid = gis["id"]
    _check(
        c.post(
            f"/objects/{oid}/hosts/sync-from-scanner", headers=meth, json={"addresses": GIS_HOSTS}
        )
    )
    cls = _check(
        c.post(f"/objects/{oid}/classifications", headers=meth, json={"inputs": GIS_K2}), 201
    )
    if cls["result"] != "К2":
        raise DemoError(f"классификация дала {cls['result']}, ожидался К2")
    _check(
        c.post(
            f"/classifications/{cls['id']}/approve",
            headers=boss,
            json={
                "acknowledge_unverified": True,
                "comment": "Таблица №117 не сверена методистом — утверждено для демонстрации",
            },
        )
    )

    # 3. Набор мер по К2 и адаптация.
    _check(c.post(f"/objects/{oid}/measures/rebuild", headers=meth, json={"dry_run": False}))
    ms = {m["measure_id"]: m for m in _check(c.get(f"/objects/{oid}/measures", headers=meth))}
    for reason, measure_ids in EXCLUSIONS.items():
        for mid in measure_ids:
            if mid not in ms:
                continue
            _check(
                c.patch(
                    f"/object-measures/{ms[mid]['id']}",
                    headers=meth,
                    json={"adaptation": "excluded", "adaptation_reason": reason},
                )
            )
    target, comp, reason = COMPENSATED
    if target in ms and all(x in ms for x in comp):
        _check(
            c.patch(
                f"/object-measures/{ms[target]['id']}",
                headers=meth,
                json={
                    "adaptation": "compensated",
                    "compensating_ids": comp,
                    "adaptation_reason": reason,
                },
            )
        )
    _check(
        c.post(
            f"/objects/{oid}/adaptation/approve",
            headers=boss,
            json={"acknowledge_unverified": True, "comment": "Обоснования проверены"},
        )
    )

    # 4. Два прогона «Сканера» — два снимка.
    _check(c.post(f"/objects/{oid}/scanner/import", headers=exp, json={"run_id": 6}), 201)
    _check(c.post(f"/objects/{oid}/scanner/import", headers=exp, json={"run_id": 7}), 201)

    # 5. Одна организационная мера — интервью, оценка, подтверждение.
    vu = ms.get("ВУ")
    if vu is not None:
        _check(
            c.post(
                f"/object-measures/{vu['id']}/evidence",
                headers=exp,
                json={
                    "kind": "interview",
                    "summary": "Угрозы выявляются по модели угроз, пересмотр — раз в год",
                    "held_on": "2026-11-02",
                    "participants": "Петров П. П., администратор безопасности",
                    "details": "В: Когда пересматривалась модель угроз? О: В сентябре 2026.",
                },
            ),
            201,
        )
        _check(c.patch(f"/object-measures/{vu['id']}", headers=exp, json={"status": "implemented"}))
        _check(
            c.post(
                f"/object-measures/{vu['id']}/confirm",
                headers=exp,
                json={"status": "implemented", "comment": "Подтверждено интервью"},
            )
        )

    # 6. Второй объект — ещё без классификации.
    pdn = _check(
        c.post(
            f"/projects/{pid}/objects",
            headers=meth,
            json={"kind": "ispdn", "name": "ИСПДн «Бухгалтерия»", "regime": "21"},
        ),
        201,
    )
    _check(
        c.post(
            f"/objects/{pdn['id']}/hosts/sync-from-scanner",
            headers=meth,
            json={"addresses": PDN_HOSTS},
        )
    )

    return Result(created=True, password=password, project_id=pid, object_id=oid)


def main() -> int:
    from app.main import create_app

    app = create_app()
    with Session(get_engine()) as session:
        try:
            r = run(app, session)
        except DemoError as e:
            print(f"демо-данные: ошибка — {e}", file=sys.stderr)
            return 1
    if not r.created:
        print(f"демо-данные: проект «{DEMO_PROJECT}» уже есть — ничего не изменено")
        return 0
    print(f"демо-данные: создан проект «{DEMO_PROJECT}» и объект «{DEMO_OBJECT}» (К2, 10 хостов)")
    print("вход (пароль у всех один):")
    for username, (name, _) in DEMO_USERS.items():
        print(f"  {username:<12} {name}")
    print(f"  пароль: {r.password}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
