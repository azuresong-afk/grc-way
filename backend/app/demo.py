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
6. второй объект — ИСПДн «Бухгалтерия» из 2 хостов, ещё не классифицирован;
7. образцы выгрузок БДУ (app/integrations/bdu/sample.py — не данные ФСТЭК):
   угрозы и уязвимости применены, вторая выгрузка уязвимостей ждёт применения —
   видно сравнение и отметку «требует пересчёта». Только если БДУ ещё не загружали;
8. модель угроз ГИС по Методике 2021 (если в БДУ есть угрозы образца): все шаги
   мастера заполнены методистом, перечень актуальных угроз с обоснованием,
   находки «Сканера» с БДУ привязаны к угрозе УБИ.006 как подтверждение
   актуальности — черновик ждёт утверждения. Импорт прогона №8 вручную покажет,
   что находка Log4j устранена;
9. реестр сертифицированных СЗИ — образец (app/integrations/szi/sample.py, не данные
   ФСТЭК): первая версия применена, вторая ждёт применения; на ГИС пять СЗИ с
   привязкой к мерам — действующие, истекающий, истёкший и с оконченной поддержкой;
10. реестр уязвимостей ГИС по Методике 2025: находки прогона №7 с БДУ, две из них
   оценены экспертом (у Log4Shell в БДУ нет CVSS 3.1 — версия выбрана вручную),
   одна внесена по результатам пентеста, у одной не выбраны последствия (H);
11. комплект документов ГИС (задачи 3.1–3.2) — версия 1 всех девяти документов:
   проекты с водяным знаком, в карте полей видно, чего не хватает (границы,
   ответственные, роли хостов, утверждение модели угроз).

«Сканер» всегда берётся из фикстур (`GET /runs/{id}/compliance`, `/coverage`
и `/findings` прогонов №6–8), даже если GRC_SCANNER_MODE=live: демо не ходит в сеть.

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
from app.db.models import BduImport, BduThreat, Project, RefProfile, SziImport, User, utcnow
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

# Инвентаризация для I_infr (задача 2.7): тип компонента (значения K таблицы 1
# Методики 2025) и доступность из сети «Интернет». У хостов «Бухгалтерии» не
# заполнено — расчёт покажет, чего не хватает.
GIS_INVENTORY: dict[str, tuple[list[str], bool]] = {
    "10.10.1.10": (["K1", "K5"], False),
    "10.10.1.11": (["K1", "K5"], False),
    "10.10.1.12": (["K5"], False),
    "10.10.1.20": (["K5"], False),
    "10.10.2.5": (["K1", "K5"], True),
    "10.10.2.6": (["K3"], True),
    "10.10.3.101": (["K6"], False),
    "10.10.3.102": (["K6"], False),
    "10.10.3.103": (["K6"], False),
    "10.10.3.104": (["K6"], False),
}

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


# Модель угроз ГИС: шаги мастера (коды — справочник reference/threats) и решения по
# угрозам образца БДУ.
THREAT_STEPS: dict[str, dict[str, Any]] = {
    "consequences": {
        "items": [
            {
                "code": "У1.9",
                "justification": "В ГИС обрабатываются ПДн заявителей",
            },
            {
                "code": "У1.8",
                "justification": "Подмена справок — ущерб гражданам",
            },
            {"code": "У3.4", "justification": "Простой ГИС срывает выдачу справок учреждением"},
            {"code": "У3.28", "justification": "Справки выдаются только через ГИС"},
        ]
    },
    "objects": {
        "items": [
            {
                "key": "portal",
                "name": "Веб-портал приёма обращений",
                "description": "Публикуется в сеть «Интернет» через ДМЗ",
                "hosts": ["10.10.2.5", "10.10.2.6"],
                "impacts": ["ВВ2", "ВВ3", "ВВ4"],
                "consequences": ["У3.4", "У3.28"],
            },
            {
                "key": "db",
                "name": "СУБД с обращениями и справками",
                "hosts": ["10.10.1.10", "10.10.1.11"],
                "impacts": ["ВВ1", "ВВ4"],
                "consequences": ["У1.9", "У1.8"],
            },
            {
                "key": "arm",
                "name": "АРМ операторов",
                "hosts": ["10.10.3.101", "10.10.3.102", "10.10.3.103", "10.10.3.104"],
                "impacts": ["ВВ1", "ВВ2", "ВВ6"],
                "consequences": ["У1.9", "У3.4"],
            },
        ]
    },
    "intruders": {
        "items": [
            {
                "code": "НВ4",
                "relevant": True,
                "capability": "Н1",
                "justification": "Портал доступен из сети «Интернет»",
            },
            {
                "code": "НВ3",
                "relevant": True,
                "capability": "Н2",
                "justification": "Персональные данные заявителей представляют интерес для продажи",
            },
            {
                "code": "НВ11",
                "relevant": True,
                "capability": "Н1",
                "justification": "Операторы работают с обращениями ежедневно",
            },
            {
                "code": "НВ1",
                "relevant": False,
                "justification": "ГИС регионального масштаба, сведений, составляющих "
                "государственную тайну, нет",
            },
            {
                "code": "НВ6",
                "relevant": False,
                "justification": "Прикладное ПО сопровождается по договору без удалённого доступа",
            },
        ]
    },
    "methods": {
        "items": [
            {
                "code": "СР1",
                "interfaces": "Веб-интерфейс портала (HTTPS, 443/tcp); клиент СУБД на АРМ",
                "objects": ["portal", "db"],
                "intruders": ["НВ4", "НВ3"],
            },
            {
                "code": "СР2",
                "interfaces": "Электронная почта и съёмные носители на АРМ",
                "objects": ["arm"],
                "intruders": ["НВ3", "НВ11"],
            },
            {
                "code": "СР9",
                "interfaces": "Консоли администрирования серверов",
                "objects": ["db", "portal"],
                "intruders": ["НВ11"],
            },
        ]
    },
    "scenarios": {
        "items": [
            {"tactic": "Т1", "note": "Сканирование портала из сети «Интернет»"},
            {"tactic": "Т2"},
            {"tactic": "Т3"},
            {"tactic": "Т10"},
        ]
    },
}
# УБИ → (актуальна, обоснование, нарушители, объекты, последствия, способы, тактики)
_Decision = tuple[bool, str, list[str], list[str], list[str], list[str], list[str]]
THREAT_DECISIONS: dict[str, _Decision] = {
    "УБИ.006": (
        True,
        "Портал принимает данные из сети «Интернет»; внедрение кода через формы обращений",
        ["НВ4", "НВ3"], ["portal", "db"], ["У1.9", "У3.4"], ["СР1"], ["Т1", "Т2", "Т10"],
    ),
    "УБИ.008": (
        True,
        "Вход на портал и в СУБД по паролю; подбор возможен из сети «Интернет»",
        ["НВ4", "НВ3"], ["portal", "db"], ["У1.9"], ["СР1"], ["Т2", "Т10"],
    ),
    "УБИ.067": (
        True,
        "Операторы видят обращения других отделов: разграничение по отделам не настроено",
        ["НВ11"], ["arm", "db"], ["У1.9"], ["СР9"], ["Т10"],
    ),
    "УБИ.140": (
        True,
        "Портал — единственный канал приёма обращений; отказ останавливает выдачу справок",
        ["НВ4"], ["portal"], ["У3.4", "У3.28"], ["СР1"], ["Т10"],
    ),
    "УБИ.170": (
        True,
        "Вредоносное ПО через почту на АРМ может зашифровать файловые ресурсы",
        ["НВ3", "НВ11"], ["arm"], ["У3.4"], ["СР2"], ["Т3", "Т10"],
    ),
    "УБИ.190": (
        False,
        "Доступ АРМ в сеть «Интернет» закрыт на межсетевом экране (только портал в ДМЗ)",
        [], [], [], [], [],
    ),
}  # fmt: skip
# УБИ → уязвимости БДУ, чьи находки «Сканера» привязываются к угрозе. Находка с
# BDU:2026-00042 (обход аутентификации на 10.10.1.10) оставлена без угрозы — видно
# предупреждение «не привязаны к угрозам».
THREAT_FINDINGS: dict[str, set[str]] = {
    "УБИ.006": {"BDU:2021-06061", "BDU:2024-04835"},
}


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
        result = _populate(TestClient(app), password)
    finally:
        app.dependency_overrides.pop(get_scanner_client, None)
    if _load_bdu_samples(session):
        result.notes.append(
            "БДУ: загружены образцы выгрузок, вторая выгрузка уязвимостей ждёт применения"
        )
    tok = _check(
        TestClient(app).post("/auth/token", json={"username": "demo-meth", "password": password})
    )
    meth = {"Authorization": f"Bearer {tok['access_token']}"}
    known = set(session.scalars(select(BduThreat.code).where(BduThreat.code.in_(THREAT_DECISIONS))))
    if known == set(THREAT_DECISIONS) and result.object_id:
        _threat_model(TestClient(app), meth, result)
        result.notes.append("модель угроз ГИС: черновик заполнен, ждёт утверждения")
    if result.object_id:
        tok = _check(
            TestClient(app).post("/auth/token", json={"username": "demo-exp", "password": password})
        )
        n = _vulns(TestClient(app), {"Authorization": f"Bearer {tok['access_token']}"}, result)
        result.notes.append(f"реестр уязвимостей ГИС: оценено {n}, по одной не хватает данных")
    if _load_szi_samples(session):
        result.notes.append("реестр СЗИ: загружен образец, вторая версия ждёт применения")
    if result.object_id:
        _szi(TestClient(app), meth, result.object_id)
        result.notes.append("СЗИ ГИС: пять средств, одно истекает, у одного срок истёк")
        # Комплект документов ГИС — версия 1 (проекты с водяным знаком «Проект»).
        url = f"/objects/{result.object_id}/documents"
        types = _check(TestClient(app).get(url, headers=meth))["types"]
        for t in types:
            _check(TestClient(app).post(url, headers=meth, json={"type": t["code"]}), 201)
        result.notes.append(f"комплект документов ГИС: {len(types)} документов, версия 1 (проект)")
    return result


# Реестр уязвимостей ГИС (задача 2.8): выбор специалиста по находкам прогона №7.
DEMO_VULN_CHOICES: dict[str, dict[str, Any]] = {
    "BDU:2024-04835": {"h": ["H1"], "comment": "Удалённое выполнение кода на SSH-сервере"},
    # В БДУ у Log4Shell только CVSS 2.0 и 3.0: версию выбирает специалист (п. 13).
    "BDU:2021-06061": {
        "cvss": {"version": "3.0", "score": 10.0, "source": "bdu", "note": "CVSS 3.1 в БДУ нет"},
        "h": ["H1", "H4"],
    },
}
DEMO_MANUAL_VULN = {
    "title": "Подбор пароля учётной записи администратора портала",
    "description": "При тестировании на проникновение пароль подобран по словарю за 12 минут.",
    "manual_source": "pentest",
    "manual_hosts": ["10.10.1.10"],
    "cvss": {
        "version": "3.1",
        "score": 9.8,
        "source": "manual",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },
    "e": ["E2"],
    "h": ["H2"],
}


def _vulns(c: Any, exp: dict[str, str], result: Result) -> int:
    """Оценки критичности по Методике 2025: две по находкам «Сканера», одна — по пентесту.

    Уязвимость BDU:2026-00042 оставлена без выбора последствий (H) — видно, чего не
    хватает для расчёта."""
    oid = result.object_id
    reg = _check(c.get(f"/objects/{oid}/vulns", headers=exp))
    by = {x["bdu_id"]: x for x in reg["items"]}
    n = 0
    for bid, body in DEMO_VULN_CHOICES.items():
        if bid in by:
            d = _check(c.patch(f"/object-vulns/{by[bid]['id']}", headers=exp, json=body))
            n += int(d["assessments"] > 0)
    d = _check(c.post(f"/objects/{oid}/vulns", headers=exp, json=DEMO_MANUAL_VULN), 201)
    return n + int(d["assessments"] > 0)


# Наименование, вид, номер сертификата (образец), меры, размещение.
DEMO_SZI = [
    ("Пример-МЭ 3", "fw", "9901", ["МСЭ.1", "МСЭ.2", "МСЭ.3"], "Периметр и граница ДМЗ, 2 шт."),
    ("Пример-АВЗ", "av", "9902", ["АВЗ.1", "АВЗ.2", "АВЗ.3"], "Все АРМ и серверы, 10 лицензий"),
    ("Пример-СОВ", "ids", "9904", ["СОВ.1", "СОВ.2"], "Сенсоры на периметре и в сегменте серверов"),
    ("Пример-НСД", "nsd", "9903", ["ИАФ.1", "УПД.1"], "АРМ операторов (10.10.3.101–104)"),
    ("Пример-ОС", "os", "9906", [], "Серверы приложений 10.10.1.10–12"),
]


def _szi(c: Any, meth: dict[str, str], object_id: str) -> None:
    codes = {m["measure_id"] for m in _check(c.get(f"/objects/{object_id}/measures", headers=meth))}
    for name, kind, number, measures, placement in DEMO_SZI:
        body = {
            "name": name,
            "kind": kind,
            "cert_number": number,
            "measure_ids": [m for m in measures if m in codes],
            "placement": placement,
        }
        _check(c.post(f"/objects/{object_id}/szi", headers=meth, json=body), 201)


def _load_szi_samples(session: Session) -> bool:
    """Образец реестра СЗИ: те же шаги, что в API (загрузка — право администратора)."""
    from app.core.config import get_settings
    from app.domain import szi
    from app.domain.evidence_files import store
    from app.integrations.szi.sample import registry_csv, registry_xlsx

    if session.scalar(select(SziImport.id).limit(1)) is not None:
        return False
    settings = get_settings()
    limit = settings.szi_max_mb * 1024 * 1024
    for name, data, ext, apply in (
        ("reestr-szi.xlsx", registry_xlsx(1), "xlsx", True),
        ("reestr-szi.csv", registry_csv(2), "csv", False),
    ):
        stored = store([data], name, settings.szi_dir, limit)
        parsed = szi.parse_file(stored.path, ext)
        diff = szi.compute_diff(session, parsed, file_sha256=stored.sha256)
        row = SziImport(
            file_name=name,
            file_sha256=stored.sha256,
            file_size=stored.size,
            file_ext=ext,
            export_version=parsed.version,
            version_source=parsed.version_source,
            status="pending",
            summary=diff["summary"],
            items=diff["items"],
            warnings=diff["warnings"],
            fingerprint=diff["fingerprint"],
            created_by_name="Демо-данные",
        )
        session.add(row)
        session.flush()
        if apply:
            res = szi.apply(session, parsed, row, version=parsed.version)
            row.status, row.applied_at = "applied", utcnow()
            row.applied_by_name, row.applied = "Демо-данные", res.as_dict()
    session.commit()
    return True


def _threat_model(c: Any, meth: dict[str, str], result: Result) -> None:
    m = _check(c.post(f"/objects/{result.object_id}/threat-models", headers=meth), 201)
    url = f"/threat-models/{m['id']}"
    for step, data in THREAT_STEPS.items():
        _check(c.put(f"{url}/steps/{step}", headers=meth, json={"data": data}))
    _check(c.post(f"{url}/threats", headers=meth, json={"codes": list(THREAT_DECISIONS)}))
    for code, (rel, why, intr, objs, cons, meths, tactics) in THREAT_DECISIONS.items():
        body = {
            "relevant": rel,
            "justification": why,
            "intruders": intr,
            "objects": objs,
            "consequences": cons,
            "methods": meths,
            "tactics": tactics,
        }
        _check(c.patch(f"{url}/threats/{code}", headers=meth, json=body))
    # Находки текущего снимка (прогон №7) с БДУ как подтверждение актуальности.
    found = _check(c.get(f"{url}/findings", headers=meth))["items"]
    for code, bdu_ids in THREAT_FINDINGS.items():
        keys = [f["dedup_key"] for f in found if set(f["bdu_ids"]) & bdu_ids]
        if keys:
            _check(
                c.post(f"{url}/threats/{code}/findings", headers=meth, json={"dedup_keys": keys})
            )


def _load_bdu_samples(session: Session) -> bool:
    """Образцы БДУ. Загрузка выгрузок — право администратора, а демо-администратора нет,
    поэтому здесь те же шаги, что в API, без него: файл в том, сравнение, применение."""
    from app.core.config import get_settings
    from app.domain import bdu_import
    from app.domain.bdu import parse_file
    from app.domain.evidence_files import store
    from app.integrations.bdu.sample import thrlist_xlsx, vullist_xlsx

    if session.scalar(select(BduImport.id).limit(1)) is not None:
        return False
    settings = get_settings()
    steps = [
        ("thrlist.xlsx", thrlist_xlsx(1), True),
        ("vullist.xlsx", vullist_xlsx(1), True),
        ("vullist.xlsx", vullist_xlsx(2), False),
    ]
    for name, data, apply in steps:
        stored = store([data], name, settings.bdu_dir, settings.bdu_max_mb * 1024 * 1024)
        parsed = parse_file(stored.path)
        diff = bdu_import.compute_diff(session, parsed, file_sha256=stored.sha256)
        row = BduImport(
            kind=parsed.kind,
            file_name=name,
            file_sha256=stored.sha256,
            file_size=stored.size,
            export_version=parsed.version,
            version_source=parsed.version_source,
            status="pending",
            summary=diff["summary"],
            items=diff["items"],
            warnings=diff["warnings"],
            fingerprint=diff["fingerprint"],
            created_by_name="Демо-данные",
        )
        session.add(row)
        session.flush()
        if apply:
            res = bdu_import.apply(session, parsed, row, version=parsed.version)
            row.status, row.applied_at = "applied", utcnow()
            row.applied_by_name, row.applied = "Демо-данные", res.as_dict()
    session.commit()
    return True


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
    hosts = _check(c.get(f"/objects/{oid}/hosts", headers=meth))
    _check(
        c.put(
            f"/objects/{oid}/hosts",
            headers=meth,
            json={
                "items": [
                    {
                        "address": x["address"],
                        "hostname": x["hostname"],
                        "role": x["role"],
                        "segment_id": x["segment_id"],
                        "component_types": GIS_INVENTORY[x["address"]][0],
                        "internet_exposed": GIS_INVENTORY[x["address"]][1],
                    }
                    for x in hosts
                ]
            },
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
    for note in r.notes:
        print(f"демо-данные: {note}")
    print("вход (пароль у всех один):")
    for username, (name, _) in DEMO_USERS.items():
        print(f"  {username:<12} {name}")
    print(f"  пароль: {r.password}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
