"""Задача 2.8: реестр уязвимостей объекта, оценка V по Методике 2025."""

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from app.db.models import AuditRecord, BduVuln, ObjectVulnAssessment, utcnow
from app.domain.vuln_criticality import definition_hash
from app.domain.vuln_inventory import HostData
from app.domain.vuln_register import (
    BduInfo,
    Choices,
    check_cvss_choice,
    deadline_at,
    propose,
    stale_reasons,
)
from tests.test_scanner_import import GIS_HOSTS, _build, _import
from tests.test_scanner_import import env as scanner_env  # noqa: F401 — фикстура

FILE = Path(__file__).resolve().parents[2] / "reference" / "vuln-criticality" / "fstec-2025.yaml"


def _definition() -> dict:
    return yaml.safe_load(FILE.read_text(encoding="utf-8"))


def _host(address, types=(), internet=None):
    return HostData(
        address=address, hostname=None, component_types=tuple(types), internet_exposed=internet
    )


def _bdu_info(bdu_id="BDU:2025-01611", cvss=8.8, version="3.1", exploit=None, in_wild=None, **kw):
    from app.domain.bdu import e_level

    return BduInfo(
        bdu_id=bdu_id,
        title="Уязвимость",
        cvss3_score=cvss,
        cvss3_version=version,
        cvss3_vector=None,
        cvss_other=kw.get("cvss_other"),
        exploit=exploit,
        in_wild=in_wild,
        exploit_raw=None,
        in_wild_raw=None,
        e_level=e_level(exploit, in_wild),
        criticality_changed_at=kw.get("changed_at"),
    )


# ---------- Домен ----------


def test_example_1_from_bdu_inventory_and_specialist():
    """Пример 1: CVSS 8,8 из БДУ, межсетевой экран 1 из 4, доступен, нет эксплойта, H2."""
    d = _definition()
    hosts = [_host("10.0.0.1", ["K2"], True)] + [
        _host(f"10.0.0.{i}", ["K2"], False) for i in range(2, 5)
    ]
    p = propose(
        d,
        definition_hash(d),
        hosts=hosts,
        vulnerable=["10.0.0.1"],
        bdu=_bdu_info(exploit="none", in_wild="no"),
        bdu_id="BDU:2025-01611",
        findings=[],
        choices=Choices(h=["H2"]),
    )
    assert p.missing == []
    assert p.inputs == {
        "cvss": "8.8",
        "K": ["K2"],
        "L": ["L3"],
        "P": ["P1"],
        "E": ["E3"],
        "H": ["H2"],
    }
    assert (p.outcome["v"], p.outcome["level"]["code"]) == ("4.75", "medium")
    basis = {r["indicator"]: r for r in p.outcome["trace"]}
    assert basis["cvss"]["basis_kind"] == "bdu" and "CVSS 3.1 из БДУ" in basis["cvss"]["basis"]
    assert "1 из 4 (25 %) → L3" in basis["L"]["basis"]
    assert basis["P"]["basis"] == "Доступны из сети «Интернет»: 10.0.0.1"
    assert basis["E"]["basis_kind"] == "bdu" and basis["H"]["basis_kind"] == "specialist"


def test_missing_data_is_listed_and_nothing_computed():
    d = _definition()
    p = propose(
        d,
        definition_hash(d),
        hosts=[_host("10.0.0.1")],
        vulnerable=["10.0.0.1"],
        bdu=None,
        bdu_id="BDU:2025-99999",
        findings=[{"cvss": 7.5}],
        choices=Choices(),
    )
    codes = [m["indicator"] for m in p.missing]
    assert codes == ["cvss", "K", "L", "P", "E", "H"]
    assert "нет в загруженной выгрузке БДУ" in p.missing[0]["text"]
    assert p.outcome is None and p.fingerprint is None
    # «Сканер» дал оценку — её можно выбрать, версия не указана.
    assert p.cvss["options"] == [
        {
            "version": None,
            "score": "7.5",
            "vector": None,
            "source": "scanner",
            "title": "«Сканер» (версия CVSS не указана)",
        }
    ]


def test_cvss_fallback_is_marked_and_bdu_31_wins_later():
    d = _definition()
    hosts = [_host("10.0.0.1", ["K5"], False)]
    choice = check_cvss_choice({"version": "2.0", "score": "7,5", "source": "bdu"})
    args = dict(hosts=hosts, vulnerable=["10.0.0.1"], bdu_id="BDU:2025-1", findings=[])
    no31 = _bdu_info(
        cvss=None, version=None, cvss_other={"cvss2": {"score": 7.5, "vector": "AV:N"}}
    )
    p = propose(d, "h", bdu=no31, choices=Choices(cvss=choice, h=["H7"]), **args)
    assert p.cvss["fallback"] is True and p.inputs["cvss"] == "7.5"
    row = next(r for r in p.outcome["trace"] if r["indicator"] == "cvss")
    assert row["fallback"] and "специалист выбрал CVSS 2.0" in row["basis"]
    assert p.cvss["options"][0]["title"] == "БДУ, CVSS 2.0"
    # В БДУ появилась CVSS 3.1 — она главнее выбора специалиста (п. 13).
    p2 = propose(d, "h", bdu=_bdu_info(cvss=9.0), choices=Choices(cvss=choice, h=["H7"]), **args)
    assert p2.inputs["cvss"] == "9" and p2.cvss["fallback"] is False
    assert any("CVSS 3.1" in n for n in p2.notes)
    with pytest.raises(ValueError, match="версия CVSS"):
        check_cvss_choice({"version": "5", "score": 1})


def test_specialist_can_raise_but_not_lower_e():
    d = _definition()
    hosts = [_host("10.0.0.1", ["K5"], False)]
    args = dict(hosts=hosts, vulnerable=["10.0.0.1"], bdu_id="BDU:2025-1", findings=[])
    bdu = _bdu_info(exploit="public", in_wild="no")  # → E2
    lower = propose(d, "h", bdu=bdu, choices=Choices(e=["E3"], h=["H1"]), **args)
    e = next(r for r in lower.outcome["trace"] if r["indicator"] == "E")
    assert e["value"] == "E2" and e["rule"] == "наибольшее из значений"
    higher = propose(d, "h", bdu=bdu, choices=Choices(e=["E1"], h=["H1"]), **args)
    assert next(r for r in higher.outcome["trace"] if r["indicator"] == "E")["value"] == "E1"


def test_stale_reasons():
    d = _definition()
    hosts = [_host("10.0.0.1", ["K5"], False), _host("10.0.0.2", ["K5"], True)]
    at = datetime(2026, 11, 1, tzinfo=UTC)
    bdu = _bdu_info(exploit="none", in_wild="no")
    base = propose(
        d,
        "h1",
        hosts=hosts,
        vulnerable=["10.0.0.1"],
        bdu=bdu,
        bdu_id="B",
        findings=[],
        choices=Choices(h=["H1"]),
    )
    last = {"inputs": base.inputs, "hosts": base.hosts, "methodology_hash": "h1", "assessed_at": at}
    assert stale_reasons(d, "h1", last, base, bdu) == []
    now = propose(
        d,
        "h2",
        hosts=hosts,
        vulnerable=["10.0.0.1", "10.0.0.2"],
        bdu=bdu,
        bdu_id="B",
        findings=[],
        choices=Choices(h=["H2"]),
    )
    changed = _bdu_info(exploit="none", in_wild="no", changed_at=at + timedelta(days=1))
    reasons = stale_reasons(d, "h2", last, now, changed)
    assert reasons == [
        "в БДУ изменились сведения, влияющие на критичность (п. 16, 19)",
        "изменился справочник Методики",
        "изменился перечень уязвимых хостов: добавились 10.0.0.2",
        "изменились данные инвентаризации (L)",
        "изменились данные инвентаризации (P)",
        "изменён выбор специалиста (H)",
    ]
    # Изменение БДУ до оценки уже учтено.
    old = _bdu_info(exploit="none", in_wild="no", changed_at=at - timedelta(days=1))
    assert stale_reasons(d, "h1", last, base, old) == []


@pytest.mark.parametrize(
    ("level", "at", "due"),
    [
        ("critical", datetime(2026, 11, 5, 10, tzinfo=UTC), datetime(2026, 11, 6, 10, tzinfo=UTC)),
        ("high", datetime(2026, 11, 5, tzinfo=UTC), datetime(2026, 11, 12, tzinfo=UTC)),
        ("medium", datetime(2026, 11, 5, tzinfo=UTC), datetime(2026, 12, 3, tzinfo=UTC)),
        ("low", datetime(2026, 10, 31, tzinfo=UTC), datetime(2027, 2, 28, tzinfo=UTC)),
    ],
)
def test_deadlines_clause_21(level, at, due):
    lv = next(x for x in _definition()["levels"] if x["code"] == level)
    assert deadline_at(lv, at) == due


# ---------- API ----------

TYPES = {
    "10.10.1.10": (["K1", "K5"], True),
    "10.10.1.11": (["K5"], False),
    "10.10.1.12": (["K5"], False),
    "10.10.1.20": (["K5"], False),
    "10.10.2.5": (["K5"], False),
    "10.10.2.6": (["K5"], False),
}


def _bdu_rows(session, **over):
    imp = uuid.uuid4()
    now = utcnow()
    rows = {
        "BDU:2024-04835": dict(
            title="OpenSSH regreSSHion", cvss3_score=8.1, exploit="public", in_wild="no"
        ),
        "BDU:2021-06061": dict(
            title="Log4Shell", cvss3_score=10.0, exploit="public", in_wild="yes"
        ),
        # Нет CVSS 3.1 — только 2.0.
        "BDU:2026-00042": dict(
            title="Обход аутентификации",
            cvss3_score=None,
            exploit=None,
            in_wild=None,
            cvss_other={"cvss2": {"score": 9.0, "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}},
        ),
    }
    for bid, data in rows.items():
        data = {**data, **over.get(bid, {})}
        session.add(
            BduVuln(
                bdu_id=bid,
                cvss3_version="3.1" if data.get("cvss3_score") is not None else None,
                row_hash="x",
                crit_hash="c",
                first_import_id=imp,
                changed_import_id=imp,
                updated_at=now,
                **data,
            )
        )
    session.commit()


@pytest.fixture
def env(client, scanner_env, session):  # noqa: F811
    h, o, _ = scanner_env
    _bdu_rows(session)
    _build(client, h, o["id"])
    items = []
    for a in GIS_HOSTS:
        types, net = TYPES.get(a, (["K6"], False))
        items.append({"address": a, "component_types": types, "internet_exposed": net})
    r = client.put(f"/objects/{o['id']}/hosts", headers=h["meth"], json={"items": items})
    assert r.status_code == 200, r.text
    client.patch(f"/objects/{o['id']}", headers=h["meth"], json={"internet": True})
    assert _import(client, h, o["id"], run_id=7).status_code == 201
    return h, o


def _register(client, h, oid):
    r = client.get(f"/objects/{oid}/vulns", headers=h["viewer"])
    assert r.status_code == 200, r.text
    return r.json()


def _by_bdu(reg):
    return {x["bdu_id"]: x for x in reg["items"]}


def test_snapshot_import_fills_register_one_entry_per_bdu(client, env):
    h, o = env
    reg = _register(client, h, o["id"])
    by = _by_bdu(reg)
    # Хост «Бухгалтерии» и ложное срабатывание не попали.
    assert set(by) == {"BDU:2024-04835", "BDU:2021-06061", "BDU:2026-00042"}
    ssh = by["BDU:2024-04835"]
    assert ssh["hosts"] == ["10.10.2.5", "10.10.2.6"] and ssh["origin"] == "scanner"
    assert ssh["state"] == "incomplete"
    assert [m["indicator"] for m in ssh["missing"]] == ["H"]
    # Сведений об эксплойте в БДУ нет — E3 «отсутствуют сведения»; нет CVSS 3.1.
    assert [m["indicator"] for m in by["BDU:2026-00042"]["missing"]] == ["cvss", "H"]
    assert reg["counts"]["incomplete"] == 3 and reg["snapshot"]["number"] == 1


def test_specialist_choice_creates_assessment_with_trace_and_deadline(client, env, session):
    h, o = env
    vid = _by_bdu(_register(client, h, o["id"]))["BDU:2021-06061"]["id"]
    # Наблюдатель и методист не оценивают.
    assert (
        client.patch(f"/object-vulns/{vid}", headers=h["viewer"], json={"h": ["H1"]}).status_code
        == 403
    )
    assert (
        client.patch(f"/object-vulns/{vid}", headers=h["meth"], json={"h": ["H1"]}).status_code
        == 403
    )
    r = client.patch(f"/object-vulns/{vid}", headers=h["exp"], json={"h": ["H1"]})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["state"] == "current" and d["assessments"] == 1
    a = d["history"][0]
    # Log4Shell на 10.10.2.5 (сервер, 1 из 5 серверов = 20 % → L3), недоступен, E1, H1:
    # I_infr = 0,5×0,7 + 0,2×0,6 + 0,3×0,6 = 0,65; V = 10 × 0,65 × (0,6 + 0,5) = 7,15.
    assert a["outcome"]["groups"]["infr"] == "0.65"
    assert (a["v"], a["level"], a["level_title"]) == ("7.15", "high", "Высокий")
    assert a["inputs"]["E"] == ["E1"] and a["inputs"]["L"] == ["L3"]
    due = datetime.fromisoformat(a["deadline_at"]) - datetime.fromisoformat(a["assessed_at"])
    assert due == timedelta(days=7) and a["deadline_from"] == 1
    assert a["trigger"] == "choices" and a["assessed_by_name"] == "Козлов К. К."
    basis = {t["indicator"]: t for t in a["outcome"]["trace"]}
    assert basis["E"]["basis"].startswith("БДУ: E1")
    assert basis["K"]["source"]["table"] == "1"
    # Сохранение без изменений не плодит оценки; явный пересчёт — 409.
    r = client.patch(f"/object-vulns/{vid}", headers=h["exp"], json={"comment": "проверено"})
    assert r.json()["assessments"] == 1
    r = client.post(f"/object-vulns/{vid}/assess", headers=h["exp"])
    assert r.status_code == 409 and "не изменились" in r.json()["detail"]
    rec = session.scalars(
        select(AuditRecord).where(AuditRecord.action == "object_vuln.update")
    ).all()
    assert rec[0].details["assessment"] == {"number": 1, "v": "7.15", "level": "high"}


def test_cvss_choice_when_bdu_has_no_31(client, env):
    h, o = env
    vid = _by_bdu(_register(client, h, o["id"]))["BDU:2026-00042"]["id"]
    d = client.get(f"/object-vulns/{vid}", headers=h["viewer"]).json()
    assert d["proposal"]["cvss"]["options"][0]["title"] == "БДУ, CVSS 2.0"
    r = client.patch(
        f"/object-vulns/{vid}",
        headers=h["exp"],
        json={
            "cvss": {"version": "2.0", "score": 9.0, "source": "bdu"},
            "e": ["E3"],
            "h": ["H3"],
            "certified_szi": True,
        },
    )
    assert r.status_code == 200, r.text
    a = r.json()["history"][0]
    assert a["details"]["cvss"]["fallback"] is True
    # П. 4: средство удалённого администрирования — сертифицированное СЗИ → критический.
    assert a["level"] == "critical" and a["outcome"]["level_by_v"] is not None
    bad = client.patch(f"/object-vulns/{vid}", headers=h["exp"], json={"h": ["H99"]})
    assert bad.status_code == 422


def test_new_snapshot_recalculates_and_keeps_history(client, env, session):
    h, o = env
    by = _by_bdu(_register(client, h, o["id"]))
    for bid in ("BDU:2024-04835", "BDU:2021-06061"):
        r = client.patch(f"/object-vulns/{by[bid]['id']}", headers=h["exp"], json={"h": ["H1"]})
        assert r.status_code == 200, r.text
    ssh_first = client.get(
        f"/object-vulns/{by['BDU:2024-04835']['id']}", headers=h["viewer"]
    ).json()
    # Прогон 8: Log4Shell пропала, СУБД 10.10.1.12 с новой уязвимостью без сведений БДУ.
    assert _import(client, h, o["id"], run_id=8).status_code == 201
    reg = _register(client, h, o["id"])
    by = _by_bdu(reg)
    assert by["BDU:2021-06061"]["state"] == "not_detected"
    assert by["BDU:2021-06061"]["last_seen_snapshot"] == 1
    assert by["BDU:2026-01377"]["state"] == "incomplete"  # нет в БДУ: CVSS и E — специалисту
    # Состав уязвимых хостов SSH не изменился — пересчёта нет.
    assert by["BDU:2024-04835"]["assessments"] == 1 and by["BDU:2024-04835"]["state"] == "current"

    # Тип хоста поменялся — оценка устарела; «Пересчитать» делает новую, старая остаётся.
    items = [
        {
            "address": a,
            "component_types": (["K2"] if a == "10.10.2.5" else TYPES.get(a, (["K6"], False))[0]),
        }
        for a in GIS_HOSTS
    ]
    client.put(f"/objects/{o['id']}/hosts", headers=h["meth"], json={"items": items})
    row = _by_bdu(_register(client, h, o["id"]))["BDU:2024-04835"]
    assert (
        row["state"] == "stale" and "изменились данные инвентаризации (K)" in row["stale_reasons"]
    )
    r = client.post(f"/objects/{o['id']}/vulns/refresh", headers=h["exp"])
    assert r.status_code == 200 and r.json()["assessed"] == 1
    d = client.get(f"/object-vulns/{row['id']}", headers=h["viewer"]).json()
    assert [a["number"] for a in d["history"]] == [2, 1]
    assert d["history"][1] == ssh_first["history"][0]
    assert d["history"][0]["trigger"] == "recalc" and d["state"] == "current"
    # Оценки неизменяемы.
    with pytest.raises(DatabaseError):
        session.execute(text("UPDATE object_vuln_assessments SET v = '0'"))
    session.rollback()


def test_bdu_change_flag_triggers_recalculation(client, env, session):
    h, o = env
    vid = _by_bdu(_register(client, h, o["id"]))["BDU:2024-04835"]["id"]
    first = client.patch(f"/object-vulns/{vid}", headers=h["exp"], json={"h": ["H1"]}).json()
    assert first["history"][0]["inputs"]["E"] == ["E2"]
    # Выгрузка БДУ: уязвимость эксплуатируется в атаках (флаг задачи 2.2).
    from app.api.object_vulns import refresh_for_bdu

    row = session.get(BduVuln, "BDU:2024-04835")
    row.in_wild = "yes"
    row.criticality_changed_at = utcnow() + timedelta(seconds=1)
    session.commit()
    stale = _by_bdu(_register(client, h, o["id"]))["BDU:2024-04835"]
    assert stale["state"] == "stale"
    assert stale["stale_reasons"][0].startswith("в БДУ изменились сведения")
    assert refresh_for_bdu(session, {"BDU:2024-04835"}, None) == 1
    session.commit()
    d = client.get(f"/object-vulns/{vid}", headers=h["viewer"]).json()
    a = d["history"][0]
    assert a["trigger"] == "bdu" and a["inputs"]["E"] == ["E1"]
    # Уровень повысился — новый срок от пересчёта; тот же уровень срок не продлил бы.
    assert float(a["v"]) > float(d["history"][1]["v"])


def test_same_level_keeps_deadline(client, env):
    h, o = env
    vid = _by_bdu(_register(client, h, o["id"]))["BDU:2024-04835"]["id"]
    a1 = client.patch(f"/object-vulns/{vid}", headers=h["exp"], json={"h": ["H1"]}).json()[
        "history"
    ][0]
    a2 = client.patch(f"/object-vulns/{vid}", headers=h["exp"], json={"h": ["H2"]}).json()[
        "history"
    ][0]
    assert a2["number"] == 2 and a2["level"] == a1["level"]
    assert a2["deadline_at"] == a1["deadline_at"] and a2["deadline_from"] == 1


def test_manual_entry_and_remediation_export(client, env, session):
    h, o = env
    url = f"/objects/{o['id']}/vulns"
    body = {
        "title": "Слабый пароль администратора портала",
        "manual_source": "pentest",
        "manual_hosts": ["10.10.1.10"],
        "cvss": {
            "version": "3.1",
            "score": 9.8,
            "source": "manual",
            "vector": "AV:N/AC:L/PR:N/UI:N",
        },
        "e": ["E2"],
        "h": ["H2"],
    }
    r = client.post(url, headers=h["exp"], json=body)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["origin"] == "manual" and d["manual_source_title"] == "Тестирование на проникновение"
    assert d["state"] == "current" and d["history"][0]["level"] == "critical"
    # Хост не из состава и повтор БДУ — ошибки.
    assert (
        client.post(url, headers=h["exp"], json={**body, "manual_hosts": ["10.9.9.9"]}).status_code
        == 422
    )
    dup = client.post(url, headers=h["exp"], json={**body, "bdu_id": "BDU:2024-04835"})
    assert dup.status_code == 409 and "уже в реестре" in dup.json()["detail"]
    # Ручные хосты к записи из «Сканера».
    ssh = _by_bdu(_register(client, h, o["id"]))["BDU:2024-04835"]["id"]
    r = client.patch(
        f"/object-vulns/{ssh}",
        headers=h["exp"],
        json={"manual_hosts": ["10.10.1.11"], "manual_source": "exercise", "h": ["H7"]},
    )
    assert r.json()["hosts"] == ["10.10.1.11", "10.10.2.5", "10.10.2.6"]

    out = client.get(f"{url}/remediation", headers=h["viewer"])
    assert out.status_code == 200, out.text
    exp = out.json()
    assert exp["product"] == "grc" and exp["methodology"]["id"] == "fstec-2025"
    items = exp["items"]
    assert [i["level"] for i in items] == ["critical", "medium"]
    assert items[0]["title"].startswith("Слабый пароль") and items[0]["up_to_date"] is True
    assert {"v", "level", "deadline_at", "assessed_at", "hosts"} <= set(items[0])
    # Удалить можно только ручную запись без оценок.
    assert client.delete(f"/object-vulns/{d['id']}", headers=h["exp"]).status_code == 409
    assert client.delete(f"/object-vulns/{ssh}", headers=h["exp"]).status_code == 409
    n = session.scalar(select(ObjectVulnAssessment).limit(1))
    assert n is not None
