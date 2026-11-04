"""Модель угроз: шаги мастера, угрозы БДУ, прогресс, утверждение без самоутверждения."""

import shutil
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.db.models import AuditRecord, BduThreat, RefThreatItem, ThreatModel, utcnow
from app.domain.threat_model import Refs, bdu_source_hint, progress
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"

STEPS = {
    "consequences": {
        "items": [
            {"code": "У1.4", "justification": "В системе обрабатываются ПДн заявителей"},
            {"code": "У3.4", "justification": "Сбой срывает оказание госуслуги"},
        ]
    },
    "objects": {
        "items": [
            {
                "key": "db",
                "name": "СУБД с данными заявителей",
                "hosts": ["10.0.0.5"],
                "impacts": ["ВВ1", "ВВ4"],
                "consequences": ["У1.4"],
            },
            {
                "key": "portal",
                "name": "Веб-портал",
                "impacts": ["ВВ3"],
                "consequences": ["У3.4"],
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
                "code": "НВ1",
                "relevant": False,
                "justification": "Нет сведений об интересе спецслужб",
            },
        ]
    },
    "methods": {
        "items": [
            {
                "code": "СР1",
                "interfaces": "Веб-интерфейс портала (HTTPS)",
                "objects": ["portal", "db"],
                "intruders": ["НВ4"],
            }
        ]
    },
    "scenarios": {"items": [{"tactic": "Т2"}, {"tactic": "Т10"}]},
}


@pytest.fixture
def ref_dir(tmp_path) -> Path:
    shutil.copytree(REFERENCE / "threats", tmp_path / "threats")
    return tmp_path


def _bdu(session) -> None:
    now = utcnow()
    imp = uuid.uuid4()
    rows = [
        (6, "Угроза внедрения кода или данных", "Внешний нарушитель с низким потенциалом"),
        (67, "Угроза неправомерного ознакомления", "Внутренний нарушитель с низким потенциалом"),
        (140, "Угроза отказа в обслуживании", "Внешний нарушитель со средним потенциалом"),
    ]
    for n, title, source in rows:
        session.add(
            BduThreat(
                code=f"УБИ.{n:03d}",
                number=n,
                title=title,
                source=source,
                row_hash="x",
                first_import_id=imp,
                changed_import_id=imp,
                updated_at=now,
            )
        )
    session.commit()


@pytest.fixture
def env(client, make_user, login, session, ref_dir):
    load_reference(session, ref_dir)
    _bdu(session)
    make_user("meth", "methodologist", display_name="Иванова А. А.")
    make_user("meth2", "methodologist", "approve", display_name="Петров П. П.")
    make_user("boss", "viewer", "approve", display_name="Смирнов С. С.")
    make_user("viewer", "viewer", display_name="Наблюдатель")
    h = {u: login(u) for u in ("meth", "meth2", "boss", "viewer")}
    c = client.post("/customers", headers=h["meth"], json={"name": "ГБУ «Центр»"}).json()
    p = client.post(
        "/projects", headers=h["meth"], json={"customer_id": c["id"], "name": "Аттестация"}
    ).json()
    users = client.get("/directory/users", headers=h["meth"]).json()
    client.put(
        f"/projects/{p['id']}/members",
        headers=h["meth"],
        json={"user_ids": [u["id"] for u in users]},
    )
    o = client.post(
        f"/projects/{p['id']}/objects",
        headers=h["meth"],
        json={"kind": "gis", "name": "ГИС", "regime": "117"},
    ).json()
    r = client.put(
        f"/objects/{o['id']}/hosts",
        headers=h["meth"],
        json={"items": [{"address": "10.0.0.5"}, {"address": "10.0.0.6"}]},
    )
    assert r.status_code == 200, r.text
    return h, o


def _fill(client, h, mid) -> dict:
    for step, data in STEPS.items():
        r = client.put(f"/threat-models/{mid}/steps/{step}", headers=h, json={"data": data})
        assert r.status_code == 200, (step, r.text)
    r = client.post(
        f"/threat-models/{mid}/threats", headers=h, json={"codes": ["УБИ.006", "УБИ.067"]}
    )
    assert r.status_code == 200, r.text
    r = client.patch(
        f"/threat-models/{mid}/threats/УБИ.006",
        headers=h,
        json={
            "relevant": True,
            "justification": "Портал доступен из сети «Интернет», уязвимости веб-приложения",
            "intruders": ["НВ4"],
            "objects": ["portal", "db"],
            "consequences": ["У1.4", "У3.4"],
            "methods": ["СР1"],
            "tactics": ["Т2", "Т10"],
        },
    )
    assert r.status_code == 200, r.text
    r = client.patch(
        f"/threat-models/{mid}/threats/УБИ.067",
        headers=h,
        json={"relevant": False, "justification": "Внутренний нарушитель не актуален"},
    )
    assert r.status_code == 200, r.text
    return r.json()


# ---------- Домен ----------


def test_bdu_source_hint():
    hint = bdu_source_hint(
        "Внешний нарушитель с низким потенциалом; внутренний нарушитель со средним потенциалом"
    )
    assert hint == {"categories": ["внешний", "внутренний"], "potentials": ["низкий", "средний"]}
    assert bdu_source_hint(None) == {"categories": [], "potentials": []}


def test_progress_requires_links_for_relevant_threat():
    refs = Refs(
        kinds={"У1.1": "consequence", "НВ4": "intruder", "СР1": "method", "Т2": "tactic"},
        parents={},
        attrs={},
    )
    steps = {
        "consequences": {"items": [{"code": "У1.1"}]},
        "objects": {"items": [{"key": "a", "name": "А", "impacts": ["ВВ1"], "consequences": []}]},
        "intruders": {"items": [{"code": "НВ4", "relevant": True, "capability": "Н1"}]},
    }
    threats = [{"code": "УБИ.006", "relevant": True, "justification": "есть"}]
    p = progress(steps, threats, refs=refs, hosts=set(), bdu={"УБИ.006": {"withdrawn": True}})
    by = {s.key: s for s in p.steps}
    assert by["consequences"].done
    assert not by["objects"].done  # нет последствий у объекта
    assert not by["intruders"].done  # нет обоснования
    assert not by["methods"].done and not by["scenarios"].done
    problems = by["threats"].problems
    assert "УБИ.006: угроза исключена из БДУ, а признана актуальной" in problems
    assert any("нет актуального нарушителя" in x for x in problems)
    assert not p.ready


# ---------- API ----------


def test_wizard_fills_steps_and_tracks_progress(client, env, session):
    h, o = env
    r = client.post(f"/objects/{o['id']}/threat-models", headers=h["viewer"])
    assert r.status_code == 403
    r = client.post(f"/objects/{o['id']}/threat-models", headers=h["meth"])
    assert r.status_code == 201, r.text
    m = r.json()
    assert m["version"] == 1 and m["status"] == "draft"
    assert m["progress"]["done"] == 0 and m["progress"]["total"] == 6
    # Второй черновик не создаётся.
    assert client.post(f"/objects/{o['id']}/threat-models", headers=h["meth"]).status_code == 409

    # Неизвестный код справочника отклоняется.
    bad = {"items": [{"code": "У9.9"}]}
    r = client.put(
        f"/threat-models/{m['id']}/steps/consequences", headers=h["meth"], json={"data": bad}
    )
    assert r.status_code == 422
    # Техника не своей тактики — тоже.
    bad = {"items": [{"tactic": "Т2", "techniques": ["Т1"]}]}
    r = client.put(
        f"/threat-models/{m['id']}/steps/scenarios", headers=h["meth"], json={"data": bad}
    )
    assert r.status_code == 422

    detail = _fill(client, h["meth"], m["id"])
    assert detail["progress"]["ready"], detail["progress"]
    assert detail["progress"]["done"] == 6
    assert detail["relevant"] == 1 and detail["considered"] == 2
    assert "Т2" in detail["unverified_refs"]  # справочник — заглушка, не сверен
    t = {x["code"]: x for x in detail["threats"]}["УБИ.006"]
    assert t["title"] == "Угроза внедрения кода или данных"
    assert t["hint"]["categories"] == ["внешний"]

    # Снятие последствия на шаге 1 оставляет висячие ссылки — это проблема, а не ошибка.
    step1 = {"items": [STEPS["consequences"]["items"][0]]}
    r = client.put(
        f"/threat-models/{m['id']}/steps/consequences", headers=h["meth"], json={"data": step1}
    )
    assert r.status_code == 200
    prog = {s["key"]: s for s in r.json()["progress"]["steps"]}
    assert "«Веб-портал»: последствие У3.4 не выбрано на шаге 1" in prog["objects"]["problems"]
    assert "УБИ.006: У3.4 не выбрано на шаге 1" in prog["threats"]["problems"]
    assert not r.json()["progress"]["ready"]

    actions = set(session.scalars(select(AuditRecord.action)))
    assert {"threat_model.create", "threat_model.step", "threat_model.threat.update"} <= actions


def test_candidates_hint_by_intruder_category(client, env):
    h, o = env
    m = client.post(f"/objects/{o['id']}/threat-models", headers=h["meth"]).json()
    _fill(client, h["meth"], m["id"])
    r = client.get(f"/threat-models/{m['id']}/candidates", headers=h["viewer"])
    assert r.status_code == 200
    by = {c["code"]: c for c in r.json()}
    assert by["УБИ.006"]["in_model"] and by["УБИ.006"]["category_match"]
    assert not by["УБИ.067"]["category_match"]  # внутренний, а актуален только внешний
    r = client.get(f"/threat-models/{m['id']}/candidates?match=true", headers=h["viewer"])
    assert {c["code"] for c in r.json()} == {"УБИ.006", "УБИ.140"}
    r = client.get(f"/threat-models/{m['id']}/candidates?q=УБИ.140", headers=h["viewer"])
    assert [c["code"] for c in r.json()] == ["УБИ.140"]
    # Неизвестную угрозу не добавить.
    r = client.post(
        f"/threat-models/{m['id']}/threats", headers=h["meth"], json={"codes": ["УБИ.999"]}
    )
    assert r.status_code == 422
    r = client.delete(f"/threat-models/{m['id']}/threats/УБИ.067", headers=h["meth"])
    assert r.status_code == 200 and r.json()["considered"] == 1


def test_approve_rules_and_new_version(client, env, session):
    h, o = env
    m = client.post(f"/objects/{o['id']}/threat-models", headers=h["meth2"]).json()
    url = f"/threat-models/{m['id']}/approve"
    # Неполную модель не утвердить.
    r = client.post(url, headers=h["boss"], json={"acknowledge_unverified": True})
    assert r.status_code == 409 and "не готова" in r.json()["detail"]

    _fill(client, h["meth"], m["id"])
    # Создатель модели не утверждает, даже имея право approve.
    r = client.post(url, headers=h["meth2"], json={"acknowledge_unverified": True})
    assert r.status_code == 403
    # Несверенный справочник — только с подтверждением.
    r = client.post(url, headers=h["boss"], json={})
    assert r.status_code == 409 and r.headers["X-Error-Code"] == "unverified_refs"
    r = client.post(url, headers=h["boss"], json={"acknowledge_unverified": True, "comment": "ок"})
    assert r.status_code == 200, r.text
    v1 = r.json()
    assert v1["status"] == "approved" and v1["unverified_acknowledged"]
    assert v1["snapshot"]["bdu"]["УБИ.006"]["title"] == "Угроза внедрения кода или данных"
    assert v1["snapshot"]["refs"]["НВ4"]["verified"] is False

    # Утверждённая не меняется.
    r = client.put(
        f"/threat-models/{m['id']}/steps/scenarios",
        headers=h["meth"],
        json={"data": STEPS["scenarios"]},
    )
    assert r.status_code == 409

    # Новая версия копирует утверждённую.
    r = client.post(f"/objects/{o['id']}/threat-models", headers=h["meth"])
    assert r.status_code == 201
    v2 = r.json()
    assert v2["version"] == 2 and v2["based_on"] == m["id"]
    assert v2["relevant"] == 1 and v2["progress"]["ready"]
    # Правивший утвердить не может; другой утверждающий — может, v1 становится заменённой.
    client.patch(
        f"/threat-models/{v2['id']}/threats/УБИ.067",
        headers=h["meth2"],
        json={"justification": "Внутренние нарушители не актуальны: доступ только у штатных"},
    )
    url2 = f"/threat-models/{v2['id']}/approve"
    r = client.post(url2, headers=h["meth2"], json={"acknowledge_unverified": True})
    assert r.status_code == 403
    r = client.post(url2, headers=h["boss"], json={"acknowledge_unverified": True})
    assert r.status_code == 200, r.text
    listing = client.get(f"/objects/{o['id']}/threat-models", headers=h["viewer"]).json()
    assert [(x["version"], x["status"]) for x in listing] == [(2, "approved"), (1, "superseded")]

    denied = session.scalars(
        select(AuditRecord).where(
            AuditRecord.action == "threat_model.approve", AuditRecord.result == "denied"
        )
    ).all()
    assert len(denied) == 2


def test_verified_refs_need_no_ack(client, env, session):
    h, o = env
    m = client.post(f"/objects/{o['id']}/threat-models", headers=h["meth"]).json()
    _fill(client, h["meth"], m["id"])
    session.execute(update(RefThreatItem).values(verified_at=utcnow(), verified_by_name="X"))
    session.commit()
    r = client.post(f"/threat-models/{m['id']}/approve", headers=h["boss"], json={})
    assert r.status_code == 200, r.text
    assert not r.json()["unverified_acknowledged"]


def test_discard_draft_and_db_forbids_self_approval(client, env, session):
    h, o = env
    m = client.post(f"/objects/{o['id']}/threat-models", headers=h["meth"]).json()
    assert client.delete(f"/threat-models/{m['id']}", headers=h["viewer"]).status_code == 403
    assert client.delete(f"/threat-models/{m['id']}", headers=h["meth"]).status_code == 204
    m = client.post(f"/objects/{o['id']}/threat-models", headers=h["meth"]).json()
    row = session.get(ThreatModel, uuid.UUID(m["id"]))
    row.status = "approved"
    row.approved_by = row.created_by
    row.approved_at = utcnow()
    with pytest.raises(IntegrityError):
        session.commit()
