"""Справочник Методики оценки угроз 2021: файл, загрузка, правка, сверка."""

import copy
import shutil
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select

from app.db.models import AuditRecord, RefThreatItem
from app.domain.threat_refs import ThreatRefError, parse
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"
FILE = REFERENCE / "threats" / "methodology-2021.yaml"


def _data() -> dict:
    return yaml.safe_load(FILE.read_text(encoding="utf-8"))


# ---------- Файл ----------


def test_reference_file_has_all_sections_with_sources():
    items = parse(_data())
    by_kind: dict[str, list[dict]] = {}
    for i in items:
        by_kind.setdefault(i["kind"], []).append(i)
    assert [i["code"] for i in by_kind["consequence_type"]] == ["У1", "У2", "У3"]
    assert [i["code"] for i in by_kind["capability"]] == ["Н1", "Н2", "Н3", "Н4"]
    assert [i["code"] for i in by_kind["tactic"]] == [f"Т{n}" for n in range(1, 11)]
    assert len(by_kind["intruder"]) == 13
    assert [i["code"] for i in by_kind["impact"]] == [f"ВВ{n}" for n in range(1, 7)]
    assert [i["code"] for i in by_kind["method"]] == [f"СР{n}" for n in range(1, 10)]
    # Наименования с запятыми не обрезаны YAML.
    titles = {i["code"]: i["title"] for i in items}
    assert titles["НВ2"] == "Террористические, экстремистские группировки"
    assert titles["Т5"].endswith("к которым ранее был получен доступ")
    assert {i["attrs"]["capability"] for i in by_kind["intruder"]} <= {"Н1", "Н2", "Н3", "Н4"}
    # Примеры последствий нумеруются внутри вида и знают родителя.
    first = next(i for i in by_kind["consequence"] if i["code"] == "У1.1")
    assert first["parent_code"] == "У1" and first["title"] == "Угроза жизни или здоровью"
    # Техники без текста Методики не выдумываем.
    assert "technique" not in by_kind
    # Нормативный текст не загружен: всё — заглушка, у каждой записи есть документ.
    assert all(i["origin"] == "stub" for i in items)
    assert all("Методика оценки угроз" in i["source"]["document"] for i in items)
    assert by_kind["consequence"][0]["source"]["appendix"] == "4"
    assert by_kind["tactic"][0]["source"]["appendix"] == "11"


def test_parse_rejects_broken_file():
    bad = copy.deepcopy(_data())
    bad["sections"][2]["items"][0]["attrs"]["capability"] = "Н9"
    with pytest.raises(ThreatRefError, match="уровень возможностей"):
        parse(bad)
    bad = copy.deepcopy(_data())
    bad["sections"][3]["items"][1]["code"] = "Т1"
    with pytest.raises(ThreatRefError, match="повторяется"):
        parse(bad)
    bad = copy.deepcopy(_data())
    bad["sections"][2]["items"][1]["экстремистские группировки"] = None
    with pytest.raises(ThreatRefError, match="в кавычки"):
        parse(bad)
    bad = copy.deepcopy(_data())
    del bad["document"]
    with pytest.raises(ThreatRefError, match="документ-источник"):
        parse(bad)
    bad = copy.deepcopy(_data())
    bad["sections"][1]["items"][0]["children"] = ["x"]
    with pytest.raises(ThreatRefError, match="child_kind"):
        parse(bad)


# ---------- Загрузка ----------


@pytest.fixture
def ref_dir(tmp_path) -> Path:
    shutil.copytree(REFERENCE / "threats", tmp_path / "threats")
    (tmp_path / "profiles").mkdir()
    return tmp_path


def test_loader_is_idempotent_and_unverified(session, ref_dir):
    total = len(parse(_data()))
    r1 = load_reference(session, ref_dir)
    assert r1.threats_added == total
    r2 = load_reference(session, ref_dir)
    assert (r2.threats_added, r2.threats_updated, r2.threats_unchanged) == (0, 0, total)
    t = session.get(RefThreatItem, "Н2")
    assert t.origin == "stub" and t.verified_at is None and t.revision == 1


def test_loader_updates_changed_item_unless_edited_locally(session, ref_dir):
    load_reference(session, ref_dir)
    path = ref_dir / "threats/methodology-2021.yaml"
    data = _data()
    data["sections"][3]["items"][0]["title"] = "Разведка"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    report = load_reference(session, ref_dir)
    assert report.threats_updated == 1
    t = session.get(RefThreatItem, "Т1")
    assert (t.title, t.revision) == ("Разведка", 2)

    t.origin = "local"
    t.title = "Сбор сведений"
    session.commit()
    data["sections"][3]["items"][0]["title"] = "Разведка 2"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    report = load_reference(session, ref_dir)
    assert "threat:Т1" in report.local_conflicts
    assert session.get(RefThreatItem, "Т1").title == "Сбор сведений"
    # Конфликт показан один раз: файл больше не менялся.
    assert "threat:Т1" not in load_reference(session, ref_dir).local_conflicts


# ---------- API ----------


@pytest.fixture
def env(client, make_user, login, session, ref_dir):
    load_reference(session, ref_dir)
    make_user("admin", "admin", display_name="Администратор")
    make_user("meth", "methodologist", display_name="Иванова А. А.")
    make_user("viewer", "viewer", display_name="Наблюдатель")
    return {u: login(u) for u in ("admin", "meth", "viewer")}


def test_listing_groups_and_counts(client, env):
    r = client.get("/refs/threats", headers=env["viewer"])
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == body["unverified"] == len(body["items"])
    assert body["kinds"]["tactic"] == {"total": 10, "unverified": 10}
    assert body["kinds"]["technique"]["total"] == 0
    assert "Методика оценки угроз" in body["document"]["document"]
    codes = [i["code"] for i in body["items"]]
    assert codes.index("У1") < codes.index("У1.1") < codes.index("Н1") < codes.index("Т1")
    assert codes.index("У1.2") < codes.index("У1.10")
    detail = client.get("/refs/threats/НВ1", headers=env["viewer"]).json()
    assert detail["attrs"] == {"capability": "Н4", "category": "внешний"}
    assert detail["revisions"] == []
    assert client.get("/refs/threats/Х9", headers=env["viewer"]).status_code == 404


def test_edit_creates_revision_and_drops_verification(client, env, session):
    r = client.post("/refs/threats/Т2/verify", headers=env["meth"], json={"revision": 1})
    assert r.status_code == 200 and r.json()["verified"]
    assert r.json()["verified_by_name"] == "Иванова А. А."

    # Методист правит справочник не может (как меры и таблицы), администратор — может.
    patch = {"title": "Первоначальный доступ", "comment": "сверено с текстом"}
    assert client.patch("/refs/threats/Т2", headers=env["meth"], json=patch).status_code == 403
    r = client.patch("/refs/threats/Т2", headers=env["admin"], json=patch)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["title"] == "Первоначальный доступ"
    assert (body["revision"], body["origin"]) == (2, "local")
    assert not body["verified"]
    assert body["revisions"][0]["data"]["title"].startswith("Получение первоначального")
    assert body["revisions"][0]["comment"] == "сверено с текстом"

    # Неверный уровень возможностей нарушителя отклоняется.
    r = client.patch(
        "/refs/threats/НВ4",
        headers=env["admin"],
        json={"attrs": {"capability": "Н7"}, "comment": "x"},
    )
    assert r.status_code == 422 and "уровень возможностей" in r.json()["detail"]
    # Правка без изменений ревизию не создаёт.
    r = client.patch("/refs/threats/Н1", headers=env["admin"], json={"comment": "x"})
    assert r.json()["revision"] == 1

    actions = set(session.scalars(select(AuditRecord.action)))
    assert {"refs.threat.update", "refs.threat.verify"} <= actions


def test_add_technique_and_self_verification_forbidden(client, env, make_user, login):
    body = {
        "kind": "technique",
        "code": "Т1.1",
        "parent_code": "Т1",
        "title": "Сбор информации из публичных источников",
        "source": {"document": "Методика оценки угроз", "appendix": "11"},
        "comment": "по тексту приложения 11",
    }
    assert client.post("/refs/threats", headers=env["meth"], json=body).status_code == 403
    r = client.post("/refs/threats", headers=env["admin"], json=body)
    assert r.status_code == 201, r.text
    assert (r.json()["origin"], r.json()["position"]) == ("local", 1)
    assert client.post("/refs/threats", headers=env["admin"], json=body).status_code == 409

    wrong_parent = {**body, "code": "Т1.2", "parent_code": "У1"}
    r = client.post("/refs/threats", headers=env["admin"], json=wrong_parent)
    assert r.status_code == 422 and "Тактика" in r.json()["detail"]
    # Тактики заданы Методикой — не добавляются.
    tactic = {**body, "kind": "tactic", "code": "Т11", "parent_code": None}
    assert client.post("/refs/threats", headers=env["admin"], json=tactic).status_code == 422

    # Свою запись не сверить: у методиста с правом правки — отказ.
    make_user("meth2", "methodologist", "admin", display_name="Петров П. П.")
    h2 = login("meth2")
    r = client.post(
        "/refs/threats",
        headers=h2,
        json={**body, "code": "Т1.2", "title": "Ещё техника"},
    )
    assert r.status_code == 201
    r = client.post("/refs/threats/Т1.2/verify", headers=h2, json={"revision": 1})
    assert r.status_code == 403 and "собственную" in r.json()["detail"]
    r = client.post("/refs/threats/Т1.2/verify", headers=env["meth"], json={"revision": 2})
    assert r.status_code == 409
    r = client.post("/refs/threats/Т1.2/verify", headers=env["meth"], json={"revision": 1})
    assert r.status_code == 200 and r.json()["verified"]

    listing = client.get("/refs/threats", headers=env["viewer"]).json()
    assert listing["kinds"]["technique"] == {"total": 2, "unverified": 1}


def test_bulk_verify_reports_skipped(client, env):
    client.patch("/refs/threats/У2", headers=env["admin"], json={"title": "У2", "comment": "x"})
    items = [{"code": c, "revision": 1} for c in ("У1", "У2", "Х")]
    r = client.post("/refs/threats/verify", headers=env["viewer"], json={"items": items})
    assert r.status_code == 403
    r = client.post("/refs/threats/verify", headers=env["meth"], json={"items": items})
    assert r.status_code == 200
    assert r.json()["verified"] == ["У1"]
    assert set(r.json()["skipped"]) == {"У2", "Х"}
