import shutil
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select

from app.db.models import AuditRecord, RefMeasure, RefRevision
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"


@pytest.fixture
def ref_dir(tmp_path) -> Path:
    shutil.copytree(REFERENCE / "profiles", tmp_path / "profiles")
    return tmp_path


@pytest.fixture
def loaded(session, ref_dir):
    load_reference(session, ref_dir)
    return ref_dir


def _rewrite(path: Path, fn) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    fn(data)
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")


def test_load_is_idempotent_and_unverified(session, ref_dir):
    r1 = load_reference(session, ref_dir)
    assert r1.added > 300 and r1.checks > 30
    r2 = load_reference(session, ref_dir)
    assert (r2.added, r2.updated) == (0, 0)
    m = session.get(RefMeasure, ("fstec-117", "ИАФ.1"))
    assert m.origin == "scanner" and m.verified_at is None
    assert m.kind == "technical" and "К2" in m.levels
    assert session.get(RefMeasure, ("fstec-117", "ВУ")).kind == "organizational"
    assert session.scalars(select(AuditRecord.action)).all() == ["refs.load"]


def test_file_change_updates_scanner_measure_and_keeps_history(session, loaded):
    def rename(data):
        data["groups"][1]["controls"][0]["title"] = "Идентификация пользователей (новое)"

    _rewrite(loaded / "profiles" / "fstec-117.yaml", rename)
    report = load_reference(session, loaded)
    assert report.updated == 1
    m = session.get(RefMeasure, ("fstec-117", "ИАФ.1"))
    assert m.title.endswith("(новое)") and m.revision == 2
    rev = session.scalars(select(RefRevision)).one()
    assert rev.data["title"] == "Идентификация пользователей"


def test_local_edit_wins_over_file(client, make_user, login, session, loaded):
    make_user("admin", "admin")
    r = client.patch(
        "/refs/measures/fstec-117/ИАФ.1",
        headers=login("admin"),
        json={"title": "Своя формулировка", "comment": "по тексту приказа"},
    )
    assert r.status_code == 200, r.text

    def rename(data):
        data["groups"][1]["controls"][0]["title"] = "Из файла"

    _rewrite(loaded / "profiles" / "fstec-117.yaml", rename)
    session.expire_all()
    report = load_reference(session, loaded)
    assert report.local_conflicts == ["fstec-117:ИАФ.1"]
    assert session.get(RefMeasure, ("fstec-117", "ИАФ.1")).title == "Своя формулировка"


def test_profiles_and_filters(client, make_user, login, loaded):
    make_user("m", "methodologist")
    h = login("m")
    profiles = client.get("/refs/profiles", headers=h).json()
    assert [p["id"] for p in profiles][:3] == ["fstec-117", "fstec-21", "fstec-239"]
    p117 = profiles[0]
    assert p117["unverified"] == p117["total"] > 0
    assert p117["groups"][0]["code"] == "МРП"

    r = client.get("/refs/measures?profile=fstec-117&group=ИАФ", headers=h)
    assert [m["id"] for m in r.json()] == ["ИАФ.1", "ИАФ.2", "ИАФ.3", "ИАФ.4"]
    org = client.get("/refs/measures?profile=fstec-117&kind=organizational&group=МРП", headers=h)
    assert "ВУ" in [m["id"] for m in org.json()]
    k1_only = client.get("/refs/measures?profile=fstec-117&group=ИАФ&level=К1", headers=h).json()
    assert "ИАФ.2" not in [m["id"] for m in k1_only]

    d = client.get("/refs/measures/fstec-117/ИАФ.1", headers=h).json()
    assert d["check_details"][0]["title"]
    assert d["source"]["document"] == "ФСТЭК №117"


def test_edit_then_verify_by_other_person(client, make_user, login, session, loaded):
    make_user("admin", "admin")
    make_user("m", "methodologist", display_name="Иванова А. А.")
    ha, hm = login("admin"), login("m")

    # Методист правит справочник? Нет — правка у администратора.
    r = client.patch(
        "/refs/measures/fstec-117/ИАФ.2", headers=hm, json={"title": "x", "comment": "y"}
    )
    assert r.status_code == 403
    # Администратор сверять не может.
    assert (
        client.post(
            "/refs/measures/fstec-117/ИАФ.2/verify", headers=ha, json={"revision": 1}
        ).status_code
        == 403
    )

    r = client.patch(
        "/refs/measures/fstec-117/ИАФ.2",
        headers=ha,
        json={
            "levels": ["К1"],
            "comment": "приложение №2, столбец 1",
            "source": {"document": "Методический документ от 12.04.2026", "appendix": "2"},
        },
    )
    assert r.json()["revision"] == 2 and r.json()["origin"] == "local"
    assert (
        client.patch(
            "/refs/measures/fstec-117/ИАФ.2", headers=ha, json={"levels": ["К9"], "comment": "x"}
        ).status_code
        == 422
    )

    # Сверка устаревшей ревизии — конфликт.
    assert (
        client.post(
            "/refs/measures/fstec-117/ИАФ.2/verify", headers=hm, json={"revision": 1}
        ).status_code
        == 409
    )
    r = client.post("/refs/measures/fstec-117/ИАФ.2/verify", headers=hm, json={"revision": 2})
    assert r.json()["verified"] and r.json()["verified_by_name"] == "Иванова А. А."

    # Новая правка снимает сверку.
    r = client.patch(
        "/refs/measures/fstec-117/ИАФ.2",
        headers=ha,
        json={"title": "Идентификация и аутентификация устройств", "comment": "z"},
    )
    assert r.json()["verified"] is False
    d = client.get("/refs/measures/fstec-117/ИАФ.2", headers=hm).json()
    assert [x["revision"] for x in d["revisions"]] == [2, 1]
    assert d["revisions"][0]["data"]["verified_by_name"] == "Иванова А. А."
