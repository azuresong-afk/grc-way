"""Классификация: таблицы как данные, расчёт, черновик → утверждение без самоутверждения."""

import copy
import shutil
import uuid
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.db.models import AuditRecord, Classification, RefClassificationTable
from app.domain.classification import (
    InputError,
    TableError,
    compute,
    gaps,
    input_space,
    validate,
)
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"
TABLE_FILES = sorted((REFERENCE / "classification").glob("*.yaml"))
META = {"regime", "title", "version", "origin", "source"}

GIS_K2 = {
    "damage_confidentiality": "medium",
    "damage_integrity": "low",
    "damage_availability": "low",
    "scale": "regional",
}


def _definition(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if k not in META}


# ---------- Движок ----------


@pytest.mark.parametrize("path", TABLE_FILES, ids=lambda p: p.stem)
def test_reference_tables_are_valid_and_complete(path):
    d = _definition(path)
    validate(d)
    # Каждое сочетание исходных данных даёт результат: в таблице нет «дыр».
    assert gaps(d) == []
    allowed = {v["value"] for v in d["result"]["values"]}
    assert {compute(d, combo).result for combo in input_space(d)} <= allowed


def test_gis_trace_shows_matched_rows():
    out = compute(_definition(REFERENCE / "classification/gis-117.yaml"), GIS_K2)
    assert out.result == "К2"
    assert out.values == {"significance": "УЗ2", "class": "К2"}
    assert [t.row_id for t in out.trace] == ["uz2-c", "k-uz2-reg"]
    assert out.trace[1].matched == {"significance": "УЗ2", "scale": "regional"}


def test_ispdn_rows_follow_table():
    d = _definition(REFERENCE / "classification/ispdn-21.yaml")
    cases = {
        ("1", "public", "employees"): "УЗ2",
        ("2", "special", "gt100k"): "УЗ1",
        ("2", "public", "gt100k"): "УЗ3",
        ("3", "other", "gt100k"): "УЗ3",
        ("3", "other", "lt100k"): "УЗ4",
    }
    for (threat, cat, subj), want in cases.items():
        got = compute(d, {"threat_type": threat, "category": cat, "subjects": subj})
        assert got.result == want, (threat, cat, subj)


def test_kii_takes_most_severe_category():
    d = _definition(REFERENCE / "classification/kii-239.yaml")
    base = dict.fromkeys(["social", "political", "economic", "ecological", "defense"], "none")
    assert compute(d, base).result == "none"
    out = compute(d, {**base, "economic": "3", "social": "2"})
    assert out.result == "2"
    assert out.trace[0].matched == {"social": "2"}


def test_compute_rejects_bad_inputs():
    d = _definition(REFERENCE / "classification/gis-117.yaml")
    with pytest.raises(InputError, match="Не заполнено"):
        compute(d, {**GIS_K2, "scale": ""})
    with pytest.raises(InputError, match="Недопустимое"):
        compute(d, {**GIS_K2, "scale": "planet"})
    with pytest.raises(InputError, match="Лишние"):
        compute(d, {**GIS_K2, "extra": "x"})


def test_validate_catches_mistakes():
    d = _definition(REFERENCE / "classification/gis-117.yaml")
    bad = copy.deepcopy(d)
    bad["steps"][1]["rows"][0]["when"]["scale"] = ["planet"]
    with pytest.raises(TableError, match="нет значения"):
        validate(bad)
    bad = copy.deepcopy(d)
    bad["steps"][1]["rows"][0]["value"] = "К9"
    with pytest.raises(TableError, match="вне итога"):
        validate(bad)
    bad = copy.deepcopy(d)
    bad["steps"][0]["method"] = "magic"
    with pytest.raises(TableError, match="неизвестный способ"):
        validate(bad)


# ---------- Загрузка ----------


@pytest.fixture
def ref_dir(tmp_path) -> Path:
    shutil.copytree(REFERENCE / "classification", tmp_path / "classification")
    (tmp_path / "profiles").mkdir()
    return tmp_path


def test_loader_is_idempotent_and_unverified(session, ref_dir):
    r1 = load_reference(session, ref_dir)
    assert r1.tables_added == 3
    r2 = load_reference(session, ref_dir)
    assert (r2.tables_added, r2.tables_updated, r2.tables_unchanged) == (0, 0, 3)
    t = session.get(RefClassificationTable, "117")
    assert t.origin == "stub" and t.verified_at is None and t.revision == 1


def test_loader_updates_changed_file_unless_edited_locally(session, ref_dir):
    load_reference(session, ref_dir)
    path = ref_dir / "classification/gis-117.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["version"] = "117-stub-2"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    assert load_reference(session, ref_dir).tables_updated == 1
    t = session.get(RefClassificationTable, "117")
    assert (t.version, t.revision) == ("117-stub-2", 2)

    t.origin = "local"
    session.commit()
    data["version"] = "117-stub-3"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    report = load_reference(session, ref_dir)
    assert "classification:117" in report.local_conflicts
    assert session.get(RefClassificationTable, "117").version == "117-stub-2"


# ---------- API ----------


@pytest.fixture
def env(client, make_user, login, session, ref_dir):
    load_reference(session, ref_dir)
    make_user("admin", "admin", display_name="Администратор")
    make_user("meth", "methodologist", display_name="Иванова А. А.")
    make_user("meth2", "methodologist", "approve", display_name="Петров П. П.")
    make_user("boss", "viewer", "approve", display_name="Смирнов С. С.")
    make_user("viewer", "viewer", display_name="Наблюдатель")
    h = {u: login(u) for u in ("admin", "meth", "meth2", "boss", "viewer")}
    c = client.post("/customers", headers=h["meth"], json={"name": "ГБУ «Центр»"}).json()
    p = client.post(
        "/projects", headers=h["meth"], json={"customer_id": c["id"], "name": "Аттестация"}
    ).json()
    users = client.get("/directory/users", headers=h["meth"]).json()
    r = client.put(
        f"/projects/{p['id']}/members",
        headers=h["meth"],
        json={"user_ids": [u["id"] for u in users]},
    )
    assert r.status_code == 200, r.text
    o = client.post(
        f"/projects/{p['id']}/objects", headers=h["meth"], json={"kind": "gis", "name": "ГИС"}
    ).json()
    return h, o


def _create(client, h, obj_id, inputs=GIS_K2, **extra):
    r = client.post(
        f"/objects/{obj_id}/classifications", headers=h, json={"inputs": inputs, **extra}
    )
    assert r.status_code == 201, r.text
    return r.json()


def test_preview_and_create_draft_with_trace(client, env, session):
    h, o = env
    r = client.post(
        f"/objects/{o['id']}/classifications/preview", headers=h["meth"], json={"inputs": GIS_K2}
    )
    assert r.status_code == 200, r.text
    assert r.json()["result"] == "К2"
    assert r.json()["trace"][1]["source"]["document"].startswith("Приказ ФСТЭК")
    # Наблюдатель считать не может.
    r = client.post(
        f"/objects/{o['id']}/classifications/preview", headers=h["viewer"], json={"inputs": GIS_K2}
    )
    assert r.status_code == 403

    c = _create(client, h["meth"], o["id"], justification="По данным заказчика")
    assert c["status"] == "draft" and c["result"] == "К2" and c["reproducible"]
    assert c["table_version"] == "117-stub-1" and c["table_revision"] == 1
    assert not c["table_verified"]
    rec = session.scalars(select(AuditRecord).where(AuditRecord.action == "classification.create"))
    assert rec.one().details["rows"] == ["uz2-c", "k-uz2-reg"]

    obj = client.get(f"/objects/{o['id']}", headers=h["viewer"]).json()
    assert obj["classification"] == {
        "id": c["id"],
        "result": "К2",
        "short": "К2",
        "result_label": "К2 — второй класс",
        "status": "draft",
    }

    bad = client.post(
        f"/objects/{o['id']}/classifications",
        headers=h["meth"],
        json={"inputs": {**GIS_K2, "scale": "planet"}},
    )
    assert bad.status_code == 422


def test_new_draft_replaces_previous_draft(client, env):
    h, o = env
    first = _create(client, h["meth"], o["id"])
    second = _create(client, h["meth"], o["id"], inputs={**GIS_K2, "scale": "object"})
    items = client.get(f"/objects/{o['id']}/classifications", headers=h["meth"]).json()
    by_id = {c["id"]: c for c in items}
    assert by_id[first["id"]]["status"] == "superseded"
    assert by_id[second["id"]]["status"] == "draft"


def test_self_approval_is_forbidden_and_logged(client, env, session):
    h, o = env
    c = _create(client, h["meth2"], o["id"])
    r = client.post(
        f"/classifications/{c['id']}/approve",
        headers=h["meth2"],
        json={"acknowledge_unverified": True},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == "Нельзя утвердить собственный расчёт"
    denied = session.scalars(
        select(AuditRecord).where(
            AuditRecord.action == "classification.approve", AuditRecord.result == "denied"
        )
    ).one()
    assert denied.details == {"reason": "self_approval"}
    # Без права approve — 403 до любых проверок.
    r = client.post(f"/classifications/{c['id']}/approve", headers=h["meth"], json={})
    assert r.status_code == 403


def test_approval_requires_ack_for_unverified_table_and_supersedes(client, env, session):
    h, o = env
    c = _create(client, h["meth"], o["id"])
    r = client.post(f"/classifications/{c['id']}/approve", headers=h["boss"], json={})
    assert r.status_code == 409
    assert r.headers["X-Error-Code"] == "unverified_table"

    r = client.post(
        f"/classifications/{c['id']}/approve",
        headers=h["boss"],
        json={"acknowledge_unverified": True, "comment": "Согласовано"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "approved" and body["approved_by_name"] == "Смирнов С. С."
    assert body["unverified_acknowledged"]
    rec = session.scalars(
        select(AuditRecord).where(
            AuditRecord.action == "classification.approve", AuditRecord.result == "ok"
        )
    ).one()
    assert rec.details["result"] == "К2" and rec.details["unverified_acknowledged"] is True

    # Повторно утвердить нельзя; новая утверждённая заменяет прежнюю, история сохраняется.
    again = client.post(f"/classifications/{c['id']}/approve", headers=h["boss"], json={})
    assert again.status_code == 409
    c2 = _create(client, h["meth"], o["id"], inputs={**GIS_K2, "damage_integrity": "high"})
    assert c2["result"] == "К1"
    obj = client.get(f"/objects/{o['id']}", headers=h["meth"]).json()
    assert obj["classification"]["status"] == "approved"  # черновик не вытесняет утверждённую
    r = client.post(
        f"/classifications/{c2['id']}/approve",
        headers=h["boss"],
        json={"acknowledge_unverified": True},
    )
    assert r.status_code == 200
    items = {
        x["id"]: x
        for x in client.get(f"/objects/{o['id']}/classifications", headers=h["meth"]).json()
    }
    assert items[c["id"]]["status"] == "superseded"
    assert items[c2["id"]]["status"] == "approved"


def test_table_edit_blocks_approval_but_old_result_reproduces(client, env):
    h, o = env
    c = _create(client, h["meth"], o["id"])
    table = client.get("/refs/classification-tables/117", headers=h["admin"]).json()
    d = copy.deepcopy(table["definition"])
    row = next(r for r in d["steps"][1]["rows"] if r["id"] == "k-uz2-reg")
    row["value"] = "К1"
    r = client.patch(
        "/refs/classification-tables/117",
        headers=h["admin"],
        json={"definition": d, "comment": "Сверка с текстом №117"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["revision"] == 2 and r.json()["origin"] == "local"
    assert r.json()["revisions"][0]["comment"] == "Сверка с текстом №117"

    detail = client.get(f"/classifications/{c['id']}", headers=h["meth"]).json()
    assert detail["table_changed"] and detail["reproducible"] and detail["result"] == "К2"
    r = client.post(
        f"/classifications/{c['id']}/approve",
        headers=h["boss"],
        json={"acknowledge_unverified": True},
    )
    assert r.status_code == 409 and "пересчитайте" in r.json()["detail"]
    # Новый расчёт идёт по новой ревизии.
    c2 = _create(client, h["meth"], o["id"])
    assert (c2["result"], c2["table_revision"]) == ("К1", 2)


def test_table_edit_rules_and_verification(client, env, session):
    h, _ = env
    table = client.get("/refs/classification-tables/117", headers=h["meth"]).json()
    # Методист правит таблицу не может (как и меры), но сверяет.
    r = client.patch(
        "/refs/classification-tables/117",
        headers=h["meth"],
        json={"version": "x", "comment": "x"},
    )
    assert r.status_code == 403
    bad = copy.deepcopy(table["definition"])
    bad["steps"][1]["rows"][0]["value"] = "К9"
    r = client.patch(
        "/refs/classification-tables/117",
        headers=h["admin"],
        json={"definition": bad, "comment": "ошибка"},
    )
    assert r.status_code == 422 and "вне итога" in r.json()["detail"]

    r = client.post(
        "/refs/classification-tables/117/verify", headers=h["meth"], json={"revision": 9}
    )
    assert r.status_code == 409
    r = client.post(
        "/refs/classification-tables/117/verify", headers=h["meth"], json={"revision": 1}
    )
    assert r.status_code == 200 and r.json()["verified"]
    assert r.json()["verified_by_name"] == "Иванова А. А."

    # Сверенная таблица: утверждение без подтверждения.
    _, o = env
    c = _create(client, h["meth"], o["id"])
    assert c["table_verified"]
    r = client.post(f"/classifications/{c['id']}/approve", headers=h["boss"], json={})
    assert r.status_code == 200 and not r.json()["unverified_acknowledged"]

    # Правка снимает отметку о сверке.
    r = client.patch(
        "/refs/classification-tables/117",
        headers=h["admin"],
        json={
            "source": {"document": "Приказ ФСТЭК России №117", "clause": "п. 9"},
            "comment": "п.",
        },
    )
    assert r.status_code == 200 and not r.json()["verified"]

    listing = client.get("/refs/classification-tables", headers=h["viewer"]).json()
    assert [t["regime"] for t in listing] == ["117", "21", "239"]
    assert all(t["gaps"] == 0 for t in listing)


def test_other_object_and_outsider(client, env, make_user, login):
    h, o = env
    p = o["project_id"]
    other = client.post(
        f"/projects/{p}/objects", headers=h["meth"], json={"kind": "other", "name": "Сайт"}
    ).json()
    r = client.post(
        f"/objects/{other['id']}/classifications", headers=h["meth"], json={"inputs": GIS_K2}
    )
    assert r.status_code == 409
    c = _create(client, h["meth"], o["id"])
    make_user("stranger", "methodologist", "approve")
    hs = login("stranger")
    assert client.get(f"/classifications/{c['id']}", headers=hs).status_code == 404
    assert (
        client.post(f"/classifications/{c['id']}/approve", headers=hs, json={}).status_code == 404
    )


def test_db_forbids_self_approval(client, env, session):
    h, o = env
    c = _create(client, h["meth"], o["id"])
    row = session.get(Classification, uuid.UUID(c["id"]))
    with pytest.raises(IntegrityError):
        session.execute(
            update(Classification)
            .where(Classification.id == row.id)
            .values(approved_by=row.created_by)
        )
        session.flush()
    session.rollback()
