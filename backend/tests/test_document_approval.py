"""Согласование и сравнение версий документов (задача 3.3)."""

import uuid

import pytest
from sqlalchemy import select, update

from app.db.models import AuditRecord, DocumentReview, GeneratedDocument
from tests.test_documents import (
    GIS_K2,
    _gen,
    _xml,
    docs_dir,  # noqa: F401 — фикстура
)
from tests.test_documents import env as docs_env  # noqa: F401 — фикстура


@pytest.fixture
def env(request):
    """Проект, объект ГИС с хостами и пользователи — как в тестах движка документов."""
    return request.getfixturevalue("docs_env")


PASSPORT = "tech-passport"


def _post(client, h, did, action, body=None, status=200):
    r = client.post(f"/documents/{did}/{action}", headers=h, json=body or {})
    assert r.status_code == status, r.text
    return r.json()


def _file(client, h, did):
    r = client.get(f"/documents/{did}/file", headers=h)
    assert r.status_code == 200, r.text
    return _xml(r.content)


def test_submit_return_approve_supersede(client, env, session):
    h, o, _ = env
    d1 = _gen(client, h["meth"], o["id"])
    full = client.get(f"/documents/{d1['id']}", headers=h["meth"]).json()
    assert full["actions"]["submit"] and not full["actions"]["approve"]
    assert full["reviews"] == [] and [s["version"] for s in full["siblings"]] == [1]

    # Эксперт не отправляет на согласование; утверждающий не утверждает проект.
    _post(client, h["expert"], d1["id"], "submit", status=403)
    _post(client, h["boss"], d1["id"], "approve", status=409)

    d = _post(client, h["meth"], d1["id"], "submit", {"comment": "Прошу согласовать"})
    assert d["status"] == "review" and d["status_title"] == "На согласовании"
    assert d["submitted_by_name"] == "Иванова А. А." and not d["actions"]["submit"]
    assert d["actions"]["send_back"]
    _post(client, h["meth"], d1["id"], "submit", status=409)  # уже на согласовании

    # Утверждающий видит, что может утвердить; методист — нет (нет права).
    b = client.get(f"/documents/{d1['id']}", headers=h["boss"]).json()
    assert b["actions"]["approve"] and b["actions"]["approve_blocker"] is None

    # Вернуть на доработку — только с причиной.
    _post(client, h["boss"], d1["id"], "return", {"comment": "  "}, status=422)
    d = _post(client, h["boss"], d1["id"], "return", {"comment": "Заполните границы"})
    assert d["status"] == "draft" and d["reviews"][-1]["comment"] == "Заполните границы"
    assert [r["action"] for r in d["reviews"]] == ["submit", "return"]

    _post(client, h["meth"], d1["id"], "submit")
    d = _post(client, h["boss"], d1["id"], "approve", {"comment": "Согласовано"})
    assert d["status"] == "approved" and d["approved_by_name"] == "Смирнов С. С."
    assert d["approval_comment"] == "Согласовано"
    assert not d["watermark"] and d["watermark_reasons"] == []
    xml = _file(client, h["meth"], d1["id"])
    assert "PowerPlusWaterMarkObject" not in xml and "Утверждён" in xml and "Смирнов С. С." in xml
    row = session.get(GeneratedDocument, uuid.UUID(d1["id"]))
    session.refresh(row)
    assert row.draft_docx_sha256 and row.draft_docx_sha256 != row.docx_sha256

    # Наблюдатель видит утверждённую версию.
    body = client.get(f"/objects/{o['id']}/documents", headers=h["viewer"]).json()
    t = next(t for t in body["types"] if t["code"] == PASSPORT)
    assert [v["version"] for v in t["versions"]] == [1] and t["approved"]["version"] == 1
    assert client.get(f"/documents/{d1['id']}/file", headers=h["viewer"]).status_code == 200

    # Те же данные — новая версия не нужна, остаётся утверждённая.
    assert _gen(client, h["meth"], o["id"])["id"] == d1["id"]

    # Новая версия: проект не виден наблюдателю; после утверждения v1 — «заменён».
    client.patch(f"/objects/{o['id']}", headers=h["meth"], json={"boundaries": "Здание 1"})
    d2 = _gen(client, h["meth"], o["id"])
    assert d2["version"] == 2 and d2["status"] == "draft"
    body = client.get(f"/objects/{o['id']}/documents", headers=h["viewer"]).json()
    t = next(t for t in body["types"] if t["code"] == PASSPORT)
    assert [v["version"] for v in t["versions"]] == [1]
    _post(client, h["meth"], d2["id"], "submit")
    _post(client, h["boss"], d2["id"], "approve")
    v1 = client.get(f"/documents/{d1['id']}", headers=h["viewer"]).json()
    assert v1["status"] == "superseded" and v1["status_title"] == "Заменён"
    assert v1["reviews"][-1]["action"] == "supersede"
    body = client.get(f"/objects/{o['id']}/documents", headers=h["viewer"]).json()
    t = next(t for t in body["types"] if t["code"] == PASSPORT)
    assert [v["status"] for v in t["versions"]] == ["approved", "superseded"]
    assert t["approved"]["version"] == 2

    actions = session.scalars(
        select(AuditRecord.action).where(AuditRecord.action.like("documents.%"))
    ).all()
    assert actions.count("documents.approve") == 2 and "documents.return" in actions


def test_no_self_approval(client, env, make_user, login, session):
    h, o, p = env
    # Методист с правом утверждения сформировал и отправил — утвердить сам не может.
    make_user("both", "methodologist", "approve", display_name="Двоих Д. Д.")
    hb = login("both")
    users = client.get("/directory/users", headers=h["meth"]).json()
    client.put(
        f"/projects/{p['id']}/members",
        headers=h["meth"],
        json={"user_ids": [u["id"] for u in users]},
    )
    d = _gen(client, hb, o["id"])
    _post(client, hb, d["id"], "submit")
    b = client.get(f"/documents/{d['id']}", headers=hb).json()
    assert not b["actions"]["approve"] and "сформировали" in b["actions"]["approve_blocker"]
    r = client.post(f"/documents/{d['id']}/approve", headers=hb, json={})
    assert r.status_code == 403 and r.headers["x-error-code"] == "self_approval"
    denied = session.scalars(
        select(AuditRecord).where(
            AuditRecord.action == "documents.approve", AuditRecord.result == "denied"
        )
    ).all()
    assert len(denied) == 1
    # Отправивший на согласование тоже не утверждает.
    _post(client, hb, d["id"], "return", {"comment": "отзываю"})
    session.execute(
        update(GeneratedDocument)
        .where(GeneratedDocument.id == uuid.UUID(d["id"]))
        .values(created_by=None)
    )
    session.commit()
    _post(client, hb, d["id"], "submit")
    r = client.post(f"/documents/{d['id']}/approve", headers=hb, json={})
    assert r.status_code == 403 and "отправили" in r.json()["detail"]
    _post(client, h["boss"], d["id"], "approve")


def test_new_version_returns_review_and_only_latest(client, env, session):
    h, o, _ = env
    d1 = _gen(client, h["meth"], o["id"])
    _post(client, h["meth"], d1["id"], "submit")
    client.patch(f"/objects/{o['id']}", headers=h["meth"], json={"boundaries": "Здание 2"})
    d2 = _gen(client, h["meth"], o["id"])
    v1 = client.get(f"/documents/{d1['id']}", headers=h["meth"]).json()
    assert v1["status"] == "draft" and "версия 2" in v1["reviews"][-1]["comment"]
    # Старую версию не отправить: согласуется последняя.
    r = client.post(f"/documents/{d1['id']}/submit", headers=h["meth"], json={})
    assert r.status_code == 409 and r.headers["x-error-code"] == "not_latest"
    assert not v1["actions"]["submit"]
    _post(client, h["meth"], d2["id"], "submit")
    n = session.scalar(
        select(DocumentReview.id).where(DocumentReview.document_id == uuid.UUID(d1["id"])).limit(1)
    )
    assert n is not None


def test_unverified_needs_ack_and_keeps_watermark(client, env):
    h, o, _ = env
    c = client.post(
        f"/objects/{o['id']}/classifications", headers=h["meth"], json={"inputs": GIS_K2}
    ).json()
    client.post(
        f"/classifications/{c['id']}/approve",
        headers=h["boss"],
        json={"acknowledge_unverified": True},
    )
    d = _gen(client, h["meth"], o["id"])
    assert d["unverified"]
    _post(client, h["meth"], d["id"], "submit")
    r = client.post(f"/documents/{d['id']}/approve", headers=h["boss"], json={})
    assert r.status_code == 409 and r.headers["x-error-code"] == "unverified_refs"
    a = _post(client, h["boss"], d["id"], "approve", {"acknowledge_unverified": True})
    assert a["status"] == "approved" and a["unverified_acknowledged"]
    assert a["watermark"] and a["watermark_reasons"] == [
        "Использованы записи справочников, не сверенные методистом"
    ]
    assert 'string="ПРОЕКТ"' in _file(client, h["meth"], d["id"])


def test_template_changed_blocks_approval(client, env, session):
    h, o, _ = env
    d = _gen(client, h["meth"], o["id"])
    _post(client, h["meth"], d["id"], "submit")
    session.execute(
        update(GeneratedDocument)
        .where(GeneratedDocument.id == uuid.UUID(d["id"]))
        .values(template_sha256="0" * 64)
    )
    session.commit()
    r = client.post(f"/documents/{d['id']}/approve", headers=h["boss"], json={})
    assert r.status_code == 409 and r.headers["x-error-code"] == "template_changed"


def test_archived_object_has_no_actions(client, env):
    h, o, _ = env
    d = _gen(client, h["meth"], o["id"])
    client.patch(f"/objects/{o['id']}", headers=h["meth"], json={"status": "archived"})
    full = client.get(f"/documents/{d['id']}", headers=h["meth"]).json()
    assert not any(v for k, v in full["actions"].items() if k != "approve_blocker")
    _post(client, h["meth"], d["id"], "submit", status=409)


def test_compare_versions(client, env):
    h, o, _ = env
    d1 = _gen(client, h["meth"], o["id"])
    client.patch(f"/objects/{o['id']}", headers=h["meth"], json={"boundaries": "Здание 1"})
    client.put(
        f"/objects/{o['id']}/hosts",
        headers=h["meth"],
        json={
            "items": [
                {"address": "10.0.0.1", "hostname": "web", "role": "Веб-сервер"},
                {"address": "10.0.0.2", "role": "СУБД"},
                {"address": "10.0.0.3", "hostname": "arm"},
            ]
        },
    )
    d2 = _gen(client, h["meth"], o["id"])
    r = client.get(f"/documents/{d2['id']}/compare?with={d1['id']}", headers=h["meth"])
    assert r.status_code == 200, r.text
    c = r.json()
    assert c["old"]["version"] == 1 and c["new"]["version"] == 2  # порядок по версии
    f = {x["key"]: x for x in c["fields"]}
    b = f["object.boundaries"]
    assert b["before"] is None and b["after"] == "Здание 1"
    assert f["object.boundaries"]["state_before"] == "empty"
    assert "hosts[].role" in f
    lines = [ln for hk in c["hunks"] for ln in hk["lines"]]
    added = [ln["text"] for ln in lines if ln["op"] == "add"]
    removed = [ln["text"] for ln in lines if ln["op"] == "del"]
    assert any("Здание 1" in t for t in added)
    assert any("[не заполнено: Границы объекта]" in t for t in removed)
    assert any("10.0.0.3" in t for t in added)
    assert c["added"] >= 3 and c["removed"] >= 1 and not c["truncated"]
    assert any("Версия 2" in t for t in added)  # титул

    # Разные документы не сравниваются; проекты не видны наблюдателю.
    other = _gen(client, h["meth"], o["id"], "classification-act")
    r = client.get(f"/documents/{d2['id']}/compare?with={other['id']}", headers=h["meth"])
    assert r.status_code == 422
    r = client.get(f"/documents/{d2['id']}/compare?with={d1['id']}", headers=h["viewer"])
    assert r.status_code == 404
