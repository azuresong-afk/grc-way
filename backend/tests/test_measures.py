"""Набор мер объекта: базовый по классу, адаптация, утверждение, процент."""

import shutil
from pathlib import Path

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.db.models import Adaptation, AuditRecord, ObjectMeasure
from app.domain.measures import Current, Item, RefItem, compute_stats, plan
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"
GIS_K2 = {
    "damage_confidentiality": "medium",
    "damage_integrity": "low",
    "damage_availability": "low",
    "scale": "regional",
}
GIS_K3 = {**GIS_K2, "damage_confidentiality": "low", "scale": "object"}


# ---------- Процент ----------


def test_percent_counts_partial_and_skips_excluded_and_na():
    items = [
        Item("A", "auto", "implemented"),
        Item("B", "auto", "partial"),
        Item("C", "manual", "not_implemented"),
        Item("D", "manual", "unassessed"),
        Item("E", "manual", "implemented", "excluded"),
        Item("F", "auto", "not_applicable"),
    ]
    s = compute_stats(items)
    assert (s.total.total, s.total.excluded, s.total.not_applicable) == (4, 1, 1)
    assert s.total.score == 1.5 and s.total.percent == 37.5
    assert s.auto.percent == 75.0 and s.manual.percent == 0.0
    assert s.total.unassessed == 1
    assert compute_stats(items, partial_weight=0).total.percent == 25.0


def test_compensated_measure_takes_worst_of_compensating():
    base = [Item("X", "auto", "implemented"), Item("Y", "manual", "partial")]
    comp = Item("C", "auto", "not_implemented", "compensated", ("X", "Y"))
    s = compute_stats([*base, comp])
    # C считается как «Частично» (худшее из X и Y), а не по своему статусу.
    assert s.total.total == 3 and s.total.compensated == 1
    assert s.total.partial == 2 and s.total.implemented == 1
    # Компенсирующая пропала — мера не закрыта.
    gone = Item("C", "auto", "implemented", "compensated", ("Z",))
    assert compute_stats([gone]).total.not_implemented == 1
    assert compute_stats([]).total.percent is None


def test_plan_follows_levels():
    refs = [
        RefItem("A", "G", "a", ("К1", "К2", "К3")),
        RefItem("B", "G", "b", ("К1", "К2")),
        RefItem("C", "G", "c", ()),
    ]
    p = plan(refs, "К2", "p", [])
    assert p.add == ["A", "B"] and not p.remove
    cur = [
        Current("A", "p", "baseline", "none", (), False),
        Current("B", "p", "baseline", "none", (), True),
        Current("C", "p", "added", "compensated", ("B",), False),
    ]
    p = plan(refs, "К3", "p", cur)
    assert p.remove == ["B"] and p.reset == ["C"] and p.unchanged == 2
    # Дополненная мера, вошедшая в базовый набор, становится базовой.
    p = plan(refs, "К2", "p", [Current("B", "p", "added", "none", (), False)])
    assert p.promote == ["B"] and p.add == ["A"]


# ---------- API ----------


@pytest.fixture
def env(client, make_user, login, session, tmp_path):
    shutil.copytree(REFERENCE, tmp_path / "reference")
    load_reference(session, tmp_path / "reference")
    make_user("meth", "methodologist", display_name="Иванова А. А.")
    make_user("meth2", "methodologist", "approve", display_name="Петров П. П.")
    make_user("boss", "viewer", "approve", display_name="Смирнов С. С.")
    make_user("exp", "assessor", display_name="Козлов К. К.")
    make_user("viewer", "viewer", display_name="Наблюдатель")
    h = {u: login(u) for u in ("meth", "meth2", "boss", "exp", "viewer")}
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
        f"/projects/{p['id']}/objects", headers=h["meth"], json={"kind": "gis", "name": "ГИС"}
    ).json()
    return h, o, {u["display_name"]: u["id"] for u in users}


def _classify(client, h, oid, inputs=GIS_K2):
    c = client.post(f"/objects/{oid}/classifications", headers=h["meth"], json={"inputs": inputs})
    assert c.status_code == 201, c.text
    r = client.post(
        f"/classifications/{c.json()['id']}/approve",
        headers=h["boss"],
        json={"acknowledge_unverified": True},
    )
    assert r.status_code == 200, r.text
    return r.json()


def _build(client, h, oid):
    r = client.post(f"/objects/{oid}/measures/rebuild", headers=h["meth"], json={"dry_run": False})
    assert r.status_code == 200, r.text
    return r.json()


def _measures(client, h, oid, **params):
    r = client.get(f"/objects/{oid}/measures", headers=h["viewer"], params=params)
    assert r.status_code == 200, r.text
    return {m["measure_id"]: m for m in r.json()}


def _set(client, h, oid):
    r = client.get(f"/objects/{oid}/measure-set", headers=h["viewer"])
    assert r.status_code == 200, r.text
    return r.json()


def test_baseline_requires_approved_class(client, env):
    h, o, _ = env
    assert _set(client, h, o["id"])["state"] == "no_class"
    r = client.post(f"/objects/{o['id']}/measures/rebuild", headers=h["meth"], json={})
    assert r.status_code == 409
    assert "утвердите классификацию" in r.json()["detail"]
    # Черновик классификации не годится.
    client.post(f"/objects/{o['id']}/classifications", headers=h["meth"], json={"inputs": GIS_K2})
    r = client.post(f"/objects/{o['id']}/measures/rebuild", headers=h["meth"], json={})
    assert r.status_code == 409


def test_rebuild_plan_then_apply_by_class(client, env, session):
    h, o, _ = env
    _classify(client, h, o["id"])
    assert _set(client, h, o["id"])["state"] == "not_built"

    dry = client.post(f"/objects/{o['id']}/measures/rebuild", headers=h["meth"], json={})
    assert dry.status_code == 200
    assert dry.json()["level"] == "К2" and len(dry.json()["add"]) == 104
    assert session.scalars(select(ObjectMeasure)).first() is None  # только план

    # Эксперт и наблюдатель набор не собирают.
    for who in ("exp", "viewer"):
        r = client.post(f"/objects/{o['id']}/measures/rebuild", headers=h[who], json={})
        assert r.status_code == 403

    _build(client, h, o["id"])
    ms = _measures(client, h, o["id"])
    assert len(ms) == 104
    assert ms["КК"]["method"] == "auto" and ms["ВУ"]["method"] == "manual"
    assert "ИАФ.2" not in ms  # levels: [] — вне базового набора
    assert all(m["origin"] == "baseline" and m["status"] == "unassessed" for m in ms.values())
    assert not ms["КК"]["verified"]

    s = _set(client, h, o["id"])
    assert s["state"] == "built" and not s["rebuild_needed"]
    assert s["adaptation"]["status"] == "draft" and s["adaptation"]["version"] == 1
    assert s["stats"]["total"]["total"] == 104 and s["stats"]["total"]["percent"] == 0
    assert s["unverified"] == 104

    # Повторная сборка без изменений ничего не меняет.
    again = _build(client, h, o["id"])
    assert again["empty"] and not again["changes"]
    assert len(session.scalars(select(Adaptation)).all()) == 1

    # Новый класс К3: три меры уходят из базового набора.
    _classify(client, h, o["id"], GIS_K3)
    s = _set(client, h, o["id"])
    assert s["class_changed"] and s["rebuild_needed"]
    assert s["plan_counts"]["remove"] == 3
    out = _build(client, h, o["id"])
    assert sorted(x["measure_id"] for x in out["remove"]) == ["ЗОО.6", "ЗСВ.9", "УПД.7"]
    assert len(_measures(client, h, o["id"])) == 101
    assert _set(client, h, o["id"])["adaptation"]["version"] == 2
    rec = session.scalars(select(AuditRecord).where(AuditRecord.action == "measures.rebuild")).all()
    assert len(rec) == 2 and rec[1].details["level"] == "К3"


def test_adaptation_changes_percent(client, env):
    h, o, _ = env
    _classify(client, h, o["id"])
    _build(client, h, o["id"])
    ms = _measures(client, h, o["id"])

    # Эксперт отмечает две меры реализованными, одну частично.
    for mid, st in (("КК", "implemented"), ("КУ", "implemented"), ("КО", "partial")):
        r = client.patch(f"/object-measures/{ms[mid]['id']}", headers=h["exp"], json={"status": st})
        assert r.status_code == 200, r.text
    total = _set(client, h, o["id"])["stats"]["total"]
    assert total["total"] == 104 and total["score"] == 2.5
    assert total["percent"] == round(2.5 / 104 * 100, 1)

    # Методист не ставит статусы, эксперт не адаптирует.
    r = client.patch(
        f"/object-measures/{ms['КК']['id']}", headers=h["meth"], json={"status": "partial"}
    )
    assert r.status_code == 403
    r = client.patch(
        f"/object-measures/{ms['ВУ']['id']}",
        headers=h["exp"],
        json={"adaptation": "excluded", "adaptation_reason": "x"},
    )
    assert r.status_code == 403

    # Исключение без обоснования — нельзя.
    r = client.patch(
        f"/object-measures/{ms['ВУ']['id']}", headers=h["meth"], json={"adaptation": "excluded"}
    )
    assert r.status_code == 422 and "обоснование" in r.json()["detail"]
    r = client.patch(
        f"/object-measures/{ms['ВУ']['id']}",
        headers=h["meth"],
        json={"adaptation": "excluded", "adaptation_reason": "Угрозы не актуальны (модель угроз)"},
    )
    assert r.status_code == 200, r.text
    total = _set(client, h, o["id"])["stats"]["total"]
    assert total["total"] == 103 and total["excluded"] == 1
    assert total["percent"] == round(2.5 / 103 * 100, 1)

    # Компенсация: УД закрывается мерами КК и КО → считается как «Частично».
    r = client.patch(
        f"/object-measures/{ms['УД']['id']}",
        headers=h["meth"],
        json={
            "adaptation": "compensated",
            "adaptation_reason": "Удалённого доступа нет, компенсируется контролем конфигураций",
            "compensating_ids": ["КК", "КО"],
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["effective_status"] == "partial"
    total = _set(client, h, o["id"])["stats"]["total"]
    assert total["score"] == 3.0 and total["compensated"] == 1
    assert _measures(client, h, o["id"])["КК"]["compensates"] == ["УД"]

    # Компенсирующую нельзя исключить, пока на неё опираются.
    r = client.patch(
        f"/object-measures/{ms['КК']['id']}",
        headers=h["meth"],
        json={"adaptation": "excluded", "adaptation_reason": "…"},
    )
    assert r.status_code == 409 and "УД" in r.json()["detail"]
    # Исключённая мера не может компенсировать.
    r = client.patch(
        f"/object-measures/{ms['МУ']['id']}",
        headers=h["meth"],
        json={
            "adaptation": "compensated",
            "adaptation_reason": "…",
            "compensating_ids": ["ВУ"],
        },
    )
    assert r.status_code == 422 and "исключена" in r.json()["detail"]

    # Дополнение: мера вне базового набора, с обоснованием.
    r = client.post(
        f"/objects/{o['id']}/measures",
        headers=h["meth"],
        json={"measure_id": "ИАФ.2", "reason": ""},
    )
    assert r.status_code == 422
    r = client.post(
        f"/objects/{o['id']}/measures",
        headers=h["meth"],
        json={"measure_id": "ИАФ.2", "reason": "Мобильные устройства в контуре"},
    )
    assert r.status_code == 201, r.text
    added = r.json()
    assert added["origin"] == "added" and added["levels"] == []
    assert _set(client, h, o["id"])["stats"]["total"]["total"] == 104
    dup = client.post(
        f"/objects/{o['id']}/measures",
        headers=h["meth"],
        json={"measure_id": "ИАФ.2", "reason": "ещё раз"},
    )
    assert dup.status_code == 409
    # Базовую меру не удаляют, дополненную — можно.
    assert client.delete(f"/object-measures/{ms['ВУ']['id']}", headers=h["meth"]).status_code == 409
    assert client.delete(f"/object-measures/{added['id']}", headers=h["meth"]).status_code == 204

    # Отмена исключения возвращает меру в знаменатель.
    r = client.patch(
        f"/object-measures/{ms['ВУ']['id']}", headers=h["meth"], json={"adaptation": "none"}
    )
    assert r.status_code == 200 and r.json()["adaptation_reason"] is None
    assert _set(client, h, o["id"])["stats"]["total"]["total"] == 104

    # Фильтры списка.
    assert set(_measures(client, h, o["id"], adaptation="compensated")) == {"УД"}
    assert set(_measures(client, h, o["id"], status="partial")) == {"КО"}
    assert "КК" in _measures(client, h, o["id"], q="кк")


def test_approve_adaptation_rules(client, env, session):
    h, o, _ = env
    _classify(client, h, o["id"])
    # Собирает и правит Петров (у него есть approve) — утвердить сам не может.
    r = client.post(
        f"/objects/{o['id']}/measures/rebuild", headers=h["meth2"], json={"dry_run": False}
    )
    assert r.status_code == 200
    ms = _measures(client, h, o["id"])
    client.patch(
        f"/object-measures/{ms['ВУ']['id']}",
        headers=h["meth"],
        json={"adaptation": "excluded", "adaptation_reason": "Обоснование"},
    )
    r = client.post(f"/objects/{o['id']}/adaptation/approve", headers=h["meth2"], json={})
    assert r.status_code == 403
    assert session.scalars(
        select(AuditRecord).where(
            AuditRecord.action == "adaptation.approve", AuditRecord.result == "denied"
        )
    ).one().details == {"reason": "self_approval"}

    # Несверенный справочник — только с подтверждением.
    r = client.post(f"/objects/{o['id']}/adaptation/approve", headers=h["boss"], json={})
    assert r.status_code == 409 and r.headers["X-Error-Code"] == "unverified_measures"
    r = client.post(
        f"/objects/{o['id']}/adaptation/approve",
        headers=h["boss"],
        json={"acknowledge_unverified": True, "comment": "Согласовано", "version": 1},
    )
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["status"] == "approved" and a["approved_by_name"] == "Смирнов С. С."
    assert a["counts"] == {"total": 104, "excluded": 1, "compensated": 0, "added": 0}
    again = client.post(f"/objects/{o['id']}/adaptation/approve", headers=h["boss"], json={})
    assert again.status_code == 409

    # Статус оценки не трогает адаптацию.
    client.patch(
        f"/object-measures/{ms['КК']['id']}", headers=h["exp"], json={"status": "implemented"}
    )
    assert _set(client, h, o["id"])["adaptation"]["status"] == "approved"

    # Правка после утверждения открывает новую версию-черновик, прежняя — в истории.
    client.patch(
        f"/object-measures/{ms['ВУ']['id']}", headers=h["meth"], json={"adaptation": "none"}
    )
    s = _set(client, h, o["id"])
    assert s["adaptation"]["status"] == "draft" and s["adaptation"]["version"] == 2
    hist = client.get(f"/objects/{o['id']}/adaptations", headers=h["viewer"]).json()
    assert [(x["version"], x["status"]) for x in hist] == [(2, "draft"), (1, "superseded")]
    assert hist[1]["approved_by_name"] == "Смирнов С. С."
    # Петров не правил версию 2 — теперь может её утвердить.
    r = client.post(
        f"/objects/{o['id']}/adaptation/approve",
        headers=h["meth2"],
        json={"acknowledge_unverified": True},
    )
    assert r.status_code == 200, r.text

    # Новый класс — утверждать нельзя, пока не пересобран набор.
    _classify(client, h, o["id"], GIS_K3)
    client.patch(
        f"/object-measures/{ms['ВУ']['id']}",
        headers=h["meth"],
        json={"adaptation": "excluded", "adaptation_reason": "Снова"},
    )
    r = client.post(
        f"/objects/{o['id']}/adaptation/approve",
        headers=h["boss"],
        json={"acknowledge_unverified": True},
    )
    assert r.status_code == 409 and "пересоберите" in r.json()["detail"]
    blockers = " ".join(_set(client, h, o["id"])["approve_blockers"])
    assert "Класс объекта утверждён заново" in blockers


def test_owner_must_be_member_and_outsider_sees_nothing(client, env, make_user, login):
    h, o, ids = env
    _classify(client, h, o["id"])
    _build(client, h, o["id"])
    m = _measures(client, h, o["id"])["КК"]
    r = client.patch(
        f"/object-measures/{m['id']}",
        headers=h["exp"],
        json={"owner_id": ids["Козлов К. К."], "comment": "Проверить на стенде"},
    )
    assert r.status_code == 200 and r.json()["owner_name"] == "Козлов К. К."
    make_user("out", "assessor", display_name="Чужой")
    out = login("out")
    me = client.get("/me", headers=out).json()
    r = client.patch(f"/object-measures/{m['id']}", headers=h["exp"], json={"owner_id": me["id"]})
    assert r.status_code == 422
    assert client.get(f"/objects/{o['id']}/measures", headers=out).status_code == 404
    r = client.patch(f"/object-measures/{m['id']}", headers=out, json={"status": "implemented"})
    assert r.status_code == 404


def test_db_forbids_excluding_added_and_self_approval(client, env, session):
    h, o, _ = env
    _classify(client, h, o["id"])
    _build(client, h, o["id"])
    m = session.scalars(select(ObjectMeasure).where(ObjectMeasure.measure_id == "КК")).one()
    with pytest.raises(IntegrityError):
        session.execute(
            update(ObjectMeasure)
            .where(ObjectMeasure.id == m.id)
            .values(adaptation="excluded", adaptation_reason=None)
        )
        session.commit()
    session.rollback()
    a = session.scalars(select(Adaptation)).one()
    with pytest.raises(IntegrityError):
        session.execute(
            update(Adaptation).where(Adaptation.id == a.id).values(approved_by=a.created_by)
        )
        session.commit()
