"""Демо-данные и критерии приёмки MVP (docs/roadmap.md, задача 1.11)."""

import shutil
from pathlib import Path

import pytest
from sqlalchemy import select

from app import demo
from app.db.models import Project, ScannerSnapshot
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"
PASSWORD = "demo-password-123"  # noqa: S105 — тестовый пароль


@pytest.fixture
def demo_env(client, session, tmp_path, login, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setenv("GRC_BDU_DIR", str(tmp_path / "bdu"))
    get_settings.cache_clear()
    shutil.copytree(REFERENCE, tmp_path / "reference")
    load_reference(session, tmp_path / "reference")
    r = demo.run(client.app, session, PASSWORD)
    assert r.created
    return r, {u: login(u, PASSWORD) for u in demo.DEMO_USERS}


def test_demo_is_idempotent(client, session, demo_env):
    r, _ = demo_env
    again = demo.run(client.app, session, PASSWORD)
    assert not again.created and again.project_id == r.project_id
    assert len(session.scalars(select(Project)).all()) == 1


def test_demo_needs_reference(client, session):
    with pytest.raises(demo.DemoError, match="справочник"):
        demo.run(client.app, session, PASSWORD)


def test_mvp_acceptance(client, session, demo_env):
    r, h = demo_env
    v = h["demo-viewer"]
    oid = r.object_id

    obj = client.get(f"/objects/{oid}", headers=v).json()
    assert obj["host_count"] == 10
    assert obj["classification"]["result"] == "К2"
    assert obj["classification"]["status"] == "approved"

    ms = {m["measure_id"]: m for m in client.get(f"/objects/{oid}/measures", headers=v).json()}
    auto = [m for m in ms.values() if m["method"] != "manual" and m["adaptation"] == "none"]
    manual = [m for m in ms.values() if m["method"] == "manual" and m["adaptation"] == "none"]
    # Автоматические меры получили статусы из снимка; у каждой есть доказательство.
    assert all(m["auto_snapshot_id"] for m in auto)
    assert {m["status"] for m in auto} >= {"implemented", "partial", "not_implemented"}
    ev = client.get(f"/object-measures/{ms['ИАФ.3']['id']}/evidence", headers=v).json()
    assert ev and ev[0]["kind"] == "scanner"
    # Организационные ждут ручной оценки (кроме одной, оценённой по интервью).
    assessed = [m for m in manual if m["status"] != "unassessed"]
    assert [m["measure_id"] for m in assessed] == ["ВУ"]
    assert ms["ВУ"]["confirmed_at"] and ms["ВУ"]["manual_evidence"] == 1

    # Адаптация с обоснованием отражается в проценте.
    s = client.get(f"/objects/{oid}/measure-set", headers=v).json()
    assert s["adaptation"]["status"] == "approved"
    assert ms["ЗКО.1"]["adaptation"] == "excluded" and ms["ЗКО.1"]["adaptation_reason"]
    total = s["stats"]["total"]
    assert total["excluded"] == 15 and total["compensated"] == 1
    assert total["total"] == len(ms) - 15

    # Повторный импорт другого прогона — новый снимок, старый сохранён.
    snaps = client.get(f"/objects/{oid}/snapshots", headers=v).json()
    assert [(x["number"], x["run_id"], x["current"]) for x in snaps] == [
        (2, 7, True),
        (1, 6, False),
    ]
    assert len(session.scalars(select(ScannerSnapshot)).all()) == 2

    # Всё несверенное видно как «требует сверки».
    assert s["unverified"] > 0
    q = client.get(f"/objects/{oid}/measures?needs_review=true", headers=v).json()
    assert len(q) == s["unverified"]


def test_summary(client, demo_env):
    r, h = demo_env
    out = client.get(f"/projects/{r.project_id}/summary", headers=h["demo-viewer"])
    assert out.status_code == 200, out.text
    s = out.json()
    k = s["kpi"]
    assert (k["objects"], k["hosts"], k["objects_assessed"]) == (2, 12, 1)
    assert k["unverified_tables"] == ["117", "21"]
    gis, pdn = (next(o for o in s["objects"] if o["kind"] == kind) for kind in ("gis", "ispdn"))
    assert gis["state"] == "built" and gis["class_unverified"]
    assert gis["snapshot"]["number"] == 2 and gis["snapshot"]["run_id"] == 7
    assert gis["snapshots"] == 2 and gis["confirmed"] == 1
    assert gis["nonconformities"] > 0 and gis["manual_pending"] > 0
    # Процент проекта при одном оценённом объекте равен проценту объекта.
    ms = client.get(f"/objects/{r.object_id}/measure-set", headers=h["demo-viewer"]).json()
    assert k["stats"] == gis["stats"] == ms["stats"]
    assert k["nonconformities"] == gis["nonconformities"]
    assert pdn["state"] == "no_class" and pdn["stats"] is None and pdn["host_count"] == 2

    # Несуществующий (или чужой) проект — 404.
    missing = client.get(f"/projects/{r.object_id}/summary", headers=h["demo-viewer"])
    assert missing.status_code == 404


def test_search(client, demo_env, make_user, login):
    r, h = demo_env
    v = h["demo-viewer"]

    def find(q, **params):
        res = client.get("/search", headers=v, params={"q": q, **params})
        assert res.status_code == 200, res.text
        return res.json()["items"]

    assert find("у") == []  # слишком коротко
    objs = find("учёт")
    kinds = [i["kind"] for i in objs]
    assert kinds[0] == "project" and "object" in kinds
    obj = next(i for i in objs if i["kind"] == "object")
    assert obj["path"].startswith(f"/objects/{r.object_id}") and obj["url"].startswith("/grc/")
    # «ё» и «е» не различаются, регистр не важен.
    assert any(i["kind"] == "object" for i in find("УЧЕТ"))

    hosts = find("10.10.3")
    assert len(hosts) == 4 and {i["kind"] for i in hosts} == {"host"}
    assert "tab=composition" in hosts[0]["path"]
    assert find("srv-db01")[0]["title"] == "10.10.1.10 · srv-db01.uchet.local"

    m = find("упд.8")
    assert m[0]["kind"] == "measure" and m[0]["title"].startswith("УПД.8 ·")
    assert "tab=measures&measure=" in m[0]["path"]
    assert find("антивирусная")  # по названию меры

    # Только проекты, где пользователь — участник.
    make_user("stranger", "viewer")
    other = client.get("/search", headers=login("stranger"), params={"q": "учёт"}).json()
    assert other["items"] == []
    assert find("учёт", project_id=r.object_id) == []


def test_demo_bdu_samples(client, demo_env):
    _, h = demo_env
    st = client.get("/bdu/status", headers=h["demo-viewer"]).json()
    assert st["threats"]["active"] == 6 and st["vulns"]["active"] == 6
    pending = client.get(f"/bdu/imports/{st['vulns']['pending_id']}", headers=h["demo-viewer"])
    assert pending.json()["summary"]["criticality"] == 1
