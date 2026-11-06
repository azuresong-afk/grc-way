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
    monkeypatch.setenv("GRC_SZI_DIR", str(tmp_path / "szi"))
    monkeypatch.setenv("GRC_DOCUMENTS_DIR", str(tmp_path / "documents"))
    monkeypatch.setenv("GRC_PDF_CONVERTER", "none")
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

    # Оба процента: «Сводка» — по всем мерам, Главная платформы — по оценённым.
    pr = k["progress"]
    assert pr == gis["progress"] and pr["percent_all"] == k["stats"]["total"]["percent"]
    assert pr["manual_unassessed"] == gis["manual_pending"] > 0
    assert pr["percent_assessed"] > pr["percent_all"] and "Главная платформы" in pr["note"]
    assert pr["actions"][0]["code"] == "assess_manual"
    home = client.get(f"/summary?project={r.project_id}", headers=h["demo-viewer"]).json()["data"]
    assert home["measures_percent"] == round(pr["percent_assessed"])
    assert home["measures_percent_all"] == round(pr["percent_all"])
    assert home["measures_unassessed_manual"] == pr["manual_unassessed"]
    assert home["measures_note"] == pr["note"]
    assert [a["code"] for a in home["measures_actions"]] == [a["code"] for a in pr["actions"]]
    assert home["measures_actions"][0]["link"] == f"/grc/summary?project={r.project_id}"

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


def test_demo_szi(client, demo_env):
    r, h = demo_env
    st = client.get("/szi-registry/status", headers=h["demo-viewer"]).json()
    assert st["active"] == 6 and st["pending_id"]
    out = client.get(f"/objects/{r.object_id}/szi", headers=h["demo-viewer"]).json()
    states = {i["name"]: i["state"] for i in out["items"]}
    assert states["Пример-АВЗ"] == "expiring" and states["Пример-НСД"] == "expired"
    assert all(i["measures"] for i in out["items"] if i["name"] != "Пример-ОС")
    assert all(m["state"] == "in_set" for i in out["items"] for m in i["measures"])
    sm = client.get(f"/projects/{r.project_id}/summary", headers=h["demo-viewer"]).json()
    assert (sm["kpi"]["szi"]["bad"], sm["kpi"]["szi"]["expiring"]) == (1, 1)


def test_demo_threat_model_waits_for_approval(client, demo_env):
    r, h = demo_env
    models = client.get(f"/objects/{r.object_id}/threat-models", headers=h["demo-viewer"]).json()
    assert [(m["version"], m["status"]) for m in models] == [(1, "draft")]
    m = client.get(f"/threat-models/{models[0]['id']}", headers=h["demo-viewer"]).json()
    assert m["progress"]["ready"], m["progress"]
    assert (m["considered"], m["relevant"]) == (6, 5)
    # Находки прогона №7 с БДУ: три подтверждают УБИ.006, одна не привязана.
    assert m["findings"]["snapshot_number"] == 2
    assert (m["findings"]["total"], m["findings"]["unlinked"]) == (4, 1)
    t = next(x for x in m["threats"] if x["code"] == "УБИ.006")
    assert t["confirmed"] == 3
    r2 = client.post(
        f"/threat-models/{m['id']}/approve",
        headers=h["demo-boss"],
        json={"acknowledge_unverified": True},
    )
    assert r2.status_code == 200, r2.text


def test_demo_inventory(client, demo_env):
    r, h = demo_env
    inv = client.get(f"/objects/{r.object_id}/inventory", headers=h["demo-viewer"]).json()
    assert inv["ready"] and inv["hosts_total"] == 10
    by = {t["code"]: t["total"] for t in inv["types"]}
    assert (by["K1"], by["K5"], by["K6"]) == (3, 5, 4)
    out = client.post(
        f"/objects/{r.object_id}/inventory/infr",
        headers=h["demo-viewer"],
        json={"addresses": ["10.10.2.5", "10.10.3.101"]},
    ).json()
    assert out["complete"] and out["inputs"]["P"] == ["P1"]


def test_demo_vuln_register(client, demo_env):
    r, h = demo_env
    reg = client.get(f"/objects/{r.object_id}/vulns", headers=h["demo-viewer"]).json()
    by = {x["bdu_id"]: x for x in reg["items"]}
    assert by["BDU:2024-04835"]["state"] == "current"
    log4j = by["BDU:2021-06061"]
    assert log4j["state"] == "current" and log4j["current"]["level"] == "critical"
    assert by["BDU:2026-00042"]["state"] == "incomplete"
    manual = by[None]
    assert manual["origin"] == "manual" and manual["current"]["level"] == "high"
    out = client.get(f"/objects/{r.object_id}/vulns/remediation", headers=h["demo-viewer"])
    assert len(out.json()["items"]) == 3


def _xml(docx: bytes) -> str:
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(docx)) as z:
        return "".join(
            z.read(n).decode() for n in z.namelist() if n.startswith("word/") and n.endswith(".xml")
        )


def test_demo_document_kit(client, demo_env):
    r, h = demo_env
    body = client.get(f"/objects/{r.object_id}/documents", headers=h["demo-meth"]).json()
    types = {t["code"]: t for t in body["types"]}
    assert len(types) == 9
    for t in types.values():
        assert t["latest"]["version"] == 1 and not t["changed"], t["code"]
        assert t["latest"]["watermark"]
    t = types["tech-passport"]
    assert t["counts"]["required_empty"] > 0
    d = client.get(f"/documents/{t['latest']['id']}", headers=h["demo-exp"]).json()
    f = {x["key"]: x for x in d["fields"]}
    assert f["classification.result_label"]["state"] == "filled"
    assert f["hosts"]["value"] == "10 шт." and f["szi"]["value"] == "5 шт."
    assert d["unverified"]  # таблица классификации №117 — заглушка, не сверена
    # Согласование (3.3): паспорт утверждён (водяной знак остался из-за несверенной
    # таблицы), акт классификации на согласовании, остальные — проекты.
    assert t["latest"]["status"] == "approved" and d["unverified_acknowledged"]
    assert d["approved_by_name"].startswith("Смирнов")
    assert types["classification-act"]["latest"]["status"] == "review"
    assert types["threat-model"]["latest"]["status"] == "draft"
    # Наблюдатель видит утверждённый паспорт, проектов и согласуемых — нет.
    assert client.get(f"/documents/{d['id']}", headers=h["demo-viewer"]).status_code == 200
    act = types["classification-act"]["latest"]["id"]
    assert client.get(f"/documents/{act}", headers=h["demo-viewer"]).status_code == 404

    def xml(code: str) -> str:
        doc_id = types[code]["latest"]["id"]
        return _xml(client.get(f"/documents/{doc_id}/file", headers=h["demo-meth"]).content)

    # Модель угроз — черновик: шаги мастера и актуальные угрозы; утверждения нет.
    tm = xml("threat-model")
    assert "УБИ.006" in tm and "НВ4" in tm and "Черновик" in tm
    assert "[не заполнено: Утверждение модели угроз]" in tm
    # Протоколы: группы мер с доказательствами «Сканера» и анализ уязвимостей по Методике 2025.
    pr = xml("test-protocols")
    assert "УПД.8" in pr and "Протокол анализа уязвимостей" in pr
    assert "BDU:2021-06061" in pr and "11,00" in pr and "Критический" in pr
    assert "Методика оценки уровня критичности уязвимостей" in pr
    # «Порядок управления уязвимостями» — ссылка на Методику 2025, уровни и сроки п. 21.
    org = xml("org-docs")
    assert "ПОРЯДОК УПРАВЛЕНИЯ УЯЗВИМОСТЯМИ" in org and "до 24 часов" in org
    assert "BDU:2024-04835" in org and "Типовые формулировки ОРД" in org
    # План: меры с нарушениями и уязвимости со сроком; сроков у мер нет.
    plan = xml("remediation-plan")
    assert "УПД.8" in plan and "BDU:2021-06061" in plan and "UTC" in plan
    # Заключение: несоответствия есть — вывод «после устранения».
    assert "после устранения несоответствий" in xml("conclusion")
    # Акт: шаги расчёта по таблице.
    act = xml("classification-act")
    assert "Уровень значимости информации" in act and "К2" in act
