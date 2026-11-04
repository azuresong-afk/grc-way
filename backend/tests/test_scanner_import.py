"""Импорт результатов прогона «Сканера»: выбор прогона, снимки, покрытие, автостатусы."""

import shutil
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from app.core.config import Settings
from app.db.models import AuditRecord, Evidence, ScannerSnapshot
from app.domain.assessment import CoverageCell, auto_status, check_modules
from app.integrations.scanner.client import (
    FixtureScannerClient,
    LiveScannerClient,
    ScannerError,
    get_scanner_client,
)
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"
GIS_K2 = {
    "damage_confidentiality": "medium",
    "damage_integrity": "low",
    "damage_availability": "low",
    "scale": "regional",
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


# ---------- Правила автостатуса ----------


def _cov(**hosts):
    return {
        h.replace("_", "."): {m: CoverageCell(s) for m, s in mods.items()}
        for h, mods in hosts.items()
    }


def test_check_modules_follow_sources():
    assert check_modules({"openscap": ["x"], "lynis": ["y"]}) == {"config_audit"}
    assert check_modules({"windows": [{"key": "k"}]}) == {"win_inventory"}
    assert check_modules({"vulns": {"modules": ["vuln"]}, "services": {}}) == {"vuln"}
    assert check_modules({"cred_audit": True}) == {"cred_audit"}


def test_auto_status_rules():
    cov = {
        "10.0.0.1": {"config_audit": CoverageCell("completed")},
        "10.0.0.2": {"config_audit": CoverageCell("completed")},
        "10.0.0.3": {"config_audit": CoverageCell("not_applicable")},
        "10.0.0.4": {"config_audit": CoverageCell("unreachable", "нет ответа")},
    }
    mods = {"config_audit"}
    passed = {"status": "passed", "failed_hosts": []}

    r = auto_status(passed, ["10.0.0.1", "10.0.0.2", "10.0.0.3"], cov, mods)
    assert r.status == "implemented" and r.not_applicable == ["10.0.0.3"]

    # Хост не проверен — отсутствие нарушения не засчитывается.
    r = auto_status(passed, ["10.0.0.1", "10.0.0.4"], cov, mods)
    assert r.status == "unassessed" and r.reason == "incomplete"
    assert r.unchecked == [
        {"host": "10.0.0.4", "reason": "аудит конфигурации: хост недоступен (нет ответа)"}
    ]

    failed = {"status": "failed", "failed_hosts": [{"host": "10.0.0.1"}, {"host": "10.9.9.9"}]}
    r = auto_status(failed, ["10.0.0.1", "10.0.0.2"], cov, mods)
    assert r.status == "partial" and r.failed == ["10.0.0.1"] and r.outside_failed == ["10.9.9.9"]
    r = auto_status(failed, ["10.0.0.1", "10.0.0.4"], cov, mods)
    assert r.status == "not_implemented"

    # Провал только вне объекта — мера объекта не задета.
    r = auto_status(failed, ["10.0.0.2"], cov, mods)
    assert r.status == "implemented" and r.outside_failed == ["10.0.0.1", "10.9.9.9"]

    assert auto_status({"status": "na"}, ["10.0.0.1"], cov, mods).reason == "not_checked"
    assert auto_status(None, ["10.0.0.1"], cov, mods).reason == "absent"
    # Модуль не запускался в прогоне.
    r = auto_status(passed, ["10.0.0.1"], cov, {"cred_audit"})
    assert r.status == "unassessed" and "аудит паролей" in r.unchecked[0]["reason"]
    # Хоста нет в прогоне.
    r = auto_status(passed, ["10.0.0.1", "10.0.0.7"], cov, mods)
    assert r.unchecked == [{"host": "10.0.0.7", "reason": "хост не входил в прогон"}]


# ---------- Клиент ----------


def test_fixture_client_filters_by_level():
    c = FixtureScannerClient()
    runs = c.runs(1)
    assert [r.id for r in runs] == [9, 8, 7, 6]
    assert [r.finished for r in runs] == [False, True, True, True]
    k2 = c.run_compliance(7, "fstec-117", "К2")
    assert k2.level == "К2"
    assert "УПД.5" not in {x.id for x in k2.controls}  # levels: [] — не в базовом наборе
    assert k2.counts["passed"] + k2.counts["failed"] + k2.counts["na"] == len(k2.controls)
    assert k2.percent is not None
    cov = c.run_coverage(8)
    assert {h.host: h.status for h in cov.hosts}["10.10.3.103"] == "unreachable"
    with pytest.raises(ScannerError) as e:
        c.run_compliance(7, "fstec-21", "УЗ3")
    assert e.value.code == "scanner_not_found"


def _live(handler) -> LiveScannerClient:
    s = Settings(scanner_mode="live", scanner_url="http://scanner:8000", scanner_token="static")  # noqa: S106
    return LiveScannerClient(s, transport=httpx.MockTransport(handler))


def test_live_client_runs_compliance_coverage():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.url.path, dict(req.url.params.multi_items())))
        if req.url.path == "/engagements/3/runs":
            assert req.url.params.get_list("status") == [
                "done",
                "failed",
                "interrupted",
                "partial",
                "stopped",
            ]
            return httpx.Response(200, json=[{"id": 5, "engagement_id": 3, "status": "done"}])
        if req.url.path == "/runs/5/compliance":
            return httpx.Response(
                200,
                json={
                    "level": "К2",
                    "percent": 50.0,
                    "counts": {"passed": 1, "failed": 1},
                    "controls": [
                        {"id": "A", "title": "a", "group": "G", "status": "passed", "hosts": {}},
                        {"id": "B", "title": "b", "group": "G", "status": "failed", "hosts": {}},
                    ],
                    "manual": [],
                    "extra": "ignored",
                },
            )
        if req.url.path == "/runs/5/coverage":
            return httpx.Response(200, json={"scan_run_id": 5, "hosts": []})
        return httpx.Response(404)

    c = _live(handler)
    assert [r.id for r in c.runs(3)] == [5]
    comp = c.run_compliance(5, "fstec-117", "К2")
    assert comp.percent == 50.0 and [x.id for x in comp.controls] == ["A", "B"]
    assert seen[1][1] == {"profile": "fstec-117", "level": "К2"}
    assert c.run_coverage(5).scan_run_id == 5
    with pytest.raises(ScannerError) as e:
        c.run(77)
    assert e.value.code == "scanner_not_found"

    bad = _live(lambda req: httpx.Response(200, json={"controls": [{"id": "A"}]}))
    with pytest.raises(ScannerError) as e:
        bad.run_compliance(5, "fstec-117", None)
    assert e.value.code == "scanner_bad_response"


# ---------- API ----------


@pytest.fixture
def env(client, make_user, login, session, tmp_path):
    shutil.copytree(REFERENCE, tmp_path / "reference")
    load_reference(session, tmp_path / "reference")
    make_user("meth", "methodologist", display_name="Иванова А. А.")
    make_user("boss", "viewer", "approve", display_name="Смирнов С. С.")
    make_user("exp", "assessor", display_name="Козлов К. К.")
    make_user("viewer", "viewer", display_name="Наблюдатель")
    h = {u: login(u) for u in ("meth", "boss", "exp", "viewer")}
    c = client.post("/customers", headers=h["meth"], json={"name": "ГБУ «Центр»"}).json()
    p = client.post(
        "/projects",
        headers=h["meth"],
        json={"customer_id": c["id"], "name": "Аттестация", "scanner_engagement_id": 1},
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
    r = client.post(
        f"/objects/{o['id']}/hosts/sync-from-scanner",
        headers=h["meth"],
        json={"addresses": GIS_HOSTS},
    )
    assert r.status_code == 200, r.text
    cls = client.post(
        f"/objects/{o['id']}/classifications", headers=h["meth"], json={"inputs": GIS_K2}
    ).json()
    r = client.post(
        f"/classifications/{cls['id']}/approve",
        headers=h["boss"],
        json={"acknowledge_unverified": True},
    )
    assert r.status_code == 200, r.text
    return h, o, p


def _build(client, h, oid):
    r = client.post(f"/objects/{oid}/measures/rebuild", headers=h["meth"], json={"dry_run": False})
    assert r.status_code == 200, r.text


def _measures(client, h, oid):
    r = client.get(f"/objects/{oid}/measures", headers=h["viewer"])
    assert r.status_code == 200, r.text
    return {m["measure_id"]: m for m in r.json()}


def _import(client, h, oid, run_id="latest", who="exp"):
    return client.post(f"/objects/{oid}/scanner/import", headers=h[who], json={"run_id": run_id})


def test_runs_list_and_import_requires_measure_set(client, env):
    h, o, _ = env
    r = client.get(f"/objects/{o['id']}/scanner/runs", headers=h["viewer"])
    assert r.status_code == 200, r.text
    runs = r.json()
    assert [x["id"] for x in runs["runs"]] == [8, 7, 6]  # идущий прогон №9 не показан
    assert runs["latest_id"] == 8 and runs["engagement_id"] == 1

    r = _import(client, h, o["id"])
    assert r.status_code == 409 and "набор мер" in r.json()["detail"]
    _build(client, h, o["id"])
    # Импорт — право эксперта (scanner.import); методист и наблюдатель — нет.
    for who in ("meth", "viewer"):
        assert _import(client, h, o["id"], who=who).status_code == 403
    r = _import(client, h, o["id"], run_id=9)
    assert r.status_code == 409 and r.headers["X-Error-Code"] == "run_not_finished"
    r = _import(client, h, o["id"], run_id=404)
    assert r.status_code == 404


def test_import_sets_auto_statuses_with_evidence(client, env, session):
    h, o, _ = env
    _build(client, h, o["id"])
    r = _import(client, h, o["id"], run_id=7)
    assert r.status_code == 201, r.text
    out = r.json()
    snap = out["snapshot"]
    assert snap["number"] == 1 and snap["run_id"] == 7 and snap["current"]
    assert snap["selection"] == "manual" and snap["level"] == "К2" and snap["hosts"] == 10
    assert snap["summary"]["measures"] == 24  # технические меры базового набора К2

    ms = _measures(client, h, o["id"])
    # Нарушения на всех проверенных хостах — «Не реализована».
    assert ms["УПД.8"]["status"] == "not_implemented"
    # Нарушения на части хостов — «Частично».
    assert ms["ИАФ.3"]["status"] == "partial"
    assert "2 из" in ms["ИАФ.3"]["auto_note"]
    # Провал только на хосте «Бухгалтерии» (вне объекта) — мера объекта реализована.
    assert ms["УД"]["status"] == "implemented"
    assert ms["РСБ.1"]["status"] == "implemented"
    # Проверка паролей не запускалась — не оценена.
    assert ms["УПД.3"]["status"] == "unassessed" and ms["УПД.3"]["auto_status"] == "unassessed"
    # Организационные меры ждут ручной оценки.
    assert ms["ВУ"]["status"] == "unassessed" and ms["ВУ"]["auto_status"] is None
    assert ms["УПД.8"]["status_source"] == "auto"
    assert ms["УПД.8"]["status_by_name"] == "«Сканер», прогон №7"

    ev = client.get(f"/object-measures/{ms['ИАФ.3']['id']}/evidence", headers=h["viewer"]).json()
    assert len(ev) == 1 and ev[0]["kind"] == "scanner" and ev[0]["status"] == "partial"
    data = ev[0]["data"]
    assert data["run"]["id"] == 7 and data["failed"] == ["10.10.3.103", "10.10.3.104"]
    assert {fh["host"] for fh in data["failed_hosts"]} == {"10.10.3.103", "10.10.3.104"}
    assert data["recommendations"] and data["recommendations"][0]["remediation"]

    s = client.get(f"/objects/{o['id']}/measure-set", headers=h["viewer"]).json()
    assert s["snapshot"]["number"] == 1
    assert s["stats"]["auto"]["implemented"] > 0 and s["stats"]["manual"]["implemented"] == 0

    rec = session.scalars(select(AuditRecord).where(AuditRecord.action == "scanner.import")).one()
    assert rec.details["run_id"] == 7 and rec.details["summary"]["applied"] > 0


def test_reimport_creates_new_snapshot_and_keeps_old(client, env, session):
    h, o, _ = env
    _build(client, h, o["id"])
    first = _import(client, h, o["id"], run_id=7).json()["snapshot"]
    old = client.get(f"/snapshots/{first['id']}", headers=h["viewer"]).json()

    # Тот же прогон без изменений — не дубль.
    r = _import(client, h, o["id"], run_id=7)
    assert r.status_code == 409 and r.headers["X-Error-Code"] == "snapshot_unchanged"

    second = _import(client, h, o["id"]).json()["snapshot"]  # «последний завершённый» — №8
    assert second["number"] == 2 and second["run_id"] == 8 and second["selection"] == "latest"

    snaps = client.get(f"/objects/{o['id']}/snapshots", headers=h["viewer"]).json()
    assert [(s["number"], s["current"]) for s in snaps] == [(2, True), (1, False)]
    again = client.get(f"/snapshots/{first['id']}", headers=h["viewer"]).json()
    assert {**again, "current": True} == {**old, "current": True}  # первый не изменился
    assert not again["current"]

    ms = _measures(client, h, o["id"])
    # В прогоне №8 хост 10.10.3.103 недоступен: без провалов мера не засчитывается.
    assert ms["ЗКУ.3"]["status"] == "unassessed"
    assert "не проверено" in ms["ЗКУ.3"]["auto_note"]
    ev = client.get(f"/object-measures/{ms['ЗКУ.3']['id']}/evidence", headers=h["viewer"]).json()
    assert [e["snapshot"]["number"] for e in ev] == [2, 1]
    assert ev[1]["status"] == "partial"
    assert {u["host"] for u in ev[0]["data"]["unchecked"]} == {"10.10.3.103"}

    detail = client.get(f"/snapshots/{second['id']}", headers=h["viewer"]).json()
    gis = {c["host"]: c for c in detail["coverage_hosts"]}
    assert gis["10.10.3.103"]["status"] == "unreachable" and gis["10.10.3.103"]["in_object"]
    assert not gis["10.20.0.15"]["in_object"]
    assert len(session.scalars(select(Evidence)).all()) == 2 * second["summary"]["measures"]


def test_snapshot_rows_are_immutable(client, env, session):
    h, o, _ = env
    _build(client, h, o["id"])
    _import(client, h, o["id"], run_id=7)
    with pytest.raises(DatabaseError):
        session.execute(text("UPDATE scanner_snapshots SET percent = 100"))
    session.rollback()
    assert session.scalars(select(ScannerSnapshot)).one().percent != 100


def test_manual_status_survives_reimport_and_use_auto(client, env):
    h, o, _ = env
    _build(client, h, o["id"])
    _import(client, h, o["id"], run_id=7)
    m = _measures(client, h, o["id"])["УПД.8"]
    r = client.patch(f"/object-measures/{m['id']}", headers=h["exp"], json={"status": "partial"})
    assert r.status_code == 200 and r.json()["status_source"] == "manual"

    out = _import(client, h, o["id"], run_id=8).json()
    assert out["kept_manual"] >= 1
    m = _measures(client, h, o["id"])["УПД.8"]
    assert m["status"] == "partial" and m["auto_status"] == "not_implemented"

    r = client.patch(f"/object-measures/{m['id']}", headers=h["exp"], json={"use_auto": True})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "not_implemented" and r.json()["status_source"] == "auto"
    # Наблюдатель предложение не принимает.
    r = client.patch(f"/object-measures/{m['id']}", headers=h["viewer"], json={"use_auto": True})
    assert r.status_code == 403
    vu = _measures(client, h, o["id"])["ВУ"]
    r = client.patch(f"/object-measures/{vu['id']}", headers=h["exp"], json={"use_auto": True})
    assert r.status_code == 409


def test_import_errors_are_reported(client, env, session):
    h, o, p = env
    _build(client, h, o["id"])

    class Broken(FixtureScannerClient):
        def run_compliance(self, run_id, profile, level):
            raise ScannerError("«Сканер» не ответил за 20 с")

    client.app.dependency_overrides[get_scanner_client] = lambda: Broken()
    try:
        r = _import(client, h, o["id"])
    finally:
        client.app.dependency_overrides.clear()
    assert r.status_code == 502 and "не ответил" in r.json()["detail"]
    rec = session.scalars(select(AuditRecord).where(AuditRecord.action == "scanner.import")).one()
    assert rec.result == "error"
    assert session.scalars(select(ScannerSnapshot)).first() is None

    client.patch(f"/projects/{p['id']}", headers=h["meth"], json={"scanner_engagement_id": None})
    r = client.get(f"/objects/{o['id']}/scanner/runs", headers=h["viewer"])
    assert r.status_code == 409 and r.headers["X-Error-Code"] == "scanner_not_linked"
