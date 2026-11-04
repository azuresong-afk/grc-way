"""Находки «Сканера» с БДУ как подтверждение актуальности угроз (задача 2.4)."""

import copy
import hashlib

import httpx
import pytest
from sqlalchemy import select

from app.core.config import Settings
from app.db.models import AuditRecord, ScannerSnapshot
from app.domain.threat_findings import (
    FindingsView,
    check,
    host_objects,
    object_findings,
    suggested_threats,
)
from app.integrations.scanner.client import FixtureScannerClient, LiveScannerClient
from tests.test_scanner_import import _build, _import
from tests.test_scanner_import import env as scanner_env  # noqa: F401 — фикстура
from tests.test_threat_model import STEPS, _bdu


def _key(host, port, vuln_id, module="vuln") -> str:
    return hashlib.sha256(f"{host}|{port}|{vuln_id}|{module}".encode()).hexdigest()


SSH_25 = _key("10.10.2.5", 22, "CVE-2024-6387")
SSH_26 = _key("10.10.2.6", 22, "CVE-2024-6387")
LOG4J = _key("10.10.2.5", 8080, "CVE-2021-44228")
ADMIN = _key("10.10.1.10", 8443, "BDU:2026-00042")
# Хост «Бухгалтерии», в ГИС не входит.
SSH_OTHER = _key("10.20.0.15", 22, "CVE-2024-6387")
DB_NEW = _key("10.10.1.12", 5432, "CVE-2026-0001")


def _f(key, host, sev="high", bdu=("BDU:2024-04835",), port=22):
    return {"dedup_key": key, "host": host, "port": port, "severity": sev, "bdu_ids": list(bdu)}


# ---------- Домен ----------


def test_object_findings_keep_object_hosts_with_bdu_only():
    rows = [
        _f("k1", "10.0.0.5", "medium"),
        _f("k2", "10.0.0.9"),  # не в объекте
        _f("k3", "10.0.0.6", "critical"),
        _f("k4", "10.0.0.5", bdu=()),  # без БДУ
        _f("k1", "10.0.0.5", "medium"),  # повтор
        {**_f("k5", " 10.0.0.6 ", "critical", port=443), "extra": "drop"},
    ]
    out = object_findings(rows, ["10.0.0.5", "10.0.0.6"])
    assert [r["dedup_key"] for r in out] == ["k3", "k5", "k1"]
    assert out[1]["host"] == "10.0.0.6" and "extra" not in out[1]


def test_check_problems_and_warnings():
    view = FindingsView.of("s", 3, [_f("a", "h"), _f("b", "h"), _f("c", "h")])
    threats = [
        {"code": "УБИ.006", "relevant": True, "linked_findings": [{"dedup_key": "a"}]},
        {
            "code": "УБИ.067",
            "relevant": False,
            "linked_findings": [{"dedup_key": "b"}, {"dedup_key": "gone"}],
        },
    ]
    problems, warnings = check(threats, view)
    assert problems == [
        "УБИ.067: признана неактуальной, но подтверждена находками «Сканера» (1 в снимке №3) "
        "— пересмотрите решение или отвяжите находки"
    ]
    assert any(w.startswith("УБИ.067: привязанных находок нет в снимке №3 (1)") for w in warnings)
    assert warnings[-1].endswith("не привязаны к угрозам: 1")

    # Снимок без находок (сделан до 2.4) — только предупреждение; снимков нет — тишина.
    old = FindingsView.of("s", 2, None)
    assert old.state("a") == "unknown"
    p, w = check(threats, old)
    assert p == [] and "до импорта находок" in w[0]
    assert check(threats, FindingsView.empty()) == ([], [])


def test_suggested_threats_by_impact_object_hosts():
    hosts = host_objects(STEPS)
    assert hosts == {"10.0.0.5": ["db"]}
    threats = [
        {"code": "УБИ.006", "relevant": True, "objects": ["portal", "db"]},
        {"code": "УБИ.067", "relevant": False, "objects": ["db"]},
        {"code": "УБИ.140", "relevant": None, "objects": ["db"]},
        {"code": "УБИ.170", "relevant": True, "objects": ["portal"]},
    ]
    assert suggested_threats({"host": "10.0.0.5"}, threats, hosts) == ["УБИ.006", "УБИ.140"]
    assert suggested_threats({"host": "10.0.0.6"}, threats, hosts) == []


# ---------- Клиент ----------


def test_fixture_findings_exclude_false_positives_and_no_bdu():
    rows = FixtureScannerClient().run_findings(7)
    keys = {f.dedup_key for f in rows}
    assert keys == {SSH_25, SSH_26, LOG4J, ADMIN, SSH_OTHER}
    assert all(f.bdu_ids for f in rows)
    # Ключ фикстуры посчитан так же, как в «Сканере».
    assert next(f for f in rows if f.dedup_key == LOG4J).bdu_ids == ["BDU:2021-06061"]
    assert FixtureScannerClient().run_findings(404) == []


def test_live_findings_request_bdu_only():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.update(dict(req.url.params))
        body = [
            {
                "id": 1,
                "dedup_key": "a" * 64,
                "module": "vuln",
                "host": "10.0.0.5",
                "port": 22,
                "finding_type": "vuln",
                "title": "x",
                "severity": "high",
                "bdu_ids": ["BDU:2024-04835"],
                "cve_ids": [],
                "detected_at": "2026-11-01T00:00:00Z",
                "priority": {"rank": 1},
            },
            # Старый «Сканер» без фильтра: такие отбрасываются у себя.
            {
                "id": 2,
                "dedup_key": "b" * 64,
                "module": "vuln",
                "host": "10.0.0.5",
                "port": 22,
                "finding_type": "vuln",
                "title": "y",
                "severity": "low",
                "bdu_ids": [],
                "cve_ids": [],
            },
        ]
        return httpx.Response(200, json=body)

    s = Settings(scanner_mode="live", scanner_url="http://scanner:8000", scanner_token="static")  # noqa: S106
    rows = LiveScannerClient(s, transport=httpx.MockTransport(handler)).run_findings(5)
    assert [f.dedup_key for f in rows] == ["a" * 64]
    assert seen == {"bdu_only": "true", "false_positives": "exclude"}


# ---------- API ----------

# Шаги модели для объекта ГИС из фикстуры «Сканера»: портал и СУБД.
GIS_STEPS = copy.deepcopy(STEPS)
GIS_STEPS["objects"]["items"][0]["hosts"] = ["10.10.1.10", "10.10.1.11"]
GIS_STEPS["objects"]["items"][1]["hosts"] = ["10.10.2.5", "10.10.2.6"]


@pytest.fixture
def env(client, scanner_env, session):  # noqa: F811
    h, o, _ = scanner_env
    _bdu(session)
    _build(client, h, o["id"])
    assert _import(client, h, o["id"], run_id=7).status_code == 201
    m = client.post(f"/objects/{o['id']}/threat-models", headers=h["meth"]).json()
    mid = m["id"]
    for step, data in GIS_STEPS.items():
        r = client.put(f"/threat-models/{mid}/steps/{step}", headers=h["meth"], json={"data": data})
        assert r.status_code == 200, (step, r.text)
    r = client.post(
        f"/threat-models/{mid}/threats",
        headers=h["meth"],
        json={"codes": ["УБИ.006", "УБИ.067"]},
    )
    assert r.status_code == 200, r.text
    for code, body in {
        "УБИ.006": {
            "relevant": True,
            "justification": "Портал доступен из сети «Интернет»",
            "intruders": ["НВ4"],
            "objects": ["portal", "db"],
            "consequences": ["У1.4", "У3.4"],
            "methods": ["СР1"],
            "tactics": ["Т2", "Т10"],
        },
        "УБИ.067": {"relevant": False, "justification": "Внутренний нарушитель не актуален"},
    }.items():
        r = client.patch(f"/threat-models/{mid}/threats/{code}", headers=h["meth"], json=body)
        assert r.status_code == 200, r.text
    return h, o, mid


def _link(client, h, mid, code, *keys, who="meth"):
    return client.post(
        f"/threat-models/{mid}/threats/{code}/findings",
        headers=h[who],
        json={"dedup_keys": list(keys)},
    )


def test_import_stores_object_findings_in_snapshot(client, env, session):
    h, o, _ = env
    snaps = client.get(f"/objects/{o['id']}/snapshots", headers=h["viewer"]).json()
    assert snaps[0]["bdu_findings"] == 4
    s = client.get(f"/snapshots/{snaps[0]['id']}", headers=h["viewer"]).json()
    # Хост «Бухгалтерии» и ложное срабатывание не попали; сначала критические.
    assert [f["dedup_key"] for f in s["findings"]] == [ADMIN, LOG4J, SSH_25, SSH_26]
    assert s["findings"][1]["bdu_ids"] == ["BDU:2021-06061"]
    rec = session.scalars(select(AuditRecord).where(AuditRecord.action == "scanner.import")).one()
    assert rec.details["bdu_findings"] == 4


def test_link_findings_confirms_threat(client, env, session):
    h, _, mid = env
    r = client.get(f"/threat-models/{mid}/findings", headers=h["viewer"])
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["snapshot_number"] == 1 and out["imported"]
    assert out["total"] == 4 and out["unlinked"] == 4 and out["confirmed_threats"] == 0
    rows = {f["dedup_key"]: f for f in out["items"]}
    # Подсказка из модели: хост портала входит в объект воздействия угрозы УБИ.006.
    assert rows[LOG4J]["objects"] == ["portal"] and rows[LOG4J]["suggested"] == ["УБИ.006"]
    assert rows[LOG4J]["bdu"][0] == {
        "bdu_id": "BDU:2021-06061",
        "title": None,
        "in_bdu": False,
        "withdrawn": False,
        "cvss3_score": None,
    }
    m = client.get(f"/threat-models/{mid}", headers=h["viewer"]).json()
    threats_step = next(s for s in m["progress"]["steps"] if s["key"] == "threats")
    assert threats_step["warnings"] == [
        "Находки «Сканера» с БДУ из снимка №1 не привязаны к угрозам: 4"
    ]
    assert m["progress"]["ready"]  # предупреждения утверждению не мешают

    # Привязывает редактор модели; наблюдатель — нет; находки не из снимка — нет.
    assert _link(client, h, mid, "УБИ.006", LOG4J, who="viewer").status_code == 403
    r = _link(client, h, mid, "УБИ.006", SSH_OTHER)
    assert r.status_code == 422 and "нет в текущем снимке №1" in r.json()["detail"]
    r = _link(client, h, mid, "УБИ.999", LOG4J)
    assert r.status_code == 404

    r = _link(client, h, mid, "УБИ.006", LOG4J, SSH_25, LOG4J)
    assert r.status_code == 200, r.text
    m = r.json()
    t = next(x for x in m["threats"] if x["code"] == "УБИ.006")
    assert t["confirmed"] == 2
    assert [(x["dedup_key"], x["state"]) for x in t["linked_findings"]] == [
        (LOG4J, "present"),
        (SSH_25, "present"),
    ]
    assert t["linked_findings"][0]["snapshot_number"] == 1
    assert t["linked_findings"][0]["linked_by_name"] == "Иванова А. А."
    assert m["findings"]["unlinked"] == 2 and m["findings"]["confirmed_threats"] == 1
    # Повторная привязка ничего не добавляет.
    r = _link(client, h, mid, "УБИ.006", LOG4J)
    assert (
        len(next(x for x in r.json()["threats"] if x["code"] == "УБИ.006")["linked_findings"]) == 2
    )

    rows = {
        f["dedup_key"]: f
        for f in client.get(f"/threat-models/{mid}/findings", headers=h["viewer"]).json()["items"]
    }
    assert rows[LOG4J]["linked"] == ["УБИ.006"] and rows[LOG4J]["suggested"] == []

    rec = session.scalars(
        select(AuditRecord).where(AuditRecord.action == "threat_model.finding.link")
    ).one()
    assert rec.details["code"] == "УБИ.006" and rec.details["snapshot"] == 1
    assert {f["dedup_key"] for f in rec.details["findings"]} == {LOG4J, SSH_25}


def test_not_relevant_threat_with_findings_blocks_approval(client, env):
    h, _, mid = env
    r = _link(client, h, mid, "УБИ.067", ADMIN)
    assert r.status_code == 200, r.text
    step = next(s for s in r.json()["progress"]["steps"] if s["key"] == "threats")
    assert any("УБИ.067: признана неактуальной" in p for p in step["problems"])
    r = client.post(
        f"/threat-models/{mid}/approve", headers=h["boss"], json={"acknowledge_unverified": True}
    )
    assert r.status_code == 409 and "подтверждена находками" in r.json()["detail"]

    r = client.delete(f"/threat-models/{mid}/threats/УБИ.067/findings/{ADMIN}", headers=h["meth"])
    assert r.status_code == 200, r.text
    assert r.json()["progress"]["ready"]
    r = client.delete(f"/threat-models/{mid}/threats/УБИ.067/findings/{ADMIN}", headers=h["meth"])
    assert r.status_code == 404


def test_new_snapshot_shows_fixed_findings_and_approval_keeps_evidence(client, env):
    h, o, mid = env
    assert _link(client, h, mid, "УБИ.006", LOG4J, SSH_25).status_code == 200
    # Прогон №8: Log4j на портале устранён, на 10.10.1.12 новая уязвимость СУБД.
    assert _import(client, h, o["id"], run_id=8).status_code == 201
    m = client.get(f"/threat-models/{mid}", headers=h["viewer"]).json()
    t = next(x for x in m["threats"] if x["code"] == "УБИ.006")
    assert {x["dedup_key"]: x["state"] for x in t["linked_findings"]} == {
        LOG4J: "absent",
        SSH_25: "present",
    }
    assert t["confirmed"] == 1
    step = next(s for s in m["progress"]["steps"] if s["key"] == "threats")
    assert (
        "УБИ.006: привязанных находок нет в снимке №2 (1) — устранены или хост не проверялся"
        in (step["warnings"])
    )
    out = client.get(f"/threat-models/{mid}/findings", headers=h["viewer"]).json()
    assert out["snapshot_number"] == 2
    assert {f["dedup_key"] for f in out["items"]} == {SSH_25, SSH_26, ADMIN, DB_NEW}

    r = client.post(
        f"/threat-models/{mid}/approve", headers=h["boss"], json={"acknowledge_unverified": True}
    )
    assert r.status_code == 200, r.text
    snap = r.json()["snapshot"]["findings"]
    assert snap["snapshot_number"] == 2 and snap["total"] == 4 and snap["unlinked"] == 3
    assert snap["confirmed"] == {"УБИ.006": [SSH_25]}

    # Утверждённая модель не меняется; новая версия переносит привязки.
    assert _link(client, h, mid, "УБИ.006", SSH_26).status_code == 409
    v2 = client.post(f"/objects/{o['id']}/threat-models", headers=h["meth"]).json()
    t2 = next(x for x in v2["threats"] if x["code"] == "УБИ.006")
    assert [x["dedup_key"] for x in t2["linked_findings"]] == [LOG4J, SSH_25]
    assert _link(client, h, v2["id"], "УБИ.006", SSH_26).status_code == 200


def test_snapshot_findings_are_immutable(client, env, session):
    s = session.scalars(select(ScannerSnapshot)).one()
    s.findings = []
    with pytest.raises(Exception, match="immutable"):
        session.commit()
    session.rollback()
